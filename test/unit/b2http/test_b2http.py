######################################################################
#
# File: test/unit/b2http/test_b2http.py
#
# Copyright 2019 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
from __future__ import annotations

import datetime
import locale
import sys
from unittest.mock import MagicMock, call

import apiver_deps
import pytest
import requests
import responses
from apiver_deps import USER_AGENT, B2Http, B2HttpApiConfig, ClockSkewHook
from apiver_deps_exception import (
    B2ConnectionError,
    B2RequestTimeout,
    BadDateFormat,
    BadJson,
    BadRequest,
    BrokenPipe,
    ClockSkew,
    ConnectionReset,
    PotentialS3EndpointPassedAsRealm,
    ServiceError,
    TooManyRequests,
    UnknownError,
    UnknownHost,
)
from pytest_mock import MockerFixture

from b2sdk._internal.b2http import setlocale

from ..test_base import TestBase


class TestTranslateErrors:
    def test_ok(self):
        response = MagicMock()
        response.status_code = 200
        actual = B2Http._translate_errors(lambda: response)
        assert response == actual

    def test_partial_content(self):
        response = MagicMock()
        response.status_code = 206
        actual = B2Http._translate_errors(lambda: response)
        assert response == actual

    def test_b2_error(self):
        response = MagicMock()
        response.status_code = 503
        response.content = b'{"status": 503, "code": "server_busy", "message": "busy"}'
        with pytest.raises(ServiceError):
            B2Http._translate_errors(lambda: response)

    def test_broken_pipe(self):
        def fcn():
            raise requests.ConnectionError(
                requests.packages.urllib3.exceptions.ProtocolError(
                    'dummy', OSError(20, 'Broken pipe')
                )
            )

        with pytest.raises(BrokenPipe):
            B2Http._translate_errors(fcn)

    def test_unknown_host(self):
        def fcn():
            raise requests.ConnectionError(
                requests.packages.urllib3.exceptions.MaxRetryError(
                    'AAA nodename nor servname provided, or not known AAA', 'http://example.com'
                )
            )

        with pytest.raises(UnknownHost):
            B2Http._translate_errors(fcn)

    def test_request_timeout(self):
        def fcn():
            raise requests.ConnectionError(
                requests.packages.urllib3.exceptions.ProtocolError(
                    'dummy', TimeoutError('The write operation timed out')
                )
            )

        with pytest.raises(B2RequestTimeout):
            B2Http._translate_errors(fcn)

    def test_connection_error(self):
        def fcn():
            raise requests.ConnectionError('a message')

        with pytest.raises(B2ConnectionError):
            B2Http._translate_errors(fcn)

    def test_connection_reset(self):
        class SysCallError(Exception):
            pass

        def fcn():
            raise SysCallError('(104, ECONNRESET)')

        with pytest.raises(ConnectionReset):
            B2Http._translate_errors(fcn)

    def test_unknown_error(self):
        def fcn():
            raise Exception('a message')

        with pytest.raises(UnknownError):
            B2Http._translate_errors(fcn)

    def test_too_many_requests(self):
        response = MagicMock()
        response.status_code = 429
        response.headers = {'retry-after': 1}
        response.content = (
            b'{"status": 429, "code": "Too Many requests", "message": "retry after some time"}'
        )
        with pytest.raises(TooManyRequests):
            B2Http._translate_errors(lambda: response)

    def test_invalid_json(self):
        response = MagicMock()
        response.status_code = 400
        response.content = b'{' * 500
        response.url = 'https://example.com'

        with pytest.raises(BadRequest) as exc_info:
            B2Http._translate_errors(lambda: response)

        assert str(exc_info.value) == f'{response.content.decode()} (non_json_response)'

    def test_potential_s3_endpoint_passed_as_realm(self):
        response = MagicMock()
        response.status_code = 400
        response.content = b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        response.url = 'https://s3.us-west-000.backblazeb2.com'

        with pytest.raises(PotentialS3EndpointPassedAsRealm):
            B2Http._translate_errors(lambda: response)

    @pytest.mark.apiver(to_ver=2)
    def test_bucket_id_not_found(self):
        from b2sdk.v2.exception import BucketIdNotFound, v3BucketIdNotFound

        def fcn():
            raise v3BucketIdNotFound('bucket_id')

        with pytest.raises(BucketIdNotFound) as exc_info:
            B2Http._translate_errors(fcn)

        assert str(exc_info.value) == 'Bucket with id=bucket_id not found (bad_bucket_id)'


def test_b2_error__nginx_html():
    """
    While errors with HTML description should not happen, we should not crash on them.
    """
    response = MagicMock()
    response.status_code = 502
    response.content = b'<html><body><h1>502 Bad Gateway</h1></body></html>'
    with pytest.raises(ServiceError) as exc_info:
        B2Http._translate_errors(lambda: response)
    assert response.content.decode('utf-8') in str(exc_info.value)


def test_b2_error__invalid_error_format():
    """
    Handling of invalid error format.

    If server returns valid JSON, but not matching B2 error schema, we should still raise ServiceError.
    """
    response = MagicMock()
    response.status_code = 503
    # valid JSON, but not a valid B2 error (it should be a dict, not a list)
    response.content = b'[]'
    with pytest.raises(ServiceError) as exc_info:
        B2Http._translate_errors(lambda: response)
    assert '503' in str(exc_info.value)


def test_b2_error__invalid_error_values():
    """
    Handling of invalid error values.

    If server returns valid JSON, but not matching B2 error schema, we should still raise ServiceError.
    """
    response = MagicMock()
    response.status_code = 503
    # valid JSON, but not a valid B2 error (code and status values (and therefore types!) are swapped)
    response.content = b'{"code": 503, "message": "Service temporarily unavailable", "status": "service_unavailable"}'
    with pytest.raises(ServiceError) as exc_info:
        B2Http._translate_errors(lambda: response)
    assert '503 Service temporarily unavailable' in str(exc_info.value)


class TestTranslateAndRetry:
    URL = 'http://example.com'

    @pytest.fixture
    def b2_http(self):
        if apiver_deps.V <= 1:
            return B2Http(
                requests,
                install_clock_skew_hook=False,
            )
        else:
            return B2Http(
                B2HttpApiConfig(
                    requests.Session,
                    install_clock_skew_hook=False,
                )
            )

    @pytest.fixture
    def mock_time(self, mocker: MockerFixture):
        return mocker.patch('time.sleep')

    def _mock_error_response(
        self,
        status_code: int = 400,
        *,
        method: str = responses.GET,
        code: str = 'server_busy',
        message: str = 'dummy',
        headers: dict | None = None,
    ):
        responses.add(
            method,
            self.URL,
            status=status_code,
            json={'status': status_code, 'code': code, 'message': message},
            adding_headers=headers,
        )

    @responses.activate
    def test_works_first_try(self, b2_http: B2Http, mock_time: MagicMock):
        data = {'foo': 'bar'}

        responses.get(self.URL, json=data)

        response = b2_http.request(responses.GET, self.URL, {})

        assert response.json() == data

        mock_time.assert_not_called()

    @responses.activate
    def test_non_retryable(self, b2_http: B2Http, mock_time: MagicMock):
        self._mock_error_response(400, code='bad_json')

        with pytest.raises(BadJson):
            b2_http.request(responses.GET, self.URL, {})

        mock_time.assert_not_called()

    @responses.activate
    def test_works_second_try_service_error(self, b2_http: B2Http, mock_time: MagicMock):
        responses.get(self.URL, body=requests.ConnectionError('oops'))
        responses.get(self.URL)

        b2_http.request(responses.GET, self.URL, {})
        mock_time.assert_called_once_with(1.0)

    @responses.activate
    def test_works_second_try_status(self, b2_http: B2Http, mock_time: MagicMock):
        self._mock_error_response(503)
        responses.get(self.URL)

        b2_http.request(responses.GET, self.URL, {})
        mock_time.assert_called_once_with(1.0)

    @responses.activate
    def test_never_works(self, b2_http: B2Http, mock_time: MagicMock):
        self._mock_error_response(503)
        self._mock_error_response(503)
        self._mock_error_response(503)
        responses.get(self.URL)

        with pytest.raises(ServiceError):
            b2_http.request(responses.GET, self.URL, {}, try_count=3)

        assert mock_time.mock_calls == [call(1.0), call(1.5)]

    @pytest.mark.xfail(reason='no int conversion in the retry-after header parsing logic')
    @responses.activate
    def test_too_many_requests_works_after_sleep(self, b2_http: B2Http, mock_time: MagicMock):
        self._mock_error_response(429, headers={'Retry-After': '2'})
        responses.get(self.URL)

        b2_http.request(responses.GET, self.URL, {})
        mock_time.assert_called_once_with(2)

    @pytest.mark.xfail(reason='no int conversion in the retry-after header parsing logic')
    @responses.activate
    def test_too_many_requests_failed_after_sleep(self, b2_http: B2Http, mock_time: MagicMock):
        self._mock_error_response(429, headers={'Retry-After': '2'})
        self._mock_error_response(429, headers={'Retry-After': '5'})

        with pytest.raises(TooManyRequests):
            b2_http.request(responses.GET, self.URL, {}, try_count=2)
        mock_time.assert_called_once_with(2)

    @pytest.mark.xfail(reason='no int conversion in the retry-after header parsing logic')
    @responses.activate
    def test_too_many_requests_retry_header_combination_one(
        self, b2_http: B2Http, mock_time: MagicMock
    ):
        # If the first response had header, and the second did not, but the third has header again, what should happen?
        self._mock_error_response(429, headers={'Retry-After': '2'})
        self._mock_error_response(429)
        self._mock_error_response(429, headers={'Retry-After': '2'})
        responses.get(self.URL)

        b2_http.request(responses.GET, self.URL, {}, try_count=4)
        assert mock_time.mock_calls == [call(2), call(1.5), call(2)]

    @pytest.mark.xfail(reason='no int conversion in the retry-after header parsing logic')
    @responses.activate
    def test_too_many_requests_retry_header_combination_two(
        self, b2_http: B2Http, mock_time: MagicMock
    ):
        # If the first response didn't have a header, second one has, and third one doesn't have, what should happen?
        self._mock_error_response(429)
        self._mock_error_response(429, headers={'Retry-After': '5'})
        self._mock_error_response(429)
        responses.get(self.URL)

        b2_http.request(responses.GET, self.URL, {}, try_count=4)
        assert mock_time.mock_calls == [call(1.0), call(5), call(2.25)]

    @responses.activate
    def test_post_json_return_json_retries(self, b2_http: B2Http, mock_time: MagicMock):
        self._mock_error_response(503, method='POST')
        responses.post(self.URL, json={'foo': 'bar'})

        b2_http.post_json_return_json(self.URL, {}, {})
        mock_time.assert_called_once_with(1.0)


class TestB2Http(TestBase):
    URL = 'http://example.com'
    UA_APPEND = None
    HEADERS = dict(my_header='my_value')
    EXPECTED_HEADERS = {'my_header': 'my_value', 'User-Agent': USER_AGENT}
    EXPECTED_JSON_HEADERS = {
        **EXPECTED_HEADERS,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    PARAMS = dict(fileSize=100)
    PARAMS_JSON_BYTES = b'{"fileSize": 100}'

    def setUp(self):
        self.session = MagicMock()
        self.response = MagicMock()

        requests = MagicMock()
        requests.Session.return_value = self.session

        if apiver_deps.V <= 1:
            self.b2_http = B2Http(
                requests, install_clock_skew_hook=False, user_agent_append=self.UA_APPEND
            )
        else:
            self.b2_http = B2Http(
                B2HttpApiConfig(
                    requests.Session,
                    install_clock_skew_hook=False,
                    user_agent_append=self.UA_APPEND,
                )
            )

    def test_post_json_return_json(self):
        self.session.request.return_value = self.response
        self.response.status_code = 200
        self.response.content = b'{"color": "blue"}'
        response_dict = self.b2_http.post_json_return_json(self.URL, self.HEADERS, self.PARAMS)
        self.assertEqual({'color': 'blue'}, response_dict)
        (pos_args, kw_args) = self.session.request.call_args
        assert pos_args[:2] == ('POST', self.URL)
        assert kw_args['headers'] == self.EXPECTED_JSON_HEADERS
        assert kw_args['data'] == self.PARAMS_JSON_BYTES

    def test_callback(self):
        callback = MagicMock()
        callback.pre_request = MagicMock()
        callback.post_request = MagicMock()
        self.b2_http.add_callback(callback)
        self.session.request.return_value = self.response
        self.response.status_code = 200
        self.response.content = b'{"color": "blue"}'
        self.b2_http.post_json_return_json(self.URL, self.HEADERS, self.PARAMS)
        callback.pre_request.assert_called_with(
            'POST', 'http://example.com', self.EXPECTED_JSON_HEADERS
        )
        callback.post_request.assert_called_with(
            'POST', 'http://example.com', self.EXPECTED_JSON_HEADERS, self.response
        )

    def test_get_content(self):
        self.session.request.return_value = self.response
        self.response.status_code = 200
        with self.b2_http.get_content(self.URL, self.HEADERS) as r:
            self.assertIs(self.response, r)
        self.session.request.assert_called_with(
            'GET',
            self.URL,
            headers=self.EXPECTED_HEADERS,
            data=None,
            params=None,
            stream=True,
            timeout=(B2Http.CONNECTION_TIMEOUT, B2Http.TIMEOUT),
        )
        self.response.close.assert_not_called()  # prevent premature close() on requests.Response

    def test_head_content(self):
        self.session.request.return_value = self.response
        self.response.status_code = 200
        self.response.headers = {'color': 'blue'}

        response = self.b2_http.head_content(self.URL, self.HEADERS)

        self.assertEqual({'color': 'blue'}, response.headers)
        (pos_args, kw_args) = self.session.request.call_args
        assert pos_args[:2] == ('HEAD', self.URL)
        assert kw_args['headers'] == self.EXPECTED_HEADERS


class TestB2HttpUserAgentAppend(TestB2Http):
    UA_APPEND = 'ua_extra_string'
    EXPECTED_HEADERS = {**TestB2Http.EXPECTED_HEADERS, 'User-Agent': f'{USER_AGENT} {UA_APPEND}'}
    EXPECTED_JSON_HEADERS = {
        **TestB2Http.EXPECTED_JSON_HEADERS,
        'User-Agent': EXPECTED_HEADERS['User-Agent'],
    }


class TestSetLocaleContextManager(TestBase):
    def test_set_locale_context_manager(self):
        # C.UTF-8 on Ubuntu 18.04 Bionic, C.utf8 on Ubuntu 22.04 Jammy
        # Neither macOS nor Windows have C.UTF-8 locale, and they use `en_US.UTF-8`.
        # Since Python 3.12, locale.normalize no longer falls back
        # to the `en_US` version, so we're providing it here manually.
        test_locale = locale.normalize('C.UTF-8' if sys.platform == 'linux' else 'en_US.UTF-8')
        other_locale = 'C'

        saved = locale.setlocale(locale.LC_ALL)
        if saved == test_locale:
            test_locale, other_locale = other_locale, test_locale

        locale.setlocale(locale.LC_ALL, other_locale)
        with setlocale(test_locale):
            assert locale.setlocale(category=locale.LC_ALL) == test_locale
        locale.setlocale(locale.LC_ALL, saved)


class TestClockSkewHook(TestBase):
    def test_bad_format(self):
        response = MagicMock()
        response.headers = {'Date': 'bad format'}
        with self.assertRaises(BadDateFormat):
            ClockSkewHook().post_request('POST', 'http://example.com', {}, response)

    def test_bad_month(self):
        response = MagicMock()
        response.headers = {'Date': 'Fri, 16 XXX 2016 20:52:30 GMT'}
        with self.assertRaises(BadDateFormat):
            ClockSkewHook().post_request('POST', 'http://example.com', {}, response)

    def test_no_skew(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        now_str = now.strftime('%a, %d %b %Y %H:%M:%S GMT')
        response = MagicMock()
        response.headers = {'Date': now_str}
        ClockSkewHook().post_request('POST', 'http://example.com', {}, response)

    def test_positive_skew(self):
        now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=11)
        now_str = now.strftime('%a, %d %b %Y %H:%M:%S GMT')
        response = MagicMock()
        response.headers = {'Date': now_str}
        with self.assertRaises(ClockSkew):
            ClockSkewHook().post_request('POST', 'http://example.com', {}, response)

    def test_negative_skew(self):
        now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=-11)
        now_str = now.strftime('%a, %d %b %Y %H:%M:%S GMT')
        response = MagicMock()
        response.headers = {'Date': now_str}
        with self.assertRaises(ClockSkew):
            ClockSkewHook().post_request('POST', 'http://example.com', {}, response)
