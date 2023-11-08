######################################################################
#
# File: b2sdk/b2http.py
#
# Copyright 2019 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
from __future__ import annotations

import datetime
import io
import json
import locale
import logging
import socket
import threading
import time
from contextlib import contextmanager
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter

from .api_config import DEFAULT_HTTP_API_CONFIG, B2HttpApiConfig
from .exception import (
    B2ConnectionError,
    B2Error,
    B2RequestTimeout,
    B2RequestTimeoutDuringUpload,
    BadDateFormat,
    BrokenPipe,
    ClockSkew,
    ConnectionReset,
    InvalidJsonResponse,
    PotentialS3EndpointPassedAsRealm,
    UnknownError,
    UnknownHost,
    interpret_b2_error,
)
from .requests import NotDecompressingResponse
from .retries.legacy_retry_manager import DEFAULT_POST_JSON_RETRY_HANDLER, DEFAULT_POST_OPERATION_RETRY_HANDLER, \
    DEFAULT_GET_OPERATION_RETRY_HANDLER, DEFAULT_HEAD_OPERATION_RETRY_HANDLER
from .retries.retry_manager import RetryHandler
from .version import USER_AGENT

LOCALE_LOCK = threading.Lock()
logger = logging.getLogger(__name__)


def _print_exception(e, indent=''):
    """
    Used for debugging to print out nested exception structures.

    :param str indent: message prefix
    """
    print(indent + 'EXCEPTION', repr(e))
    print(indent + 'CLASS', type(e))
    for (i, a) in enumerate(e.args):
        print(indent + 'ARG %d: %s' % (i, repr(a)))
        if isinstance(a, Exception):
            _print_exception(a, indent + '        ')


@contextmanager
def setlocale(name):
    with LOCALE_LOCK:
        saved = locale.setlocale(locale.LC_ALL)
        try:
            yield locale.setlocale(locale.LC_ALL, name)
        finally:
            locale.setlocale(locale.LC_ALL, saved)


class ResponseContextManager:
    """
    A context manager that closes a requests.Response when done.
    """

    def __init__(self, response):
        self.response = response

    def __enter__(self):
        return self.response

    def __exit__(self, exc_type, exc_val, exc_tb):
        return None


class HttpCallback:
    """
    A callback object that does nothing.  Overrides pre_request
    and/or post_request as desired.
    """

    def pre_request(self, method, url, headers):
        """
        Called before processing an HTTP request.

        Raises an exception if this request should not be processed.
        The exception raised must inherit from B2HttpCallbackPreRequestException.

        :param str method: str, one of: 'POST', 'GET', etc.
        :param str url: the URL that will be used
        :param dict headers: the header sent with the request

        """

    def post_request(self, method, url, headers, response):
        """
        Called after processing an HTTP request.
        Should not raise an exception.

        Raises an exception if this request should be treated as failing.
        The exception raised must inherit from B2HttpCallbackPostRequestException.

        :param str method: one of: 'POST', 'GET', etc.
        :param str url: the URL that will be used
        :param dict headers: the header sent with the request
        :param response: a response object from the requests library
        """


class ClockSkewHook(HttpCallback):
    def post_request(self, method, url, headers, response):
        """
        Raise an exception if the clock in the server is too different from the
        clock on the local host.

        The Date header contains a string that looks like: "Fri, 16 Dec 2016 20:52:30 GMT".

        :param str method: one of: 'POST', 'GET', etc.
        :param str url: the URL that will be used
        :param dict headers: the header sent with the request
        :param response: a response object from the requests library
        """
        # Make a string that uses month numbers instead of month names
        server_date_str = response.headers['Date']

        # Convert the server time to a datetime object
        try:
            with setlocale("C"):
                server_time = datetime.datetime.strptime(
                    server_date_str, '%a, %d %b %Y %H:%M:%S %Z'
                )
        except ValueError:
            logger.exception('server returned date in an inappropriate format')
            raise BadDateFormat(server_date_str)

        # Get the local time
        local_time = datetime.datetime.utcnow()

        # Check the difference.
        max_allowed = 10 * 60  # ten minutes, in seconds
        skew = local_time - server_time
        skew_seconds = int(skew.total_seconds())
        if max_allowed < abs(skew_seconds):
            raise ClockSkew(skew_seconds)


class B2Http:
    """
    A wrapper for the requests module.  Provides the operations
    needed to access B2, and handles retrying when the returned
    status is 503 Service Unavailable, 429 Too Many Requests, etc.

    The operations supported are:

    - post_json_return_json
    - post_content_return_json
    - get_content
    - head_content

    The methods that return JSON either return a Python dict or
    raise a subclass of B2Error.  They can be used like this:

    .. code-block:: python

       try:
           response_dict = b2_http.post_json_return_json(url, headers, params)
           ...
       except B2Error as e:
           ...

    All the operations accept RetryHandler as a mean of providing timeouts, retry logic, and backoff strategy.
    If no object is provided, a reasonable default (matching the legacy behavior) will be used.
    """

    def __init__(self, api_config: B2HttpApiConfig = DEFAULT_HTTP_API_CONFIG):
        """
        Initialize with a reference to the requests module, which makes
        it easy to mock for testing.
        """
        self.user_agent = self._get_user_agent(api_config.user_agent_append)
        self.session = api_config.http_session_factory()
        if not api_config.decode_content:
            self.session.adapters.clear()
            self.session.mount('', NotDecompressingHTTPAdapter())
        self.callbacks = []
        if api_config.install_clock_skew_hook:
            self.add_callback(ClockSkewHook())

    def add_callback(self, callback):
        """
        Add a callback that inherits from HttpCallback.

        :param callback: a callback to be added to a chain
        :type callback: callable
        """
        self.callbacks.append(callback)

    def post_content_return_json(
        self,
        url: str,
        headers: dict[str, str],
        data: io.BytesIO,
        retry_handler: Optional[RetryHandler] = None,
        post_params: Optional[dict] = None,
    ) -> dict[str, Any]:
        """
        Use like this:

        .. code-block:: python

           try:
               response_dict = b2_http.post_content_return_json(url, headers, data)
               ...
           except B2Error as e:
               ...

        :param url: a URL to call
        :param headers: headers to send.
        :param data: file-like object, to send
        :param retry_handler: configuration for retries and timeouts
        :return: a dict that is the decoded JSON
        """
        request_headers = {**headers, 'User-Agent': self.user_agent}
        retry_handler = retry_handler or DEFAULT_POST_OPERATION_RETRY_HANDLER

        # Do the HTTP POST.  This may retry, so each post needs to
        # rewind the data back to the beginning.
        def do_post():
            data.seek(0)
            self._run_pre_request_hooks('POST', url, request_headers)
            response = self.session.post(
                url,
                headers=request_headers,
                data=data,
                timeout=retry_handler.get_session_timeouts(),
            )
            self._run_post_request_hooks('POST', url, request_headers, response)
            return response

        try:
            response = self._translate_and_retry(do_post, retry_handler, post_params)
        except B2RequestTimeout:
            # this forces a token refresh, which is necessary if request is still alive
            # on the server but has terminated for some reason on the client. See #79
            raise B2RequestTimeoutDuringUpload()

        # Decode the JSON that came back.  If we've gotten this far,
        # we know we have a status of 200 OK.  In this case, the body
        # of the response is always JSON, so we don't need to handle
        # it being something else.
        try:
            return json.loads(response.content.decode('utf-8'))
        finally:
            response.close()

    def post_json_return_json(
        self,
        url: str,
        headers: dict[str, str],
        params: Optional[dict],
        retry_handler: Optional[RetryHandler] = None,
    ) -> dict[str, Any]:
        """
        Use like this:

        .. code-block:: python

           try:
               response_dict = b2_http.post_json_return_json(url, headers, params)
               ...
           except B2Error as e:
               ...

        :param url: a URL to call
        :param headers: headers to send.
        :param params: a dict that will be converted to JSON
        :param retry_handler: configuration for retries and timeouts
        :return: the decoded JSON document
        """
        data = io.BytesIO(json.dumps(params).encode())
        return self.post_content_return_json(
            url,
            headers,
            data,
            retry_handler or DEFAULT_POST_JSON_RETRY_HANDLER,
            params,
        )

    def get_content(
        self,
        url: str,
        headers: dict[str, str],
        retry_handler: Optional[RetryHandler] = None,
    ) -> ResponseContextManager:
        """
        Fetches content from a URL.

        Use like this:

        .. code-block:: python

           try:
               with b2_http.get_content(url, headers) as response:
                   for byte_data in response.iter_content(chunk_size=1024):
                       ...
           except B2Error as e:
               ...

        The response object is only guarantee to have:
            - headers
            - iter_content()

        :param url: a URL to call
        :param headers: headers to send
        :param retry_handler: configuration for retries and timeouts
        :return: Context manager that returns an object that supports iter_content()
        """
        request_headers = {**headers, 'User-Agent': self.user_agent}
        retry_handler = retry_handler or DEFAULT_GET_OPERATION_RETRY_HANDLER

        # Do the HTTP GET.
        def do_get():
            self._run_pre_request_hooks('GET', url, request_headers)
            response = self.session.get(
                url,
                headers=request_headers,
                stream=True,
                timeout=retry_handler.get_session_timeouts(),
            )
            self._run_post_request_hooks('GET', url, request_headers, response)
            return response

        response = self._translate_and_retry(do_get, retry_handler, None)
        return ResponseContextManager(response)

    def head_content(
        self,
        url: str,
        headers: dict[str, Any],
        retry_handler: Optional[RetryHandler] = None,
    ) -> dict[str, Any]:
        """
        Does a HEAD instead of a GET for the URL.
        The response's content is limited to the headers.

        Use like this:

        .. code-block:: python

           try:
               response_dict = b2_http.head_content(url, headers)
               ...
           except B2Error as e:
               ...

        The response object is only guaranteed to have:
            - headers

        :param url: a URL to call
        :param headers: headers to send
        :param retry_handler: configuration for retries and timeouts
        :return: the decoded response
        """
        request_headers = {**headers, 'User-Agent': self.user_agent}
        retry_handler = retry_handler or DEFAULT_HEAD_OPERATION_RETRY_HANDLER

        # Do the HTTP HEAD.
        def do_head():
            self._run_pre_request_hooks('HEAD', url, request_headers)
            response = self.session.head(
                url,
                headers=request_headers,
                stream=True,
                timeout=retry_handler.get_session_timeouts(),
            )
            self._run_post_request_hooks('HEAD', url, request_headers, response)
            return response

        return self._translate_and_retry(do_head, retry_handler, None)

    @classmethod
    def _get_user_agent(cls, user_agent_append):
        if user_agent_append:
            return f'{USER_AGENT} {user_agent_append}'
        return USER_AGENT

    def _run_pre_request_hooks(self, method, url, headers):
        for callback in self.callbacks:
            callback.pre_request(method, url, headers)

    def _run_post_request_hooks(self, method, url, headers, response):
        for callback in self.callbacks:
            callback.post_request(method, url, headers, response)

    @classmethod
    def _translate_errors(cls, fcn, post_params: Optional[dict]=None):
        """
        Call the given function, turning any exception raised into the right
        kind of B2Error.

        :param post_params: request parameters
        """
        response = None
        try:
            response = fcn()
            if response.status_code not in [200, 206]:
                # Decode the error object returned by the service
                error = json.loads(response.content.decode('utf-8')) if response.content else {}
                extra_error_keys = error.keys() - ('code', 'status', 'message')
                if extra_error_keys:
                    logger.debug(
                        'received error has extra (unsupported) keys: %s', extra_error_keys
                    )
                raise interpret_b2_error(
                    int(error.get('status', response.status_code)),
                    error.get('code'),
                    error.get('message'),
                    response.headers,
                    post_params,
                )
            return response

        except B2Error:
            raise  # pass through exceptions from just above

        except requests.ConnectionError as e0:
            e1 = e0.args[0]
            if isinstance(e1, requests.packages.urllib3.exceptions.MaxRetryError):
                msg = e1.args[0]
                if 'nodename nor servname provided, or not known' in msg:
                    # Unknown host, or DNS failing.  In the context of calling
                    # B2, this means that something is down between here and
                    # Backblaze, so we treat it like 503 Service Unavailable.
                    raise UnknownHost()
            elif isinstance(e1, requests.packages.urllib3.exceptions.ProtocolError):
                e2 = e1.args[1]
                if isinstance(e2, socket.error):
                    if len(e2.args) >= 2 and e2.args[1] == 'Broken pipe':
                        # Broken pipes are usually caused by the service rejecting
                        # an upload request for cause, so we use a 400 Bad Request
                        # code.
                        raise BrokenPipe()
            raise B2ConnectionError(str(e0))

        except requests.Timeout as e:
            raise B2RequestTimeout(str(e))

        except json.JSONDecodeError:
            if response is None:
                raise RuntimeError('Got JSON error without a response.')

            # When the user points to an S3 endpoint, he won't receive the JSON error
            # he expects. In that case, we can provide at least a hint of "what happened".
            # s3 url has the form of e.g. https://s3.us-west-000.backblazeb2.com
            if '://s3.' in response.url:
                raise PotentialS3EndpointPassedAsRealm(response.content)
            raise InvalidJsonResponse(response.content)

        except Exception as e:
            text = repr(e)

            # This is a special case to handle when urllib3 doesn't translate
            # ECONNRESET into something that requests can turn into something
            # we understand.  The SysCallError is from the optional library
            # pyOpenSsl, which we don't require, so we can't import it and
            # catch it explicitly.
            #
            # The text from one such error looks like this: SysCallError(104, 'ECONNRESET')
            if text.startswith('SysCallError'):
                if 'ECONNRESET' in text:
                    raise ConnectionReset()

            logger.exception('_translate_errors has intercepted an unexpected exception')
            raise UnknownError(text)

    @classmethod
    def _translate_and_retry(cls, fcn, retry_handler: RetryHandler, post_params: Optional[dict]=None):
        """
        Try calling fcn try_count times, retrying only if
        the exception is a retryable B2Error.

        :param post_params: request parameters
        """
        while True:
            try:
                response = cls._translate_errors(fcn, post_params)
                retry_handler.operation_succeeded()
                return response
            except B2Error as e:
                if not e.should_retry_http():
                    raise

                retry_handler.operation_failed()
                if not retry_handler.should_retry():
                    raise

                logger.debug(str(e), exc_info=True)
                sleep_duration, sleep_reason = retry_handler.get_retry_backoff(e.retry_after_seconds)

                logger.info(
                    'Pausing thread for %i seconds because %s',
                    sleep_duration,
                    sleep_reason,
                )
                time.sleep(sleep_duration)


class NotDecompressingHTTPAdapter(HTTPAdapter):
    """
    HTTP adapter that uses :class:`b2sdk.requests.NotDecompressingResponse` instead of the default
    :code:`requests.Response` class.
    """

    def build_response(self, req, resp):
        return NotDecompressingResponse.from_builtin_response(super().build_response(req, resp))


def test_http():
    """
    Run a few tests on error diagnosis.

    This test takes a while to run and is not used in the automated tests
    during building.  Run the test by hand to exercise the code.
    """

    from .exception import BadJson

    b2_http = B2Http()

    # Error from B2
    print('TEST: error object from B2')
    try:
        b2_http.post_json_return_json(
            'https://api.backblazeb2.com/b2api/v1/b2_get_file_info', {}, {}
        )
        assert False, 'should have failed with bad json'
    except BadJson as e:
        assert str(e) == 'Bad request: required field fileId is missing'

    # Successful get
    print('TEST: get')
    with b2_http.get_content(
        'https://api.backblazeb2.com/test/echo_zeros?length=10', {}
    ) as response:
        assert response.status_code == 200
        response_data = b''.join(response.iter_content())
        assert response_data == b'\x00' * 10

    # Successful post
    print('TEST: post')
    response_dict = b2_http.post_json_return_json(
        'https://api.backblazeb2.com/api/build_version', {}, {}
    )
    assert 'timestamp' in response_dict

    # Unknown host
    print('TEST: unknown host')
    try:
        b2_http.post_json_return_json('https://unknown.backblazeb2.com', {}, {})
        assert False, 'should have failed with unknown host'
    except UnknownHost:
        pass

    # Broken pipe
    print('TEST: broken pipe')
    try:
        data = io.BytesIO(b'\x00' * 10000000)
        b2_http.post_content_return_json('https://api.backblazeb2.com/bad_url', {}, data)
        assert False, 'should have failed with broken pipe'
    except BrokenPipe:
        pass

    # Generic connection error
    print('TEST: generic connection error')
    try:
        with b2_http.get_content('https://www.backblazeb2.com:80/bad_url', {}) as response:
            assert False, 'should have failed with connection error'
            response.iter_content()  # noqa: make pyflakes happy
    except B2ConnectionError:
        pass
