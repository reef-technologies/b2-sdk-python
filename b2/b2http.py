######################################################################
#
# File: b2/b2http.py
#
# Copyright 2016 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

from __future__ import print_function

import functools
import json
import socket

import requests
import six

from .exception import B2Error, BrokenPipe, ConnectionError, interpret_b2_error, UnknownError, UnknownHost
from .version import USER_AGENT


def _print_exception(e, indent=''):
    """
    Used for debugging to print out nested exception structures.
    """
    print(indent + 'EXCEPTION', repr(e))
    print(indent + 'CLASS', type(e))
    for (i, a) in enumerate(e.args):
        print(indent + 'ARG %d: %s' % (i, repr(a)))
        if isinstance(a, Exception):
            _print_exception(a, indent + '        ')


def _translate_errors(fcn):
    """
    Calls the given function, turning any exception raised into the right
    kind of B2Error.
    """
    try:
        response = fcn()
        if response.status_code not in [200, 206]:
            # Decode the error object returned by the service
            error = json.loads(response.content.decode('utf-8'))
            raise interpret_b2_error(int(error['status']), error['code'], error['message'])
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
                if e2.args[1] == 'Broken pipe':
                    # Broken pipes are usually caused by the service rejecting
                    # an upload request for cause, so we use a 400 Bad Request
                    # code.
                    raise BrokenPipe()
        raise ConnectionError(str(e0))

    except Exception as e:
        # Don't expect this to happen.  To get lots of info for
        # debugging, call print_exception: print_exception(e)
        raise UnknownError(repr(e))


class ResponseContextManager(object):
    """
    Context manager that closes a requests.Response when done.
    """

    def __init__(self, response):
        self.response = response

    def __enter__(self):
        return self.response

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.response.close()


class B2Http(object):
    """
    A wrapper for the requests module.  Provides the operations
    needed to access B2, and handles retrying when the returned
    status is 503 Service Unavailable or 429 Too Many Requests.

    The operations supported are:
       - post_json_return_json
       - post_content_return_json
       - get_content

    The methods that return JSON either return a Python dict  or
    raise a subclass of B2Error.  They can be used like this:

        try:
            response_dict = b2_http.post_json_return_json(url, headers, params)
            ...
        except B2Error as e:
            ...


    get_content() returns a context manager object that returns
    an object that acts like requests.Response.

        try:
            with b2_http.get_content(url, headers) as response:
                for byte_data in response.iter_content(chunk_size=1024):
                    ...
        except B2Error as e:
            ...

    The response object is only guarantee to have:
        - headers
        - iter_content()
    """

    def __init__(self, requests_module=None):
        """
        Initialize with a reference to the requests module, which makes
        it easy to mock for testing.
        """
        self.requests = requests_module or requests

    def post_content_return_json(self, url, headers, data):
        """
        :param url: URL to call
        :param headers: Headers to send.
        :param data: bytes (Python 3) or str (Python 2) to send
        :return:
        """
        headers['User-Agent'] = USER_AGENT
        response = _translate_errors(
            functools.partial(
                self.requests.post,
                url,
                headers=headers,
                data=data
            )
        )
        try:
            return json.loads(response.content.decode('utf-8'))
        finally:
            response.close()

    def post_json_return_json(self, url, headers, params):
        """
        :param url: URL to call
        :param headers: Headers to send.
        :param params: A dict that will be converted to JSON
        :return:
        """
        data = six.b(json.dumps(params))
        return self.post_content_return_json(url, headers, data)

    def get_content(self, url, headers):
        """
        :param url: URL to call
        :param headers: Headers to send
        :return: Context manager that returns an object that supports iter_content()
        """
        headers['User-Agent'] = USER_AGENT
        response = _translate_errors(functools.partial(self.requests.get, url, headers=headers))
        return ResponseContextManager(response)


def test_http():
    """
    Runs a few tests on error diagnosis.

    This test takes a while to run, and is not used in the automated tests
    during building.  Run the test by hand to exercise the code.  Be sure
    to run in both Python 2 and Python 3.
    """

    from .exception import BadJson

    b2_http = B2Http()

    # Error from B2
    print('TEST: error object from B2')
    try:
        b2_http.post_json_return_json('https://api.backblaze.com/b2api/v1/b2_get_file_info', {}, {})
        assert False, 'should have failed with bad json'
    except BadJson as e:
        assert str(e) == 'Bad request: required field fileId is missing'

    # Successful get
    print('TEST: get')
    with b2_http.get_content('https://api.backblaze.com/test/echo_zeros?length=10', {}) as response:
        assert response.status_code == 200
        response_data = six.b('').join(response.iter_content())
        assert response_data == six.b(chr(0) * 10)

    # Successful post
    print('TEST: post')
    response_dict = b2_http.post_json_return_json(
        'https://api.backblaze.com/api/build_version', {}, {}
    )
    assert 'timestamp' in response_dict

    # Unknown host
    print('TEST: unknown host')
    try:
        b2_http.post_json_return_json('https://unknown.backblaze.com', {}, {})
        assert False, 'should have failed with unknown host'
    except UnknownHost as e:
        pass

    # Broken pipe
    print('TEST: broken pipe')
    try:
        b2_http.post_content_return_json(
            'https://api.backblaze.com/bad_url', {}, six.b(chr(0)) * 10000000
        )
        assert False, 'should have failed with broken pipe'
    except BrokenPipe as e:
        pass

    # Generic connection error
    print('TEST: generic connection error')
    try:
        with b2_http.get_content('https://www.backblaze.com:80/bad_url', {}) as response:
            assert False, 'should have failed with connection error'
            response.iter_content()  # make pyflakes happy
    except ConnectionError as e:
        pass
