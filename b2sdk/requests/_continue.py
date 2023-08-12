# Code taken from:
# https://github.com/boto/botocore/blob/754b699bbf34261eae47c9dece3b11d7b58eb03c/botocore/awsrequest.py
# The code has been modified to work with urllib3>=2.0

# Copyright (c) 2012-2013 Mitch Garnaat http://garnaat.org/
# Copyright 2012-2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
import functools
import logging
from http.client import HTTPResponse

import urllib3
from requests import adapters
from urllib3.connection import HTTPConnection, VerifiedHTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

logger = logging.getLogger(__name__)


class AWSHTTPResponse(HTTPResponse):
    # The *args, **kwargs is used because the args are slightly
    # different in py2.6 than in py2.7/py3.
    def __init__(self, *args, **kwargs):
        self._status_tuple = kwargs.pop('status_tuple')
        HTTPResponse.__init__(self, *args, **kwargs)

    def _read_status(self):
        if self._status_tuple is not None:
            status_tuple = self._status_tuple
            self._status_tuple = None
            return status_tuple
        else:
            return HTTPResponse._read_status(self)


class AWSConnection:
    """Mixin for HTTPConnection that supports Expect 100-continue.

    This when mixed with a subclass of httplib.HTTPConnection (though
    technically we subclass from urllib3, which subclasses
    httplib.HTTPConnection) and we only override this class to support Expect
    100-continue, which we need for S3.  As far as I can tell, this is
    general purpose enough to not be specific to S3, but I'm being
    tentative and keeping it in botocore because I've only tested
    this against AWS services.

    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._original_response_cls = self.response_class
        # This variable is set when we receive an early response from the
        # server. If this value is set to True, any calls to send() are noops.
        # This value is reset to false every time _send_request is called.
        # This is to workaround changes in urllib3 2.0 which uses separate
        # send() calls in request() instead of delegating to endheaders(),
        # which is where the body is sent in CPython's HTTPConnection.
        self._response_received = False
        self._expect_header_set = False
        self._send_called = False

    def close(self):
        super().close()
        # Reset all of our instance state we were tracking.
        self._response_received = False
        self._expect_header_set = False
        self._send_called = False
        self.response_class = self._original_response_cls

    def request(self, method, url, body=None, headers=None, *args, **kwargs):
        if headers is None:
            headers = {}
        self._response_received = False
        if headers.get('Expect', b'') in [b'100-continue', '100-continue']:
            self._expect_header_set = True
        else:
            self._expect_header_set = False
            self.response_class = self._original_response_cls
        rval = super().request(method, url, body, headers, *args, **kwargs)
        self._expect_header_set = False
        return rval

    def _convert_to_bytes(self, mixed_buffer):
        # Take a list of mixed str/bytes and convert it
        # all into a single bytestring.
        # Any str will be encoded as utf-8.
        bytes_buffer = []
        for chunk in mixed_buffer:
            if isinstance(chunk, str):
                bytes_buffer.append(chunk.encode('utf-8'))
            else:
                bytes_buffer.append(chunk)
        msg = b"\r\n".join(bytes_buffer)
        return msg

    def _send_output(self, message_body=None, *args, **kwargs):
        self._buffer.extend((b"", b""))
        msg = b"\r\n".join(self._buffer)
        del self._buffer[:]
        # If msg and message_body are sent in a single send() call,
        # it will avoid performance problems caused by the interaction
        # between delayed ack and the Nagle algorithm.
        if isinstance(message_body, bytes):
            msg += message_body
            message_body = None
        self.send(msg)
        if self._expect_header_set:
            # This is our custom behavior.  If the Expect header was
            # set, it will trigger this custom behavior.
            logger.debug("Waiting for 100 Continue response.")
            # Wait for 1 second for the server to send a response.
            if urllib3.util.wait_for_read(self.sock, 2):
                self._handle_expect_response(message_body)
                return
            else:
                # From the RFC:
                # Because of the presence of older implementations, the
                # protocol allows ambiguous situations in which a client may
                # send "Expect: 100-continue" without receiving either a 417
                # (Expectation Failed) status or a 100 (Continue) status.
                # Therefore, when a client sends this header field to an origin
                # server (possibly via a proxy) from which it has never seen a
                # 100 (Continue) status, the client SHOULD NOT wait for an
                # indefinite period before sending the request body.
                logger.debug(
                    "No response seen from server, continuing to "
                    "send the response body."
                )
        if message_body is not None:
            # message_body was not a string (i.e. it is a file), and
            # we must run the risk of Nagle.
            self.send(message_body)

    def _consume_headers(self, fp):
        # Most servers (including S3) will just return
        # the CLRF after the 100 continue response.  However,
        # some servers (I've specifically seen this for squid when
        # used as a straight HTTP proxy) will also inject a
        # Connection: keep-alive header.  To account for this
        # we'll read until we read '\r\n', and ignore any headers
        # that come immediately after the 100 continue response.
        current = None
        while current != b'\r\n':
            current = fp.readline()

    def _handle_expect_response(self, message_body):
        # This is called when we sent the request headers containing
        # an Expect: 100-continue header and received a response.
        # We now need to figure out what to do.
        fp = self.sock.makefile('rb', 0)
        try:
            maybe_status_line = fp.readline()
            parts = maybe_status_line.split(None, 2)

            # Check for 'HTTP/<version> 100 Continue\r\n' or, 'HTTP/<version> 100\r\n'
            if len(parts) >= 2 and parts[0].startswith(b'HTTP/') and parts[1] == b'100':
                self._consume_headers(fp)
                logger.debug(
                    "100 Continue response seen, now sending request body."
                )
                self._send_message_body(message_body)
            elif len(parts) >= 2 and parts[0].startswith(b'HTTP/'):
                # From the RFC:
                # Requirements for HTTP/1.1 origin servers:
                #
                # - Upon receiving a request which includes an Expect
                #   request-header field with the "100-continue"
                #   expectation, an origin server MUST either respond with
                #   100 (Continue) status and continue to read from the
                #   input stream, or respond with a final status code.
                #
                # So if we don't get a 100 Continue response, then
                # whatever the server has sent back is the final response
                # and don't send the message_body.
                logger.debug(
                    "Received a non 100 Continue response "
                    "from the server, NOT sending request body."
                )
                status_tuple = (
                    parts[0].decode('ascii'),
                    int(parts[1]),
                    parts[2].decode('ascii') if len(parts) > 2 else '',
                )
                response_class = functools.partial(
                    AWSHTTPResponse, status_tuple=status_tuple
                )
                self.response_class = response_class
                self._response_received = True
        finally:
            fp.close()

    def _send_message_body(self, message_body):
        if message_body is not None:
            self.send(message_body)

    def send(self, str):
        if self._response_received:
            if not self._send_called:
                # urllib3 2.0 chunks and calls send potentially
                # thousands of times inside `request` unlike the
                # standard library. Only log this once for sanity.
                logger.debug(
                    "send() called, but response already received. "
                    "Not sending data."
                )
            self._send_called = True
            return
        return super().send(str)


class AWSHTTPConnection(AWSConnection, HTTPConnection):
    """An HTTPConnection that supports 100 Continue behavior."""


class AWSHTTPSConnection(AWSConnection, VerifiedHTTPSConnection):
    """An HTTPSConnection that supports 100 Continue behavior."""


class AWSHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = AWSHTTPConnection


class AWSHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = AWSHTTPSConnection


pool_classes_by_scheme = {"http": AWSHTTPConnectionPool, "https": AWSHTTPSConnectionPool}


class HTTPAdapterWithContinue(adapters.HTTPAdapter):
    def init_poolmanager(
        self, connections, maxsize, block=adapters.DEFAULT_POOLBLOCK, **pool_kwargs
    ):
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)
        self.poolmanager.pool_classes_by_scheme = pool_classes_by_scheme
