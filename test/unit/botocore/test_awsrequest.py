######################################################################
#
# File: test/unit/botocore/test_awsrequest.py
#
# Copyright 2023 Backblaze Inc. All Rights Reserved.
# Copyright (c) 2012-2013 Mitch Garnaat http://garnaat.org/
# Copyright 2012-2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
# See NOTICE and LICENSE files in b2sdk/_botocore directory.
#
######################################################################
from __future__ import annotations

import io
import socket
import unittest
from unittest import mock

from b2sdk._botocore.awsrequest import AWSHTTPConnection


class IgnoreCloseBytesIO(io.BytesIO):
    def close(self):
        pass


class FakeSocket:
    def __init__(self, read_data, fileclass=IgnoreCloseBytesIO):
        self.sent_data = b''
        self.read_data = read_data
        self.fileclass = fileclass
        self._fp_object = None

    def sendall(self, data):
        self.sent_data += data

    def makefile(self, mode, bufsize=None):
        if self._fp_object is None:
            self._fp_object = self.fileclass(self.read_data)
        return self._fp_object

    def close(self):
        pass

    def settimeout(self, value):
        pass


class BytesIOWithLen(io.BytesIO):
    def __len__(self):
        return len(self.getvalue())


class TestAWSHTTPConnection(unittest.TestCase):
    def create_tunneled_connection(self, url, port, response):
        s = FakeSocket(response)
        conn = AWSHTTPConnection(url, port)
        conn.sock = s
        conn._tunnel_host = url
        conn._tunnel_port = port
        conn._tunnel_headers = {'key': 'value'}

        # Create a mock response.
        self.mock_response = mock.Mock()
        self.mock_response.fp = mock.Mock()

        # Imitate readline function by creating a list to be sent as
        # a side effect of the mocked readline to be able to track how the
        # response is processed in ``_tunnel()``.
        delimiter = b'\r\n'
        side_effect = []
        response_components = response.split(delimiter)
        for i in range(len(response_components)):
            new_component = response_components[i]
            # Only add the delimiter on if it is not the last component
            # which should be an empty string.
            if i != len(response_components) - 1:
                new_component += delimiter
            side_effect.append(new_component)

        self.mock_response.fp.readline.side_effect = side_effect

        response_components = response.split(b' ')
        self.mock_response._read_status.return_value = (
            response_components[0],
            int(response_components[1]),
            response_components[2],
        )
        conn.response_class = mock.Mock()
        conn.response_class.return_value = self.mock_response
        return conn

    def test_expect_100_continue_returned(self):
        with mock.patch('urllib3.util.wait_for_read') as wait_mock:
            # Shows the server first sending a 100 continue response
            # then a 200 ok response.
            s = FakeSocket(b'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n')
            conn = AWSHTTPConnection('s3.amazonaws.com', 443)
            conn.sock = s
            wait_mock.return_value = True
            conn.request('GET', '/bucket/foo', b'body', {'Expect': b'100-continue'})
            response = conn.getresponse()
            # Assert that we waited for the 100-continue response
            self.assertEqual(wait_mock.call_count, 1)
            # Now we should verify that our final response is the 200 OK
            self.assertEqual(response.status, 200)

    def test_handles_expect_100_with_different_reason_phrase(self):
        with mock.patch('urllib3.util.wait_for_read') as wait_mock:
            # Shows the server first sending a 100 continue response
            # then a 200 ok response.
            s = FakeSocket(b'HTTP/1.1 100 (Continue)\r\n\r\nHTTP/1.1 200 OK\r\n')
            conn = AWSHTTPConnection('s3.amazonaws.com', 443)
            conn.sock = s
            wait_mock.return_value = True
            conn.request(
                'GET',
                '/bucket/foo',
                io.BytesIO(b'body'),
                {
                    'Expect': b'100-continue',
                    'Content-Length': b'4'
                },
            )
            response = conn.getresponse()
            # Now we should verify that our final response is the 200 OK.
            self.assertEqual(response.status, 200)
            # Assert that we waited for the 100-continue response
            self.assertEqual(wait_mock.call_count, 1)
            # Verify that we went the request body because we got a 100
            # continue.
            self.assertIn(b'body', s.sent_data)

    def test_expect_100_sends_connection_header(self):
        # When using squid as an HTTP proxy, it will also send
        # a Connection: keep-alive header back with the 100 continue
        # response.  We need to ensure we handle this case.
        with mock.patch('urllib3.util.wait_for_read') as wait_mock:
            # Shows the server first sending a 100 continue response
            # then a 500 response.  We're picking 500 to confirm we
            # actually parse the response instead of getting the
            # default status of 200 which happens when we can't parse
            # the response.
            s = FakeSocket(
                b'HTTP/1.1 100 Continue\r\n'
                b'Connection: keep-alive\r\n'
                b'\r\n'
                b'HTTP/1.1 500 Internal Service Error\r\n'
            )
            conn = AWSHTTPConnection('s3.amazonaws.com', 443)
            conn.sock = s
            wait_mock.return_value = True
            conn.request('GET', '/bucket/foo', b'body', {'Expect': b'100-continue'})
            # Assert that we waited for the 100-continue response
            self.assertEqual(wait_mock.call_count, 1)
            response = conn.getresponse()
            self.assertEqual(response.status, 500)

    def test_expect_100_continue_sends_307(self):
        # This is the case where we send a 100 continue and the server
        # immediately sends a 307
        with mock.patch('urllib3.util.wait_for_read') as wait_mock:
            # Shows the server first sending a 100 continue response
            # then a 200 ok response.
            s = FakeSocket(
                b'HTTP/1.1 307 Temporary Redirect\r\n'
                b'Location: http://example.org\r\n'
            )
            conn = AWSHTTPConnection('s3.amazonaws.com', 443)
            conn.sock = s
            wait_mock.return_value = True
            conn.request('GET', '/bucket/foo', b'body', {'Expect': b'100-continue'})
            # Assert that we waited for the 100-continue response
            self.assertEqual(wait_mock.call_count, 1)
            response = conn.getresponse()
            # Now we should verify that our final response is the 307.
            self.assertEqual(response.status, 307)

    def test_expect_100_continue_no_response_from_server(self):
        with mock.patch('urllib3.util.wait_for_read') as wait_mock:
            # Shows the server first sending a 100 continue response
            # then a 200 ok response.
            s = FakeSocket(
                b'HTTP/1.1 307 Temporary Redirect\r\n'
                b'Location: http://example.org\r\n'
            )
            conn = AWSHTTPConnection('s3.amazonaws.com', 443)
            conn.sock = s
            # By settings wait_mock to return False, this indicates
            # that the server did not send any response.  In this situation
            # we should just send the request anyways.
            wait_mock.return_value = False
            conn.request('GET', '/bucket/foo', b'body', {'Expect': b'100-continue'})
            # Assert that we waited for the 100-continue response
            self.assertEqual(wait_mock.call_count, 1)
            response = conn.getresponse()
            self.assertEqual(response.status, 307)

    def test_message_body_is_file_like_object(self):
        # Shows the server first sending a 100 continue response
        # then a 200 ok response.
        body = BytesIOWithLen(b'body contents')
        s = FakeSocket(b'HTTP/1.1 200 OK\r\n')
        conn = AWSHTTPConnection('s3.amazonaws.com', 443)
        conn.sock = s
        conn.request('GET', '/bucket/foo', body)
        response = conn.getresponse()
        self.assertEqual(response.status, 200)

    def test_no_expect_header_set(self):
        # Shows the server first sending a 100 continue response
        # then a 200 ok response.
        s = FakeSocket(b'HTTP/1.1 200 OK\r\n')
        conn = AWSHTTPConnection('s3.amazonaws.com', 443)
        conn.sock = s
        conn.request('GET', '/bucket/foo', b'body')
        response = conn.getresponse()
        self.assertEqual(response.status, 200)

    def test_tunnel_readline_normal(self):
        # Tests that ``_tunnel`` function behaves normally when it comes
        # across the usual http ending.
        conn = self.create_tunneled_connection(
            url='s3.amazonaws.com',
            port=443,
            response=b'HTTP/1.1 200 OK\r\n\r\n',
        )
        conn._tunnel()
        # Ensure proper amount of readline calls were made.
        self.assertEqual(self.mock_response.fp.readline.call_count, 2)

    def test_tunnel_raises_socket_error(self):
        # Tests that ``_tunnel`` function throws appropriate error when
        # not 200 status.
        conn = self.create_tunneled_connection(
            url='s3.amazonaws.com',
            port=443,
            response=b'HTTP/1.1 404 Not Found\r\n\r\n',
        )
        with self.assertRaises(socket.error):
            conn._tunnel()

    def test_tunnel_uses_std_lib(self):
        s = FakeSocket(b'HTTP/1.1 200 OK\r\n')
        conn = AWSHTTPConnection('s3.amazonaws.com', 443)
        conn.sock = s
        # Test that the standard library method was used by patching out
        # the ``_tunnel`` method and seeing if the std lib method was called.
        with mock.patch('urllib3.connection.HTTPConnection._tunnel') as mock_tunnel:
            conn._tunnel()
            self.assertTrue(mock_tunnel.called)

    def test_encodes_unicode_method_line(self):
        s = FakeSocket(b'HTTP/1.1 200 OK\r\n')
        conn = AWSHTTPConnection('s3.amazonaws.com', 443)
        conn.sock = s
        # Note the combination of unicode 'GET' and
        # bytes 'Utf8-Header' value.
        conn.request(
            'GET',
            '/bucket/foo',
            b'body',
            headers={"Utf8-Header": b"\xe5\xb0\x8f"},
        )
        response = conn.getresponse()
        self.assertEqual(response.status, 200)

    def test_state_reset_on_connection_close(self):
        # This simulates what urllib3 does with connections
        # in its connection pool logic.
        with mock.patch('urllib3.util.wait_for_read') as wait_mock:
            # First fast fail with a 500 response when we first
            # send the expect header.
            s = FakeSocket(b'HTTP/1.1 500 Internal Server Error\r\n')
            conn = AWSHTTPConnection('s3.amazonaws.com', 443)
            conn.sock = s
            wait_mock.return_value = True

            conn.request('GET', '/bucket/foo', b'body', {'Expect': b'100-continue'})
            self.assertEqual(wait_mock.call_count, 1)
            response = conn.getresponse()
            self.assertEqual(response.status, 500)

            # Now what happens in urllib3 is that when the next
            # request comes along and this connection gets checked
            # out.  We see that the connection needs to be
            # reset.  So first the connection is closed.
            conn.close()

            # And then a new connection is established.
            new_conn = FakeSocket(b'HTTP/1.1 100 (Continue)\r\n\r\nHTTP/1.1 200 OK\r\n')
            conn.sock = new_conn

            # And we make a request, we should see the 200 response
            # that was sent back.
            wait_mock.return_value = True

            conn.request('GET', '/bucket/foo', b'body', {'Expect': b'100-continue'})
            # Assert that we waited for the 100-continue response
            self.assertEqual(wait_mock.call_count, 2)
            response = conn.getresponse()
            # This should be 200.  If it's a 500 then
            # the prior response was leaking into our
            # current response.,
            self.assertEqual(response.status, 200)

    def test_handles_expect_100_with_no_reason_phrase(self):
        with mock.patch('urllib3.util.wait_for_read') as wait_mock:
            # Shows the server first sending a 100 continue response
            # then a 200 ok response.
            s = FakeSocket(b'HTTP/1.1 100\r\n\r\nHTTP/1.1 200 OK\r\n')
            conn = AWSHTTPConnection('s3.amazonaws.com', 443)
            conn.sock = s
            wait_mock.return_value = True
            conn.request(
                'GET',
                '/bucket/foo',
                io.BytesIO(b'body'),
                {
                    'Expect': b'100-continue',
                    'Content-Length': b'4'
                },
            )
            response = conn.getresponse()
            # Now we should verify that our final response is the 200 OK.
            self.assertEqual(response.status, 200)
            # Assert that we waited for the 100-continue response
            self.assertEqual(wait_mock.call_count, 1)
            # Verify that we went the request body because we got a 100
            # continue.
            self.assertIn(b'body', s.sent_data)
