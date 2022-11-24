######################################################################
#
# File: b2sdk/utils/curl.py
#
# Copyright 2020 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
"""
CURL flow:

A single Curl object handles a single request.
These requests can be added to CurlMulti and polled together.

The idea is:
- Have a single CurlMulti object for all requests.
- Each new Curl is added to it (even across threads).
- Each is streaming data to StreamedBuffer.
- Whenever any of these try to iterate content,
  we just check whether there's more data for any of them.
- If they finished (messages from CurlMulti say so), we're leaving a flag.
"""

import collections
import threading
import time
from dataclasses import dataclass, field
from functools import partial, partialmethod
from io import BytesIO
from typing import Dict, Iterator, List, Literal, Optional, Union

import certifi
import pycurl

from requests.utils import CaseInsensitiveDict

from b2sdk.stream.progress import ReadingStreamWithProgress


@dataclass
class CurlAdapters:
    adapters: dict = field(default_factory=dict)

    def clear(self):
        self.adapters = {}


@dataclass
class CurlRequest:
    url: str
    headers: CaseInsensitiveDict


class StreamedBytes:
    """
    Structure that works "kinda" like an unlimited ring buffer.

    We can put the data on one side and read it from the other,
    and the data read is lost (memory is released).
    """

    def __init__(self):
        # We store our data in chunks in a deque. Whenever data is requested,
        # we remove them from deque up to the size, and put back the reminder.
        self.deque = collections.deque()
        self.lock = threading.Lock()
        self.first_write_event = threading.Event()

    def is_empty(self) -> bool:
        with self.lock:
            return len(self.deque) == 0

    def write(self, buffer) -> int:
        with self.lock:
            if len(buffer) == 0:
                return 0

            # Whole buffer is stored as deque is implemented as double-linked list.
            # This way we have fewer, (hopefully) larger elements.
            self.deque.append(buffer)

            # If we haven't informed everyone yet, it's the time. We've received
            # first buffer of data. This is used to indicate that all the headers
            # are already downloaded.
            if not self.first_write_event.is_set():
                self.first_write_event.set()

            return len(buffer)

    def read(self, size: Optional[int] = None) -> bytes:
        with self.lock:
            result = bytearray()

            if len(self.deque) == 0:
                return result

            while 1:
                entry = self.deque.popleft()
                new_len_result = len(result) + len(entry)

                if new_len_result > size:
                    oversize = new_len_result - size
                    # Return over-sized buffer to the queue.
                    oversize_buffer = entry[-oversize:]
                    self.deque.appendleft(oversize_buffer)
                    # Cut down next entry.
                    entry = entry[:-oversize]

                result += entry

                if (size != -1 and len(result) == size) or len(self.deque) == 0:
                    break

            return result


@dataclass
class CurlStreamer:
    curl: pycurl.Curl
    manager: 'CurlManager'
    output: StreamedBytes
    _headers: CaseInsensitiveDict

    _status_code: Optional[int] = None
    done: threading.Event = field(default_factory=threading.Event)
    timeout_seconds: float = 5.0

    def _wait_for_headers(self) -> None:
        # If we're already done there's nothing to wait for.
        if self.done.is_set():
            return

        start_time = time.time()
        while not self.output.first_write_event.is_set():
            # `run_iteration` either waits to acquire lock or
            # waits on select, so this can be counted as a form of sleep.
            self.manager.run_iteration()

            if (time.time() - start_time) > self.timeout_seconds:
                raise TimeoutError()

    def _get_and_cache_status_code(self) -> int:
        if self._status_code is None:
            self._status_code = self.curl.getinfo(pycurl.RESPONSE_CODE)
        return self._status_code

    @property
    def status_code(self) -> int:
        self._wait_for_headers()
        return self._get_and_cache_status_code()

    @property
    def headers(self) -> CaseInsensitiveDict:
        self._wait_for_headers()
        return self._headers

    def read(self, count: int) -> bytes:
        self.manager.run_iteration()
        return self.output.read(count)

    def run_blocking(self) -> None:
        self.curl.perform()
        self.close()

    def close(self) -> None:
        # We won't be able to reclaim the status code once we release the object.
        self._get_and_cache_status_code()
        self.curl.close()
        self.done.set()

    @property
    def is_reading_done(self) -> bool:
        return self.done.is_set() and self.output.is_empty()


class CurlManager:
    SELECT_SLEEP_SECONDS = 1.0
    ACQUIRE_SLEEP_SECONDS = 0.1

    def __init__(self):
        self.multi = pycurl.CurlMulti()
        self.lock = threading.Lock()
        self.mapping: dict[pycurl.Curl, CurlStreamer] = {}

        self.run_lock = threading.Lock()

    def add_curl(self, streamer: CurlStreamer) -> None:
        # Block, so that no-one can iterate over curls while we're waiting for the headers.
        with self.lock:
            self.mapping[streamer.curl] = streamer
            self.multi.add_handle(streamer.curl)
            # Running first "perform" ensures that this curl is taken into account.
            # Subsequent calls to `select` will return non-zero as long as it's working.
            self.multi.perform()

    def run_iteration(self) -> None:
        # Allow only one thread at a time to run iteration. Truth is, if you're waiting
        # for `run_iteration` it's possible that your curl already has something to show.
        # And if it's hung on select, it means that the network is having issues, so
        # no need to go there anyway.
        if not self.run_lock.acquire(timeout=self.ACQUIRE_SLEEP_SECONDS):
            return
        try:
            self._run_iteration()
        finally:
            self.run_lock.release()

    def _run_iteration(self) -> None:
        result = self.multi.select(self.SELECT_SLEEP_SECONDS)
        if result == 0:
            return

        status, _count = self.multi.perform()
        # TODO: add status checking.

        with self.lock:
            # Check whether any of the curls finished, in one way or another.
            remaining_messages_count, successful_curls, failed_curls = self.multi.info_read()
            # Remove each finished curl from our multi object and close it.
            finished_curls = successful_curls + [elem[0] for elem in failed_curls]
            for curl in finished_curls:
                self.multi.remove_handle(curl)
                streamer = self.mapping[curl]
                streamer.close()


@dataclass
class CurlResponse:
    streamer: CurlStreamer
    request: CurlRequest

    content_cache: Optional[bytes] = None

    @property
    def status_code(self) -> int:
        return self.streamer.status_code

    @property
    def headers(self) -> CaseInsensitiveDict:
        return self.streamer.headers

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    @property
    def content(self) -> bytes:
        if self.content_cache is None:
            self.content_cache = b''.join(self.iter_content(1024))
        return self.content_cache

    def iter_content(self, chunk_size: int) -> Iterator[bytes]:
        while True:
            data = self.streamer.read(chunk_size)
            if not data:
                if self.streamer.is_reading_done:
                    break
                else:
                    continue

            yield data

    def close(self):
        pass


def read_headers(header_line: bytes, output: CaseInsensitiveDict):
    # HTTP standard specifies that headers are encoded in iso-8859-1.
    # On Python 2, decoding step can be skipped.
    # On Python 3, decoding step is required.
    header_line = header_line.decode('iso-8859-1')

    # Header lines include the first status line (HTTP/1.x ...).
    # We are going to ignore all lines that don't have a colon in them.
    # This will botch headers that are split on multiple lines...
    if ':' not in header_line:
        return

    # Break the header line into header name and value.
    name, value = header_line.split(':', 1)

    # Remove whitespace that may be present.
    # Header lines include the trailing newline, and there may be whitespace
    # around the colon.
    name = name.strip()
    value = value.strip()

    # Header names are case insensitive.
    # Lowercase name here.
    name = name.lower()

    # Now we can actually record the header name and value.
    # Note: this only works when headers are not duplicated, see below.
    output[name] = value


def headers_to_list(headers: Dict[str, str]) -> List[str]:
    result = []
    for key, value in headers.items():
        if value is None:
            continue

        if isinstance(value, bytes):
            value = value.decode('utf8')

        result.append(f'{key}: {value}')

    return result


class CurlSession:
    TIMEOUT = 5
    EXPECT_100_TIMEOUT = 10
    BUFFER_SIZE_BYTES = 10 * 1024 * 1024
    VERBOSE = False
    NO_SIGNAL = 0

    def __init__(self, *args, **kwargs):
        self.adapters = CurlAdapters()
        self.manager = CurlManager()

    def mount(self, scheme, adapter):
        self.adapters.adapters[scheme] = adapter

    def request(
        self,
        url: str,
        method: Literal['get', 'post'],
        headers: Optional[Dict[str, Union[str, bytes]]] = None,
        data: Optional[BytesIO] = None,
        timeout: int = TIMEOUT,
        stream: bool = False,
    ) -> CurlResponse:
        from b2sdk.b2http import NotDecompressingHTTPAdapter

        # Currently head is incompatible with stream.
        if method == 'head':
            stream = False

        output = StreamedBytes()
        output_headers = CaseInsensitiveDict()

        curl = pycurl.Curl()
        curl.setopt(pycurl.VERBOSE, self.VERBOSE)
        curl.setopt(pycurl.URL, url)
        if headers:
            curl.setopt(pycurl.HTTPHEADER, headers_to_list(headers))
        curl.setopt(pycurl.EXPECT_100_TIMEOUT_MS, self.EXPECT_100_TIMEOUT * 1000)
        curl.setopt(pycurl.BUFFERSIZE, self.BUFFER_SIZE_BYTES)
        curl.setopt(pycurl.NOSIGNAL, self.NO_SIGNAL)
        curl.setopt(pycurl.CAINFO, certifi.where())
        curl.setopt(pycurl.WRITEDATA, output)
        if method == 'head':
            curl.setopt(pycurl.NOBODY, True)
        elif method == 'post':
            curl.setopt(pycurl.POST, 1)
            data = data or BytesIO()
            curl.setopt(pycurl.READDATA, data)
            content_length = data.length if isinstance(data, ReadingStreamWithProgress) else len(
                data.getvalue()
            )
            curl.setopt(pycurl.POSTFIELDSIZE, content_length)
        curl.setopt(pycurl.TIMEOUT_MS, timeout * 1000)
        curl.setopt(pycurl.HEADERFUNCTION, partial(read_headers, output=output_headers))
        if any(
            isinstance(adapter, NotDecompressingHTTPAdapter)
            for adapter in self.adapters.adapters.values()
        ):
            curl.setopt(pycurl.HTTP_CONTENT_DECODING, False)
        else:
            curl.setopt(pycurl.HTTP_CONTENT_DECODING, True)
            curl.setopt(pycurl.ACCEPT_ENCODING, '')

        streamer = CurlStreamer(
            curl,
            self.manager,
            output,
            output_headers,
            timeout_seconds=timeout,
        )

        if stream:
            self.manager.add_curl(streamer)
        else:
            streamer.run_blocking()

        return CurlResponse(
            streamer=streamer,
            request=CurlRequest(
                url=url,
                headers=CaseInsensitiveDict(headers) if headers else CaseInsensitiveDict(),
            ),
        )

    head = partialmethod(request, method='head')
    get = partialmethod(request, method='get')
    post = partialmethod(request, method='post')
