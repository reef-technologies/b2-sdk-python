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
from contextlib import suppress
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
    def __init__(self):
        # We store our data in chunks in a deque. Whenever data is requested,
        # we remove them from deque up to the size, and put back the reminder.
        self.deque = collections.deque()
        self.lock = threading.Lock()
        self.first_write_event = threading.Event()

    def write(self, buffer) -> int:
        with self.lock:
            if len(buffer) == 0:
                return 0

            self.deque.append(buffer)
            if not self.first_write_event.is_set():
                self.first_write_event.set()

            return len(buffer)

    def read(self, size: Optional[int] = None) -> bytes:
        with self.lock:
            result = b''

            if len(self.deque) == 0:
                return result

            while 1:
                entry = self.deque.popleft()
                result += entry

                if size != -1 and len(result) > size:
                    back_data = result[size:]
                    result = result[:size]
                    self.deque.appendleft(back_data)

                if size != -1 and len(result) == size:
                    break

                # If we have no more data – also return.
                if len(self.deque) == 0:
                    break

            return result


class CurlManager:
    def __init__(self):
        self.multi = pycurl.CurlMulti()
        # Set that contains curls that finished.
        # Information is saved to it when curl finishes and removed from it whenever it's read.
        self.did_curl_finish = set()
        self.lock = threading.Lock()
        self.iterate_lock = threading.Lock()

    def add_curl(self, curl: pycurl.Curl, awaiter_function) -> None:
        # Block, so that no-one can iterate over curls while we're waiting for the headers.
        with self.iterate_lock:
            with self.lock:
                self.multi.add_handle(curl)

            while True:
                # We need to keep the curl so that header can be read from it.
                self._iterate_curls(remove_finished=False)

                # Iterate have to be called at least once before we leave.
                if awaiter_function():
                    return

    def did_curl_finish_get_and_remove(self, curl: pycurl.Curl) -> bool:
        with self.lock:
            with suppress(KeyError):
                self.did_curl_finish.remove(curl)
                return True
            return False

    def iterate_curls(self) -> None:
        # Allow only for one parallel iterate curls, no matter how many threads are asking.
        # Under this lock self.lock can be acquired. Order is important.
        if not self.iterate_lock.acquire(blocking=False):
            return
        try:
            self._iterate_curls(remove_finished=True)
        finally:
            self.iterate_lock.release()

    def _iterate_curls(self, remove_finished: bool) -> None:
        # We could perform select here to check whether anything is waiting for us,
        # but we're only interested in non-blocking operations anyway, so we can
        # skip to just doing "perform".

        status, _count = self.multi.perform()
        # TODO: add status checking.

        # Don't check for messages if we're not to purge some of these curls.
        if not remove_finished:
            return

        # Check whether any of the curls finished, in one way or another.
        remaining_messages_count, successful_curls, failed_curls = self.multi.info_read()
        with self.lock:
            # Remove each finished curl from our multi object and close it.
            finished_curls = successful_curls + [elem[0] for elem in failed_curls]
            for curl in finished_curls:
                self.multi.remove_handle(curl)
                curl.close()
                self.did_curl_finish.add(curl)


@dataclass
class CurlResponse:
    # The parent that updates all the curl objects, or False
    manager: Union[CurlManager, bool]
    # Current curl object, we need to take care of releasing it
    curl: pycurl.Curl

    status_code: int
    headers: CaseInsensitiveDict
    stream: StreamedBytes
    request: CurlRequest

    content_cache: Optional[bytes] = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    @property
    def content(self) -> bytes:
        if self.content_cache is None:
            self.content_cache = b''.join(self.iter_content(1024))
        return self.content_cache

    def iter_content(self, chunk_size: int) -> Iterator[bytes]:
        did_finish = not self.manager
        while True:
            if self.manager:
                self.manager.iterate_curls()
                # Manager returns true exactly once. We keep
                # the returned value until we finish providing content.
                did_finish = did_finish or self.manager.did_curl_finish_get_and_remove(self.curl)

            data = self.stream.read(chunk_size)
            if not data:
                if did_finish:
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
        curl.setopt(curl.VERBOSE, self.VERBOSE)
        curl.setopt(curl.URL, url)
        if headers:
            curl.setopt(curl.HTTPHEADER, headers_to_list(headers))
        curl.setopt(curl.EXPECT_100_TIMEOUT_MS, self.EXPECT_100_TIMEOUT * 1000)
        curl.setopt(curl.BUFFERSIZE, self.BUFFER_SIZE_BYTES)
        curl.setopt(curl.NOSIGNAL, self.NO_SIGNAL)
        curl.setopt(curl.CAINFO, certifi.where())
        curl.setopt(curl.WRITEDATA, output)
        if method == 'head':
            curl.setopt(curl.NOBODY, True)
        elif method == 'post':
            curl.setopt(curl.POST, 1)
            data = data or BytesIO()
            curl.setopt(curl.READDATA, data)
            content_length = data.length if isinstance(data, ReadingStreamWithProgress) else len(
                data.getvalue()
            )
            curl.setopt(curl.POSTFIELDSIZE, content_length)
        curl.setopt(curl.TIMEOUT_MS, timeout * 1000)
        curl.setopt(curl.HEADERFUNCTION, partial(read_headers, output=output_headers))
        if any(
            isinstance(adapter, NotDecompressingHTTPAdapter)
            for adapter in self.adapters.adapters.values()
        ):
            curl.setopt(curl.HTTP_CONTENT_DECODING, False)
        else:
            curl.setopt(curl.HTTP_CONTENT_DECODING, True)
            curl.setopt(curl.ACCEPT_ENCODING, '')

        if stream:
            # Waiting for the first write content event to ensure that
            # status code and the headers are ready.
            self.manager.add_curl(curl, output.first_write_event.is_set)
        else:
            curl.perform()

        status_code = curl.getinfo(curl.RESPONSE_CODE)

        if not stream:
            curl.close()

        return CurlResponse(
            manager=stream and self.manager,
            curl=curl,
            status_code=status_code,
            headers=output_headers,
            stream=output,
            request=CurlRequest(url=url, headers=headers),
        )

    head = partialmethod(request, method='head')
    get = partialmethod(request, method='get')
    post = partialmethod(request, method='post')
