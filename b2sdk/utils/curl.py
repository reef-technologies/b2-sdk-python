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
cURL – how does it work

cURL provides a simple, low level interface pycurl.Curl that represents a single request.
This request can be awaited on (blocking mode) or bunched in a group to be done in parallel.

cURL also provides bunch-interface, pycurl.CurlMulti. It uses `select`-like approach to determine
whether there's data waiting for any of the Curl object. Everything can be done in a single thread.

From our perspective, we're wrapping these classes into our own abstractions. We have CurlManager
that is thread-safe and handles everything Curl-object related, including informing them when
they are finished. We have CurlStreamer, which wraps simple Curl with a more recognisable interface.

`requests` always provide us with headers and status code as soon as available. This is not
the case here – when a Curl object is streamed we're receiving all the bytes in a raw form.
Not only content, but also headers and status line are going through our hands. We need to ensure
that we e.g. fetch the status code before the Curl object is closed (after which the underlying
C structure is lost, and we're just holding an empty shell).

For this reason, StreamedBytes are also provided. It's a buffer that grows as data is provided
and shrinks as it's removed, but also informs whenever first write was performed. This allows
us to determine whether all the headers are actually downloaded and available.

In short:
- CurlStreamer handles a single query and provides means of handling headers/status code/data fetching
- StreamedBytes provides us with a buffer behaving as if it has both reading and writing offsets
- CurlManager is ensuring that multiple streamed queries get their updates, and limits the amount of data downloaded
- Everything is done without another thread – CurlStreamer will ask CurlManager to poll
  for new data whenever it's asked for data, headers or a status code
"""

import email.parser
import threading
import time
from dataclasses import dataclass, field
from functools import partialmethod
from io import BytesIO
from typing import Any, Dict, Iterator, List, Optional, Union, Tuple

import certifi
import pycurl

from requests.utils import CaseInsensitiveDict

from b2sdk.stream.progress import ReadingStreamWithProgress
from b2sdk.utils.cookie_jar import CookieJar
from b2sdk.utils.not_decompresing_http_adapter import NotDecompressingHTTPAdapter
from b2sdk.utils.streamed_bytes import StreamedBytes, StreamedBytesFactory


@dataclass
class CurlAdapters:
    """
    requests-like adapters handler
    """
    adapters: dict = field(default_factory=dict)

    def clear(self):
        self.adapters = {}

    def add_adapter(self, scheme: str, adapter: Any) -> None:
        self.adapters[scheme] = adapter

    def get_by_url(self, url: str) -> Any:
        """
        Provides adapter assigned to the closest match registered (or None).
        """
        longest_matched_prefix_len = -1
        result = None

        for prefix, value in self.adapters.items():
            if url.startswith(prefix) and len(prefix) > longest_matched_prefix_len:
                longest_matched_prefix_len = len(prefix)
                result = value

        return result


@dataclass
class CurlRequest:
    url: str
    headers: CaseInsensitiveDict


class HeadersReader:
    # RFC 2086 Section 4.2 states:
    # HTTP header fields (...) follow the same generic format as that given in Section 3.1 of RFC 822
    #
    # email.parser is made to parse RFC 822 headers. Only difference is in encodings. By default,
    # email.parser uses ASCII encoding while RFC 2086 requires ISO-8859-1. We'll conform to the latter.
    PARSER = email.parser.HeaderParser()
    ENCODING = 'iso-8859-1'

    def __init__(self):
        self.lines = []
        self.headers: Optional[CaseInsensitiveDict] = None
        self.raw_headers: List[Tuple[str, str]] = field(default_factory=list)

    def add_header_line(self, line: bytes) -> None:
        # First line of the header contains http version and status code.
        # Last line of the header contains just `\r\n`. Removing both.
        if line.startswith(b'HTTP/') or len(line.strip()) == 0:
            return
        self.lines.append(line)

    def parse_headers(self) -> None:
        if self.headers is not None:
            return

        parsed_header = self.PARSER.parsestr(
            b''.join(self.lines).decode(self.ENCODING),
            headersonly=True,
        )
        self.raw_headers = [pair for pair in parsed_header.items()]
        self.headers = CaseInsensitiveDict(self.raw_headers)


@dataclass
class CurlStreamer:
    """
    Simple Curl object wrapper.

    It provides a friendly interface without worrying about "how much data was provided".

    Note that it can be used without `CurlManager`, `CurlStreamer.run_blocking`
    will perform the request in a "blocking" manner, providing all the data
    (including headers and status code) at once.

    In case of streamed mode, calling either `headers` or `status_code` will block execution
    until enough data was downloaded. `CurlManager` will be called in a loop until either
    we get to the content section of the HTTP response or the whole query was downloaded.
    """

    curl: pycurl.Curl
    # There's no way to fetch it from Curl, and we need it to handle cookies.
    url: str
    manager: 'CurlManager'
    output: StreamedBytes
    _headers: HeadersReader
    jar: CookieJar

    _status_code: Optional[int] = None
    done: threading.Event = field(default_factory=threading.Event)
    timeout_seconds: float = 120.0

    def _wait_for_headers(self) -> None:
        """
        Function that ensures that all the headers are downloaded,
        or TimeoutError is raised.

        We know that all the headers are ready from two different sources:
        - instance can be marked as `done` by `CurlManager`
        - output buffer can inform that it received any amount of data

        This function performs no parsing, it only ensures that conditions
        are met and call `CurlManager.run_iteration` until it's done.
        """
        start_time = time.time()
        # Stop if we're either done or had any content written.
        while not self.done.is_set() and not self.output.first_write_event.is_set():
            # `run_iteration` either waits to acquire lock so this can be counted as a form of sleep.
            self.manager.run_iteration()

            if (time.time() - start_time) > self.timeout_seconds:
                raise TimeoutError()

    def _get_and_cache_status_code(self) -> int:
        if self._status_code is None:
            # This lock is required to ensure that we're not during "perform" operation.
            with self.manager.perform_lock:
                # After curl object is closed we won't be able to fetch it any more.
                self._status_code = self.curl.getinfo(pycurl.RESPONSE_CODE)
        return self._status_code

    @property
    def status_code(self) -> int:
        self._wait_for_headers()
        return self._get_and_cache_status_code()

    @property
    def headers(self) -> CaseInsensitiveDict:
        self._wait_for_headers()
        self._headers.parse_headers()
        return self._headers.headers

    def fetch_data(self, count: int) -> bytes:
        """
        Perform a read from Curl object in streaming mode.

        It also ensures that `CurlManager.run_iteration` is called,
        so that data is fed to all waiting `CurlStreamer` objects.

        This operation can be delayed by said `CurlManager.run_iteration`, but
        otherwise it's non-blocking in regard to reading from the output buffer.
        """
        self.manager.run_iteration()
        return self.output.read(count)

    def run_blocking(self) -> None:
        """
        Perform a fully blocking HTTP request.

        Use only for small operations, as all data
        has to be downloaded before it's provided.
        """
        self.curl.perform()
        self.close()

    @property
    def is_reading_done(self) -> bool:
        """
        Information whether it's worth to wait for any more data.

        Use with conjunction with `fetch_data` to download whole content.
        """
        return self.done.is_set() and self.output.is_empty()

    def close(self) -> None:
        # We won't be able to reclaim the status code once we release the object.
        self._get_and_cache_status_code()
        self._headers.parse_headers()
        self.jar.add_headers(self.url, self._headers.raw_headers)
        self.curl.close()
        # When reading will finish from this buffer, we can release it safely.
        self.output.mark_for_release()
        self.done.set()


class CurlManager:
    """
    Wrapper for CurlMulti operations.

    Contains CurlMulti, gathers all simple Curl objects,
    manages their processing and informs them that they are finished.

    It contains two locks:
    - run_lock – lock that ensures that only a single run_iteration is handled at the given time.
    - perform_lock – lock that protects perform operation and all operations that are exclusive to it.
                 This includes add/remove_handler/select from CurlMulti and getinfo from Curl.

    Whenever an operation with curl is to be made, e.g. headers fetching or content iteration,
    one should first invoke `run_iteration` to ensure that curl process progresses with all the updates
    from the network.

    Note that `run_iteration` can become a no-op if too much data was downloaded and not enough of it
    was ingested.

    Whenever `output` is set for CurlStreamer, it should be obtained via `CurlManager.buffer_factory.get_buffer`.
    This way this class can limit the amount of content downloaded and not consumed.

    Whole class is thread safe.

    By default, multiplexing is enabled. https://curl.se/libcurl/c/CURLMOPT_PIPELINING.html
    """

    ACQUIRE_SLEEP_SECONDS = 0.1

    def __init__(self, max_used_memory_bytes: int):
        self.multi = pycurl.CurlMulti()
        self.multi.setopt(pycurl.M_PIPELINING, pycurl.PIPE_MULTIPLEX | pycurl.PIPE_HTTP1)  # noqa

        self.mapping: dict[pycurl.Curl, CurlStreamer] = {}

        self.buffers_factory = StreamedBytesFactory()
        self.max_used_memory_bytes = max_used_memory_bytes

        # Re-entrant, as it's possible that Curl will try to do
        # `getinfo` during CurlStreamer.close from the same thread.
        self.perform_lock = threading.RLock()

        self.run_lock = threading.Lock()

    def add_curl(self, streamer: CurlStreamer) -> None:
        """
        Add a CurlStreamer for parallel processing.

        After running this operation calling `CurlStreamer.run_blocking`
        will lead to an undefined behaviour.

        This function is thread-safe.

        :param streamer: CurlStreamer object to be added
        """
        with self.perform_lock:
            self.mapping[streamer.curl] = streamer
            self.multi.add_handle(streamer.curl)

    def run_iteration(self) -> None:
        """
        Fetch data for all added CurlStreamer objects.

        This should be run whenever data (status code, headers, content) is required from
        any of the streamed Curl objects. During run not only Curl callbacks will be called,
        but also Curl objects may be closed and cleaned up.

        This function is thread-safe. Only a single thread is allowed to run this operation in parallel.
        Other threads trying to run this function will be blocked for a certain amount of time.

        If buffers created by buffers_factory are used with CurlStreamers, this operation
        can become a no-op in case that too much data is downloaded and not consumed.
        """
        # Truth is, if you're waiting for `run_iteration` it's possible that your curl already has something
        # to show. This is a separate lock than the perform lock, as the latter has to be re-entrant.
        if not self.run_lock.acquire(timeout=self.ACQUIRE_SLEEP_SECONDS):
            return
        try:
            self._run_iteration()
        finally:
            self.run_lock.release()

    def _run_iteration(self) -> None:
        # We could use select here for cases when there is nothing to do (no curls registered)
        # but this provides us with no actual gain. `run_iteration` is called by any thread
        # that wants data, so naturally there are operations awaiting data.
        with self.perform_lock:
            # If we already went above our memory limit, we must wait for some queries to finish first.
            # Note that this memory is only counted for payload – headers and status codes are not added up here.
            if self.buffers_factory.get_total_buffer_memory() >= self.max_used_memory_bytes:
                return

            # Perform also have to be inside this lock to ensure that neither `add_handler`
            # nor `Curl.getinfo` is called during this operation.
            status, _count = self.multi.perform()
            # Usual culprits here could be "out of memory" and "internal error",
            # we can't really do anything about either of them.
            assert status == pycurl.E_MULTI_OK, status

            # Check whether any of the curls finished, in one way or another.
            remaining_messages_count, successful_curls, failed_curls = self.multi.info_read()
            # Remove each finished curl from our multi object and close it.
            finished_curls = successful_curls + [elem[0] for elem in failed_curls]
            # TODO: additional handling for failed curls.
            for curl in finished_curls:
                self.multi.remove_handle(curl)
                streamer = self.mapping[curl]
                streamer.close()


@dataclass
class CurlResponse:
    """
    Analog of requests.Response

    Provides basic interface for interaction with HTTP.

    Note that in streaming mode it can be completely "empty",
    that is neither status code nor headers are downloaded initially.
    This means that first call to `status_code`, `headers` or
    `iter_content` (through e.g. `content`) will start the actual operations.
    """

    streamer: CurlStreamer
    request: CurlRequest

    content_cache: Optional[bytes] = None

    @property
    def url(self) -> str:
        return self.request.url

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
            data = self.streamer.fetch_data(chunk_size)
            if not data:
                if self.streamer.is_reading_done:
                    break
                else:
                    continue

            yield data

    def close(self):
        pass


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
    """
    SessionProtocol-like object.

    Provides low level interface for performing HTTP requests.
    """

    TIMEOUT_SECONDS = 120
    EXPECT_100_TIMEOUT_SECONDS = 10
    BUFFER_SIZE_BYTES = 10 * 1024 * 1024
    MAX_DOWNLOAD_MEMORY_SIZE_BYTES = 200 * 1024 * 1024
    VERBOSE = False
    NO_SIGNAL = 0

    def __init__(self, *args, **kwargs):  # noqa (unused arguments)
        self.adapters = CurlAdapters()
        self.manager = CurlManager(self.MAX_DOWNLOAD_MEMORY_SIZE_BYTES)
        self.jar = CookieJar()

    def mount(self, scheme: str, adapter: Any) -> None:
        self.adapters.add_adapter(scheme, adapter)

    def request(
        self,
        url: str,
        method: str,
        headers: Optional[Dict[str, Union[str, bytes]]] = None,
        data: Optional[BytesIO] = None,
        timeout: int = TIMEOUT_SECONDS,
        stream: bool = False,
    ) -> CurlResponse:
        output = self.manager.buffers_factory.get_buffer()
        output_headers = HeadersReader()

        curl = pycurl.Curl()
        curl.setopt(pycurl.VERBOSE, self.VERBOSE)
        curl.setopt(pycurl.URL, url)
        if headers:
            curl.setopt(pycurl.HTTPHEADER, headers_to_list(headers))
        for cookie in self.jar.iter_cookies(url):
            curl.setopt(pycurl.COOKIE, cookie)
        curl.setopt(pycurl.EXPECT_100_TIMEOUT_MS, self.EXPECT_100_TIMEOUT_SECONDS * 1000)
        curl.setopt(pycurl.BUFFERSIZE, self.BUFFER_SIZE_BYTES)
        curl.setopt(pycurl.NOSIGNAL, self.NO_SIGNAL)
        curl.setopt(pycurl.CAINFO, certifi.where())
        # It will use `write` method of provided object.
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
        curl.setopt(pycurl.HEADERFUNCTION, output_headers.add_header_line)

        mounted_adapter = self.adapters.get_by_url(url)
        if isinstance(mounted_adapter, NotDecompressingHTTPAdapter):
            curl.setopt(pycurl.HTTP_CONTENT_DECODING, False)
        else:
            curl.setopt(pycurl.HTTP_CONTENT_DECODING, True)
            curl.setopt(pycurl.ACCEPT_ENCODING, '')

        streamer = CurlStreamer(
            curl,
            url,
            self.manager,
            output,
            output_headers,
            self.jar,
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
