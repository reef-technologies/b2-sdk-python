from dataclasses import dataclass, field
from functools import partial, partialmethod
from io import BytesIO
from typing import Dict, Generator, List, Literal, Optional, Union

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


@dataclass
class CurlResponse:
    status_code: int
    headers: CaseInsensitiveDict
    stream: BytesIO
    request: CurlRequest

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    @property
    def content(self) -> bytes:
        return self.stream.getvalue()

    def iter_content(self, chunk_size: int) -> Generator[bytes, None, None]:
        while True:
            data = self.stream.read(chunk_size)
            if not data:
                break

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

    def mount(self, scheme, adapter):
        self.adapters.adapters[scheme] = adapter

    def request(
        self,
        url: str,
        method: Literal['get', 'post'],
        headers: Optional[Dict[str, Union[str, bytes]]] = None,
        data: Optional[BytesIO] = None,
        timeout: int = TIMEOUT,
        stream: bool = False,  # TODO
    ) -> CurlResponse:
        from b2sdk.b2http import NotDecompressingHTTPAdapter

        output = BytesIO()
        output_headers = CaseInsensitiveDict()

        curl = pycurl.Curl()
        curl.setopt(curl.VERBOSE, self.VERBOSE)
        curl.setopt(curl.URL, url)
        if headers:
            curl.setopt(curl.HTTPHEADER, headers_to_list(headers))
        curl.setopt(curl.EXPECT_100_TIMEOUT_MS, self.EXPECT_100_TIMEOUT * 1000)
        curl.setopt(curl.BUFFERSIZE, self.BUFFER_SIZE_BYTES)  # TODO
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

        curl.perform()
        status_code = curl.getinfo(curl.RESPONSE_CODE)
        curl.close()

        output.seek(0)
        return CurlResponse(
            status_code=status_code,
            headers=output_headers,
            stream=output,
            request=CurlRequest(url=url, headers=headers),
        )

    head = partialmethod(request, method='head')
    get = partialmethod(request, method='get')
    post = partialmethod(request, method='post')
