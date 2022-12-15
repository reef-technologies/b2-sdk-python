######################################################################
#
# File: b2sdk/utils/cookie_jar.py
#
# Copyright 2022 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
import email.parser
import threading
import urllib.parse
from dataclasses import (
    dataclass,
    field,
)
from http.cookiejar import CookieJar as HttpCookieJar
from typing import (
    Iterator,
    List,
    Tuple,
)

from requests.structures import CaseInsensitiveDict


class CookieJar:
    """
    Wrapper that handles cookies in an interface-agnostic way.
    All you need is to provide url and headers on one end,
    and you'll receive strings on another end.

    This class is thread-safe.
    """

    # Mocks urllib.request.Request interface required by
    # http.cookiejar.CookieJar.extract_cookies and http.cookiejar.CookieJar.add_cookie_header
    @dataclass
    class _Request:
        url: str
        origin_req_host: str

        headers: CaseInsensitiveDict = field(default_factory=CaseInsensitiveDict)
        unverifiable: bool = False
        cookies: List[str] = field(default_factory=list)

        parsed_url = None

        def __post_init__(self):
            self.parsed_url = urllib.parse.urlparse(self.url)

        @property
        def type(self) -> str:
            return self.parsed_url.scheme

        @property
        def host(self) -> str:
            return self.parsed_url.hostname

        def has_header(self, header_name: str) -> bool:
            return header_name in self.headers

        def get_header(self, header_name: str) -> str:
            return self.headers[header_name]

        def header_items(self) -> Iterator[Tuple[str, str]]:
            for pair in self.headers.items():
                yield pair

        def add_unredirected_header(self, header_name, header_value) -> None:
            # It is assumed that CookieJar will only touch cookies in this way.
            self.cookies.append(header_value)
            self.headers[header_name] = header_value

        def get_full_url(self) -> str:
            return self.url

    # Mocks urllib.request.HTTPResponse interface
    # required by http.cookiejar.CookieJar.extract_cookies
    @dataclass
    class _Response:
        headers: List[Tuple[str, str]]

        def info(self) -> email.message.EmailMessage:
            message = email.message.EmailMessage()
            for key, value in self.headers:
                message.add_header(key, value)
            return message

    def __init__(self):
        self.lock = threading.Lock()
        # Default policy is to support netscape and to not support Set-Cookie2.
        # This way we know that we should receive only one set of cookies.
        self.jar = HttpCookieJar()
        self.original_host = None

    def add_headers(self, url: str, headers: List[Tuple[str, str]]) -> None:
        """
        Add Cookies

        Headers are filtered and cookies are assigned to the url.
        If this is the very first query, host is also assumed
        to be the original host for purposes of future requests.
        """
        with self.lock:
            response = self._Response(headers)
            request = self._Request(url, self.original_host)

            if self.original_host is None:
                self.original_host = request.host

            self.jar.extract_cookies(response, request)  # noqa (provided classes meet minimal interface requirements)

    def iter_cookies(self, url: str) -> Iterator[str]:
        """
        Fetches all the cookies from the jar for given url.
        """
        with self.lock:
            request = self._Request(url, self.original_host)
            self.jar.add_cookie_header(request)  # noqa (provided class meets minimal interface requirements)
            for cookie in request.cookies:
                yield cookie

    def clear(self) -> None:
        with self.lock:
            self.original_host = None
            self.jar.clear()
