######################################################################
#
# File: test/unit/internal/test_cookie_jar.py
#
# Copyright 2022 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
import datetime

from b2sdk.utils.cookie_jar import CookieJar
from test.unit.test_base import TestBase


class TestCookieJar(TestBase):
    """
    This class only tests a facade, it's assumed that the underlying CookieJar is working as intended.
    """

    def setUp(self) -> None:
        super().setUp()
        self.jar = CookieJar()

    def test_store_cookies_from_headers(self):
        url = 'https://example.com'
        cookie_value = 'test=value'
        expires = datetime.datetime.now() + datetime.timedelta(hours=1)
        expires_str = expires.strftime("%a, %d %b %Y %H:%M:%S GMT")
        full_cookie = cookie_value + f'; Expires={expires_str}; Secure; HttpOnly'

        example_headers = [('Set-Cookie', full_cookie)]
        self.jar.add_headers(url, example_headers)
        all_entries = [elem for elem in self.jar.iter_cookies(url)]
        self.assertEqual([cookie_value], all_entries)

    def test_no_cookies(self):
        url = 'https://example.com'
        self.jar.add_headers(url, [])
        all_entries = [elem for elem in self.jar.iter_cookies(url)]
        self.assertEqual(0, len(all_entries))
