######################################################################
#
# File: test/integration/base.py
#
# Copyright 2022 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

import http.client
import os

import pytest

from b2sdk.test.api_test_manager import ApiTestManager


class IntegrationTestBase:
    @pytest.fixture(autouse=True)
    def set_http_debug(self):
        if os.environ.get('B2_DEBUG_HTTP'):
            http.client.HTTPConnection.debuglevel = 1

    @pytest.fixture(autouse=True)
    def setup_method(self, b2_auth_data, realm):
        self.b2_api = ApiTestManager(*b2_auth_data, realm)
        self.info = self.b2_api.account_info
        yield
        self.b2_api.clean_buckets()

    def write_zeros(self, file, number):
        line = b'0' * 1000 + b'\n'
        line_len = len(line)
        written = 0
        while written <= number:
            file.write(line)
            written += line_len

    def create_bucket(self):
        return self.b2_api.create_test_bucket()
