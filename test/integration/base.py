######################################################################
#
# File: test/integration/base.py
#
# Copyright 2022 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
from __future__ import annotations

from test.integration.bucket_cleaner import BucketCleaner
from test.integration.persistent_bucket import PersistentBucketAggregate

import pytest

from b2sdk.v2 import B2Api


@pytest.mark.usefixtures("cls_setup")
class IntegrationTestBase:
    b2_api: B2Api
    this_run_bucket_name_prefix: str
    bucket_cleaner: BucketCleaner
    persistent_bucket: PersistentBucketAggregate

    @pytest.fixture(autouse=True, scope="class")
    def cls_setup(
        self, request, b2_api, b2_auth_data, bucket_name_prefix, bucket_cleaner, persistent_bucket
    ):
        cls = request.cls
        cls.b2_auth_data = b2_auth_data
        cls.this_run_bucket_name_prefix = bucket_name_prefix
        cls.bucket_cleaner = bucket_cleaner
        cls.b2_api = b2_api
        cls.info = b2_api.account_info
        cls.persistent_bucket = persistent_bucket

    def write_zeros(self, file, number):
        line = b'0' * 1000 + b'\n'
        line_len = len(line)
        written = 0
        while written <= number:
            file.write(line)
            written += line_len
