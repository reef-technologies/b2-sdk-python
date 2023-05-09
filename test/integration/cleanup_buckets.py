######################################################################
#
# File: test/integration/cleanup_buckets.py
#
# Copyright 2021 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

from . import get_b2_auth_data, get_realm
from b2sdk.test.api_test_manager import ApiTestManager
from .test_raw_api import cleanup_old_buckets

if __name__ == '__main__':
    cleanup_old_buckets()
    ApiTestManager(*get_b2_auth_data(), get_realm()).clean_all_buckets()
