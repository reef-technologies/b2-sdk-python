######################################################################
#
# File: test/integration/helpers.py
#
# Copyright 2022 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
from __future__ import annotations

import os
import re
import secrets
import sys
import time

from b2sdk._internal.b2http import B2Http
from b2sdk._internal.file_lock import NO_RETENTION_FILE_SETTING
from b2sdk._internal.raw_api import REALM_URLS, B2RawHTTPApi
from b2sdk.v2 import (
    BUCKET_NAME_CHARS_UNIQ,
    BUCKET_NAME_LENGTH_RANGE,
    DEFAULT_HTTP_API_CONFIG,
    B2Api,
    InMemoryAccountInfo,
)

GENERAL_BUCKET_NAME_PREFIX = 'sdktst'
BUCKET_NAME_LENGTH = BUCKET_NAME_LENGTH_RANGE[1]
BUCKET_CREATED_AT_MILLIS = 'created_at_millis'

RNG = secrets.SystemRandom()


def _bucket_name_prefix_part(length: int) -> str:
    return ''.join(RNG.choice(BUCKET_NAME_CHARS_UNIQ) for _ in range(length))


def get_bucket_name_prefix(rnd_len: int = 8) -> str:
    return GENERAL_BUCKET_NAME_PREFIX + _bucket_name_prefix_part(rnd_len)


def random_bucket_name(prefix: str = GENERAL_BUCKET_NAME_PREFIX) -> str:
    return prefix + _bucket_name_prefix_part(BUCKET_NAME_LENGTH - len(prefix))


def authorize(b2_auth_data, api_config=DEFAULT_HTTP_API_CONFIG):
    info = InMemoryAccountInfo()
    b2_api = B2Api(info, api_config=api_config)
    realm = os.environ.get('B2_TEST_ENVIRONMENT', 'production')
    b2_api.authorize_account(realm, *b2_auth_data)
    return b2_api, info


def authorize_raw_api(raw_api):
    application_key_id = os.environ.get('B2_TEST_APPLICATION_KEY_ID')
    if application_key_id is None:
        print('B2_TEST_APPLICATION_KEY_ID is not set.', file=sys.stderr)
        sys.exit(1)

    application_key = os.environ.get('B2_TEST_APPLICATION_KEY')
    if application_key is None:
        print('B2_TEST_APPLICATION_KEY is not set.', file=sys.stderr)
        sys.exit(1)

    realm = os.environ.get('B2_TEST_ENVIRONMENT', 'production')
    realm_url = REALM_URLS.get(realm, realm)
    auth_dict = raw_api.authorize_account(realm_url, application_key_id, application_key)
    return auth_dict


def cleanup_old_buckets():
    raw_api = B2RawHTTPApi(B2Http())
    auth_dict = authorize_raw_api(raw_api)
    bucket_list_dict = raw_api.list_buckets(
        auth_dict['apiUrl'], auth_dict['authorizationToken'], auth_dict['accountId']
    )
    _cleanup_old_buckets(raw_api, auth_dict, bucket_list_dict)


def _cleanup_old_buckets(raw_api, auth_dict, bucket_list_dict):
    for bucket_dict in bucket_list_dict['buckets']:
        bucket_id = bucket_dict['bucketId']
        bucket_name = bucket_dict['bucketName']
        if _should_delete_bucket(bucket_name):
            print('cleaning up old bucket: ' + bucket_name)
            _clean_and_delete_bucket(
                raw_api,
                auth_dict['apiUrl'],
                auth_dict['authorizationToken'],
                auth_dict['accountId'],
                bucket_id,
            )


def _clean_and_delete_bucket(raw_api, api_url, account_auth_token, account_id, bucket_id):
    # Delete the files. This test never creates more than a few files,
    # so one call to list_file_versions should get them all.
    versions_dict = raw_api.list_file_versions(api_url, account_auth_token, bucket_id)
    for version_dict in versions_dict['files']:
        file_id = version_dict['fileId']
        file_name = version_dict['fileName']
        action = version_dict['action']
        if action in ['hide', 'upload']:
            print('b2_delete_file', file_name, action)
            if action == 'upload' and version_dict[
                'fileRetention'] and version_dict['fileRetention']['value']['mode'] is not None:
                raw_api.update_file_retention(
                    api_url,
                    account_auth_token,
                    file_id,
                    file_name,
                    NO_RETENTION_FILE_SETTING,
                    bypass_governance=True
                )
            raw_api.delete_file_version(api_url, account_auth_token, file_id, file_name)
        else:
            print('b2_cancel_large_file', file_name)
            raw_api.cancel_large_file(api_url, account_auth_token, file_id)

    # Delete the bucket
    print('b2_delete_bucket', bucket_id)
    raw_api.delete_bucket(api_url, account_auth_token, account_id, bucket_id)


def _should_delete_bucket(bucket_name):
    # Bucket names for this test look like: c7b22d0b0ad7-1460060364-5670
    # Other buckets should not be deleted.
    match = re.match(r'^test-raw-api-[a-f0-9]+-([0-9]+)-([0-9]+)', bucket_name)
    if match is None:
        return False

    # Is it more than an hour old?
    bucket_time = int(match.group(1))
    now = time.time()
    return bucket_time + 3600 <= now