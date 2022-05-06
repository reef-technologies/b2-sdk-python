######################################################################
#
# File: test/integration/conftest.py
#
# Copyright 2021 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

from io import BytesIO
from os import environ
from random import randint
from time import time

import pytest

from b2sdk.b2http import B2Http
from b2sdk.encryption.setting import EncryptionAlgorithm, EncryptionMode, EncryptionSetting
from b2sdk.raw_api import ALL_CAPABILITIES, REALM_URLS, B2RawHTTPApi
from b2sdk.utils import hex_sha1_of_stream

from .bucket_cleaner import _clean_and_delete_bucket


def pytest_addoption(parser):
    """Add a flag for not cleaning up old buckets"""
    parser.addoption(
        '--dont-cleanup-old-buckets',
        action="store_true",
        default=False,
    )


@pytest.fixture(scope='session')
def dont_cleanup_old_buckets(request):
    return request.config.getoption("--dont-cleanup-old-buckets")


@pytest.fixture(scope='session')
def application_key_id() -> str:
    key_id = environ.get('B2_TEST_APPLICATION_KEY_ID')
    assert key_id
    return key_id


@pytest.fixture(scope='session')
def application_key() -> str:
    key = environ.get('B2_TEST_APPLICATION_KEY')
    assert key
    return key


@pytest.fixture(scope='module')
def raw_api() -> B2RawHTTPApi:
    return B2RawHTTPApi(B2Http())


@pytest.fixture(scope='session')
def realm_url() -> str:
    realm = environ.get('B2_TEST_ENVIRONMENT', 'production')
    return REALM_URLS.get(realm, realm)


@pytest.fixture(scope='module')
def auth_dict(raw_api, application_key, application_key_id, realm_url) -> dict:
    result = raw_api.authorize_account(realm_url, application_key_id, application_key)

    missing_capabilities = set(ALL_CAPABILITIES) - \
        {'readBuckets', 'listAllBucketNames'} - set(result['allowed']['capabilities'])
    assert not missing_capabilities, \
        f'Seems like a non-full key. Missing capabilities: {missing_capabilities}'

    return result


@pytest.fixture(scope='module')
def account_id(auth_dict) -> str:
    return auth_dict['accountId']


@pytest.fixture(scope='module')
def account_auth_token(auth_dict) -> str:
    return auth_dict['authorizationToken']


@pytest.fixture(scope='module')
def api_url(auth_dict) -> str:
    return auth_dict['apiUrl']


@pytest.fixture(scope='module')
def download_url(auth_dict) -> str:
    return auth_dict['downloadUrl']


@pytest.fixture(scope='module')
def bucket_dict(raw_api, api_url, account_auth_token, account_id) -> dict:
    # include the account ID in the bucket name to be
    # sure it doesn't collide with bucket names from
    # other accounts.
    bucket_name = f'test-raw-api-{account_id}-{time():.0f}-{randint(1000, 9999)}'

    bucket = raw_api.create_bucket(
        api_url,
        account_auth_token,
        account_id,
        bucket_name,
        'allPublic',
        is_file_lock_enabled=True,
    )
    yield bucket

    _clean_and_delete_bucket(
        raw_api,
        api_url,
        account_auth_token,
        account_id,
        bucket['bucketId'],
    )


@pytest.fixture(scope='module')
def bucket_id(bucket_dict) -> str:
    return bucket_dict['bucketId']


@pytest.fixture(scope='module')
def bucket_name(bucket_dict) -> str:
    return bucket_dict['bucketName']


@pytest.fixture(scope='module')
def upload_url_dict(raw_api, api_url, account_auth_token, bucket_id) -> dict:
    return raw_api.get_upload_url(api_url, account_auth_token, bucket_id)


@pytest.fixture(scope='module')
def file_name() -> str:
    return 'test.txt'


@pytest.fixture(scope='module')
def file_contents() -> bytes:
    return b'hello world'


@pytest.fixture(scope='session')
def sse_none() -> EncryptionSetting:
    return EncryptionSetting(mode=EncryptionMode.NONE)


@pytest.fixture(scope='session')
def sse_b2_aes() -> EncryptionSetting:
    return EncryptionSetting(
        mode=EncryptionMode.SSE_B2,
        algorithm=EncryptionAlgorithm.AES256,
    )


@pytest.fixture(scope='module')
def file_dict(raw_api, upload_url_dict, file_name, file_contents, sse_b2_aes) -> dict:
    return raw_api.upload_file(
        upload_url_dict['uploadUrl'],
        upload_url_dict['authorizationToken'],
        file_name,
        len(file_contents),
        'text/plain',
        hex_sha1_of_stream(BytesIO(file_contents), len(file_contents)),
        {'color': 'blue'},
        BytesIO(file_contents),
        server_side_encryption=sse_b2_aes,
    )


@pytest.fixture(scope='module')
def file_id(file_dict) -> str:
    return file_dict['fileId']


@pytest.fixture(scope='module')
def download_auth_dict(raw_api, api_url, account_auth_token, bucket_id, file_name) -> dict:
    return raw_api.get_download_authorization(
        api_url, account_auth_token, bucket_id, file_name[:-2], 12345,
    )


@pytest.fixture(scope='module')
def download_auth_token(download_auth_dict) -> str:
    return download_auth_dict['authorizationToken']
