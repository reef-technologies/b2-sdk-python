######################################################################
#
# File: test/integration/test_raw_expect_100.py
#
# Copyright 2023 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
import http.client
import io
import os
import random
import secrets
import time

import pytest

from b2sdk.b2http import B2Http
from b2sdk.encryption.setting import EncryptionSetting
from b2sdk.encryption.types import EncryptionAlgorithm, EncryptionMode
from b2sdk.exception import InvalidAuthToken
from b2sdk.raw_api import REALM_URLS, B2RawHTTPApi
from b2sdk.utils import hex_sha1_of_stream

from .fixtures import b2_auth_data  # noqa


@pytest.fixture
def expect_100_setup(b2_auth_data, monkeypatch):  # noqa
    application_key_id, application_key = b2_auth_data
    raw_api = B2RawHTTPApi(B2Http())
    realm = os.environ.get('B2_TEST_ENVIRONMENT', 'production')
    realm_url = REALM_URLS.get(realm, realm)
    auth_dict = raw_api.authorize_account(realm_url, application_key_id, application_key)

    account_id = auth_dict['accountId']
    account_auth_token = auth_dict['authorizationToken']
    api_url = auth_dict['apiUrl']

    sse_b2_aes = EncryptionSetting(
        mode=EncryptionMode.SSE_B2,
        algorithm=EncryptionAlgorithm.AES256,
    )

    bucket_name = 'test-raw-api-%s-%d-%d' % (
        account_id, int(time.time()), random.randint(1000, 9999)
    )

    bucket_dict = raw_api.create_bucket(
        api_url,
        account_auth_token,
        account_id,
        bucket_name,
        'allPublic',
        is_file_lock_enabled=True,
    )

    upload_url_dict = raw_api.get_upload_url(api_url, account_auth_token, bucket_dict['bucketId'])
    upload_url = upload_url_dict['uploadUrl']
    upload_auth_token = upload_url_dict['authorizationToken']

    orig_send = http.client.HTTPConnection.send
    sent_data = bytearray()

    def patched_send(self, data):
        sent_data.extend(data)
        return orig_send(self, data)

    monkeypatch.setattr(
        http.client.HTTPConnection,
        "send",
        patched_send,
    )

    file_name = 'test-100-continue.txt'
    file_contents = secrets.token_bytes()
    file_length = len(file_contents)
    file_sha1 = hex_sha1_of_stream(io.BytesIO(file_contents), file_length)

    return {
        "raw_api": raw_api,
        "upload_url": upload_url,
        "upload_auth_token": upload_auth_token,
        "sse_b2_aes": sse_b2_aes,
        "sent_data": sent_data,
        "file_name": file_name,
        "file_contents": file_contents,
        "file_length": file_length,
        "file_sha1": file_sha1,
    }


@pytest.fixture(autouse=True)
def rest_sent_data(expect_100_setup):
    expect_100_setup["sent_data"].clear()


def test_expect_100_non_100_response(expect_100_setup):
    raw_api = expect_100_setup["raw_api"]
    data = io.BytesIO(expect_100_setup["file_contents"])
    with pytest.raises(InvalidAuthToken):
        raw_api.upload_file(
            expect_100_setup["upload_url"],
            expect_100_setup["upload_auth_token"] + 'wrong token',
            expect_100_setup["file_name"],
            expect_100_setup["file_contents"],
            'text/plain',
            expect_100_setup["file_sha1"],
            {'color': 'blue'},
            data,
            server_side_encryption=expect_100_setup["sse_b2_aes"],
        )
    assert expect_100_setup["file_contents"] not in expect_100_setup["sent_data"]


def test_expect_100_timeout(expect_100_setup):
    raw_api = expect_100_setup["raw_api"]
    data = io.BytesIO(expect_100_setup["file_contents"])
    raw_api.upload_file(
        expect_100_setup["upload_url"],
        expect_100_setup["upload_auth_token"],
        expect_100_setup["file_name"],
        expect_100_setup["file_contents"],
        'text/plain',
        expect_100_setup["file_sha1"],
        {'color': 'blue'},
        data,
        server_side_encryption=expect_100_setup["sse_b2_aes"],
        expect_100_timeout=0,
    )
    assert expect_100_setup["file_contents"] in expect_100_setup["sent_data"]


def test_expect_100_disabled(expect_100_setup):
    raw_api = expect_100_setup["raw_api"]
    data = io.BytesIO(expect_100_setup["file_contents"])
    raw_api.upload_file(
        expect_100_setup["upload_url"],
        expect_100_setup["upload_auth_token"],
        expect_100_setup["file_name"],
        expect_100_setup["file_contents"],
        'text/plain',
        expect_100_setup["file_sha1"],
        {'color': 'blue'},
        data,
        server_side_encryption=expect_100_setup["sse_b2_aes"],
        expect_100_continue=False,
    )

    assert expect_100_setup["file_contents"] in expect_100_setup["sent_data"]
