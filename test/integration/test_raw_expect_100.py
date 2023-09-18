######################################################################
#
# File: test/integration/test_raw_expect_100.py
#
# Copyright 2023 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
import io
import secrets
from unittest import mock

import pytest
from urllib3.util import wait_for_read

from b2sdk.encryption.setting import EncryptionSetting
from b2sdk.encryption.types import EncryptionAlgorithm, EncryptionMode
from b2sdk.exception import InvalidAuthToken
from b2sdk.utils import hex_sha1_of_stream


def test_expect_100_non_100_response(raw_api, upload_url_dict, http_sent_data):
    file_name = 'test-100-continue.txt'
    file_contents = secrets.token_bytes()
    file_length = len(file_contents)
    file_sha1 = hex_sha1_of_stream(io.BytesIO(file_contents), file_length)
    data = io.BytesIO(file_contents)

    with pytest.raises(InvalidAuthToken), mock.patch(
        "urllib3.util.wait_for_read", side_effect=wait_for_read
    ) as wait_mock:
        raw_api.upload_file(
            upload_url_dict['uploadUrl'],
            upload_url_dict['authorizationToken'] + 'wrong token',
            file_name,
            file_contents,
            'text/plain',
            file_sha1,
            {'color': 'blue'},
            data,
            server_side_encryption=EncryptionSetting(
                mode=EncryptionMode.SSE_B2,
                algorithm=EncryptionAlgorithm.AES256,
            ),
        )
    assert file_contents not in http_sent_data
    assert wait_mock.call_count == 1


def test_expect_100_timeout(raw_api, upload_url_dict, http_sent_data):
    file_name = 'test-100-continue.txt'
    file_contents = secrets.token_bytes()
    file_length = len(file_contents)
    file_sha1 = hex_sha1_of_stream(io.BytesIO(file_contents), file_length)
    data = io.BytesIO(file_contents)
    timeout = 0

    with mock.patch("urllib3.util.wait_for_read", side_effect=wait_for_read) as wait_mock:
        raw_api.upload_file(
            upload_url_dict['uploadUrl'],
            upload_url_dict['authorizationToken'],
            file_name,
            file_contents,
            'text/plain',
            file_sha1,
            {'color': 'blue'},
            data,
            server_side_encryption=EncryptionSetting(
                mode=EncryptionMode.SSE_B2,
                algorithm=EncryptionAlgorithm.AES256,
            ),
            expect_100_timeout=timeout,
        )
    assert file_contents in http_sent_data
    assert wait_mock.call_count == 1
    args, _ = wait_mock.call_args
    assert args[1] == timeout


def test_expect_100_disabled(raw_api, upload_url_dict, http_sent_data):
    file_name = 'test-100-continue.txt'
    file_contents = secrets.token_bytes()
    file_length = len(file_contents)
    file_sha1 = hex_sha1_of_stream(io.BytesIO(file_contents), file_length)
    data = io.BytesIO(file_contents)

    with mock.patch("urllib3.util.wait_for_read", side_effect=wait_for_read) as wait_mock:
        raw_api.upload_file(
            upload_url_dict['uploadUrl'],
            upload_url_dict['authorizationToken'],
            file_name,
            file_contents,
            'text/plain',
            file_sha1,
            {'color': 'blue'},
            data,
            server_side_encryption=EncryptionSetting(
                mode=EncryptionMode.SSE_B2,
                algorithm=EncryptionAlgorithm.AES256,
            ),
            expect_100_continue=False,
        )
    assert file_contents in http_sent_data
    assert wait_mock.call_count == 0


def test_expect_100_data_sent_after_wait(raw_api, upload_url_dict, http_sent_data):
    file_name = 'test-100-continue.txt'
    file_contents = secrets.token_bytes()
    file_length = len(file_contents)
    file_sha1 = hex_sha1_of_stream(io.BytesIO(file_contents), file_length)
    data = io.BytesIO(file_contents)

    def patched_wait(*args, **kwargs):
        # verify that, data is not sent before waiting
        assert file_contents not in http_sent_data, "data sent before waiting for 100 Continue"
        return wait_for_read(*args, **kwargs)

    with mock.patch("urllib3.util.wait_for_read", side_effect=patched_wait) as wait_mock:
        raw_api.upload_file(
            upload_url_dict['uploadUrl'],
            upload_url_dict['authorizationToken'],
            file_name,
            file_contents,
            'text/plain',
            file_sha1,
            {'color': 'blue'},
            data,
            server_side_encryption=EncryptionSetting(
                mode=EncryptionMode.SSE_B2,
                algorithm=EncryptionAlgorithm.AES256,
            ),
        )
    assert file_contents in http_sent_data
    assert wait_mock.call_count == 1
