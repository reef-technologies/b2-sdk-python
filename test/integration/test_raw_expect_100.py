import io
import secrets

import pytest

from b2sdk.encryption.setting import EncryptionSetting
from b2sdk.encryption.types import EncryptionMode, EncryptionAlgorithm
from b2sdk.exception import InvalidAuthToken
from b2sdk.utils import hex_sha1_of_stream


def test_expect_100_non_100_response(raw_api, upload_url_dict, http_sent_data):
    file_name = 'test-100-continue.txt'
    file_contents = secrets.token_bytes()
    file_length = len(file_contents)
    file_sha1 = hex_sha1_of_stream(io.BytesIO(file_contents), file_length)
    data = io.BytesIO(file_contents)

    with pytest.raises(InvalidAuthToken):
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


def test_expect_100_timeout(raw_api, upload_url_dict, http_sent_data):
    file_name = 'test-100-continue.txt'
    file_contents = secrets.token_bytes()
    file_length = len(file_contents)
    file_sha1 = hex_sha1_of_stream(io.BytesIO(file_contents), file_length)
    data = io.BytesIO(file_contents)

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
        expect_100_timeout=0,
    )
    assert file_contents in http_sent_data


def test_expect_100_disabled(raw_api, upload_url_dict, http_sent_data):
    file_name = 'test-100-continue.txt'
    file_contents = secrets.token_bytes()
    file_length = len(file_contents)
    file_sha1 = hex_sha1_of_stream(io.BytesIO(file_contents), file_length)
    data = io.BytesIO(file_contents)

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
