######################################################################
#
# File: test/integration/test_upload.py
#
# Copyright 2021 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
from __future__ import annotations

import io

from b2sdk._internal.b2http import B2Http
from b2sdk._internal.encryption.setting import EncryptionKey, EncryptionSetting
from b2sdk._internal.encryption.types import EncryptionAlgorithm, EncryptionMode
from b2sdk.v2 import B2RawHTTPApi

from .base import IntegrationTestBase
from .test_raw_api import authorize_raw_api


class TestUnboundStreamUpload(IntegrationTestBase):
    test_prefix = "test-unbound-upload"

    def assert_data_uploaded_via_stream(self, data: bytes, part_size: int | None = None):
        bucket = self.single_bucket.bucket
        stream = io.BytesIO(data)
        file_name = self.single_bucket.get_path_for_current_test('unbound_stream')

        bucket.upload_unbound_stream(stream, file_name, recommended_upload_part_size=part_size)

        downloaded_data = io.BytesIO()
        bucket.download_file_by_name(file_name).save(downloaded_data)

        assert downloaded_data.getvalue() == data

    def test_streamed_small_buffer(self):
        # 20kb
        data = b'a small data content' * 1024
        self.assert_data_uploaded_via_stream(data)

    def test_streamed_large_buffer_small_part_size(self):
        # 10mb
        data = b'a large data content' * 512 * 1024
        # 5mb, the smallest allowed part size
        self.assert_data_uploaded_via_stream(data, part_size=5 * 1024 * 1024)


class TestUploadLargeFile(IntegrationTestBase):
    test_prefix = "test-upload-large"

    def test_ssec_key_id(self):
        sse_c = EncryptionSetting(
            mode=EncryptionMode.SSE_C,
            algorithm=EncryptionAlgorithm.AES256,
            key=EncryptionKey(secret=b'********************************', key_id='some-id'),
        )

        raw_api = B2RawHTTPApi(B2Http())

        auth_dict = authorize_raw_api(raw_api)
        account_auth_token = auth_dict['authorizationToken']
        api_url = auth_dict['apiUrl']

        large_info = raw_api.start_large_file(
            api_url,
            account_auth_token,
            self.single_bucket.bucket_id,
            self.single_bucket.get_path_for_current_test('test_largefile_sse_c.txt'),
            'text/plain',
            None,
            server_side_encryption=sse_c,
        )

        assert large_info['fileInfo'] == {
            'sse_c_key_id': sse_c.key.key_id,
        }
        assert large_info['serverSideEncryption'] == {
            'algorithm': 'AES256',
            'customerKeyMd5': 'SaaDheEjzuynJH8eW6AEpQ==',
            'mode': 'SSE-C',
        }
