######################################################################
#
# File: test/unit/v1/test_session.py
#
# Copyright 2019 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

import unittest.mock as mock

from .test_base import TestBase

from .deps_exception import InvalidAuthToken, Unauthorized
from .deps import ALL_CAPABILITIES
from .deps import B2Session
from .deps import MetadataDirectiveMode
from .deps import EncryptionAlgorithm, EncryptionSetting, EncryptionMode, EncryptionKey, SSE_NONE, SSE_B2_AES


SSE_C_AES = EncryptionSetting(
    mode=EncryptionMode.SSE_C,
    algorithm=EncryptionAlgorithm.AES256,
    key=EncryptionKey(secret=b'some_key', key_id='some-id'),
)
SSE_C_AES_2 = EncryptionSetting(
    mode=EncryptionMode.SSE_C,
    algorithm=EncryptionAlgorithm.AES256,
    key=EncryptionKey(secret=b'some_other_key', key_id='some-id-2'),
)


class TestB2Session(TestBase):
    def setUp(self):
        self.account_info = mock.MagicMock()
        self.account_info.get_account_auth_token.return_value = 'auth_token'

        self.api = mock.MagicMock()
        self.api.account_info = self.account_info

        self.raw_api = mock.MagicMock()
        self.raw_api.get_file_info_by_id.__name__ = 'get_file_info_by_id'
        self.raw_api.get_file_info_by_id.side_effect = ['ok']

        self.session = B2Session(self.account_info, raw_api=self.raw_api)

    def test_works_first_time(self):
        self.assertEqual('ok', self.session.get_file_info_by_id(None))

    def test_works_second_time(self):
        self.raw_api.get_file_info_by_id.side_effect = [
            InvalidAuthToken('message', 'code'),
            'ok',
        ]
        self.assertEqual('ok', self.session.get_file_info_by_id(None))

    def test_fails_second_time(self):
        self.raw_api.get_file_info_by_id.side_effect = [
            InvalidAuthToken('message', 'code'),
            InvalidAuthToken('message', 'code'),
        ]
        with self.assertRaises(InvalidAuthToken):
            self.session.get_file_info_by_id(None)

    def test_app_key_info_no_info(self):
        self.account_info.get_allowed.return_value = dict(
            bucketId=None,
            bucketName=None,
            capabilities=ALL_CAPABILITIES,
            namePrefix=None,
        )
        self.raw_api.get_file_info_by_id.side_effect = Unauthorized('no_go', 'code')
        with self.assertRaisesRegexp(
            Unauthorized, r'no_go for application key with no restrictions \(code\)'
        ):
            self.session.get_file_info_by_id(None)

    def test_app_key_info_no_info_no_message(self):
        self.account_info.get_allowed.return_value = dict(
            bucketId=None,
            bucketName=None,
            capabilities=ALL_CAPABILITIES,
            namePrefix=None,
        )
        self.raw_api.get_file_info_by_id.side_effect = Unauthorized('', 'code')
        with self.assertRaisesRegexp(
            Unauthorized, r'unauthorized for application key with no restrictions \(code\)'
        ):
            self.session.get_file_info_by_id(None)

    def test_app_key_info_all_info(self):
        self.account_info.get_allowed.return_value = dict(
            bucketId='123456',
            bucketName='my-bucket',
            capabilities=['readFiles'],
            namePrefix='prefix/',
        )
        self.raw_api.get_file_info_by_id.side_effect = Unauthorized('no_go', 'code')
        with self.assertRaisesRegexp(
            Unauthorized,
            r"no_go for application key with capabilities 'readFiles', restricted to bucket 'my-bucket', restricted to files that start with 'prefix/' \(code\)"
        ):
            self.session.get_file_info_by_id(None)

    def test_establish_sse_c_replace(self):
        file_info = object()
        content_type = object()
        metadata_directive, new_file_info, new_content_type = self.session._establish_sse_c_file_metadata(
            'id',
            MetadataDirectiveMode.REPLACE,
            file_info=file_info,
            content_type=content_type,
            destination_server_side_encryption=SSE_C_AES,
            source_server_side_encryption=SSE_C_AES_2,
            source_file_info=None,
            source_content_type=None,
        )
        self.assertEqual((MetadataDirectiveMode.REPLACE, file_info, content_type),
                         (metadata_directive, new_file_info, new_content_type))

    def test_establish_sse_c_copy_no_enc(self):
        file_info = object()
        content_type = object()
        metadata_directive, new_file_info, new_content_type = self.session._establish_sse_c_file_metadata(
            'id',
            MetadataDirectiveMode.COPY,
            file_info=file_info,
            content_type=content_type,
            destination_server_side_encryption=None,
            source_server_side_encryption=None,
            source_file_info=None,
            source_content_type=None,
        )
        self.assertEqual((MetadataDirectiveMode.COPY, file_info, content_type),
                         (metadata_directive, new_file_info, new_content_type))

    def test_establish_sse_c_copy_b2(self):
        file_info = object()
        content_type = object()
        metadata_directive, new_file_info, new_content_type = self.session._establish_sse_c_file_metadata(
            'id',
            MetadataDirectiveMode.COPY,
            file_info=file_info,
            content_type=content_type,
            destination_server_side_encryption=SSE_B2_AES,
            source_server_side_encryption=None,
            source_file_info=None,
            source_content_type=None,
        )
        self.assertEqual((MetadataDirectiveMode.COPY, file_info, content_type),
                         (metadata_directive, new_file_info, new_content_type))

    def test_establish_sse_c_copy_same_key_id(self):
        file_info = object()
        content_type = object()
        metadata_directive, new_file_info, new_content_type = self.session._establish_sse_c_file_metadata(
            'id',
            MetadataDirectiveMode.COPY,
            file_info=file_info,
            content_type=content_type,
            destination_server_side_encryption=SSE_C_AES,
            source_server_side_encryption=SSE_C_AES,
            source_file_info=None,
            source_content_type=None,
        )
        self.assertEqual((MetadataDirectiveMode.COPY, file_info, content_type),
                         (metadata_directive, new_file_info, new_content_type))

    def test_establish_sse_c_copy_sources_given(self):
        with mock.patch.object(self.session, 'get_file_info_by_id') as get_file_info:
            metadata_directive, new_file_info, new_content_type = self.session._establish_sse_c_file_metadata(
                'id',
                MetadataDirectiveMode.COPY,
                file_info=None,
                content_type=None,
                destination_server_side_encryption=SSE_C_AES,
                source_server_side_encryption=SSE_C_AES_2,
                source_file_info={'some_key': 'some_value', 'sse_c_key_id': 'some-id-2'},
                source_content_type='text/plain',
            )
            self.assertEqual((
                MetadataDirectiveMode.REPLACE, {'some_key': 'some_value', 'sse_c_key_id': 'some-id'}, 'text/plain'),
                (metadata_directive, new_file_info, new_content_type)
            )
            get_file_info.assert_not_called()

    def test_establish_sse_c_copy_sources_unknown(self):
        with mock.patch.object(self.session, 'get_file_info_by_id') as get_file_info:
            get_file_info.side_effect = lambda *a, **kw: {
               "accountId": "4aa9865d6f00",
               "bucketId": "547a2a395826655d561f0010",
               "contentLength": 1350,
               "contentSha1": "753ca1c2d0f3e8748320b38f5da057767029a036",
               "contentType": "application/octet-stream",
               "fileId": "4_z547a2a395826655d561f0010_f106d4ca95f8b5b78_d20160104_m003906_c001_v0001013_t0005",
               "fileInfo": {'sse_c_key_id': 'some-other-id', 'pre-existing': 'value'},
               "fileName": "name",
               "serverSideEncryption": {"algorithm": "AES256", "mode": "SSE-C"}
           }
            for source_file_info, source_content_type in [
                (None, None),
                ({'a': 'b'}, None),
                (None, 'text/plain'),
            ]:
                with self.subTest(source_file_info=source_file_info, source_content_type=source_content_type):
                    metadata_directive, new_file_info, new_content_type = self.session._establish_sse_c_file_metadata(
                        'id',
                        MetadataDirectiveMode.COPY,
                        file_info=None,
                        content_type=None,
                        destination_server_side_encryption=SSE_C_AES,
                        source_server_side_encryption=SSE_C_AES_2,
                        source_file_info=source_file_info,
                        source_content_type=source_content_type,
                    )
                    self.assertEqual((
                        MetadataDirectiveMode.REPLACE, {'pre-existing': 'value', 'sse_c_key_id': 'some-id'}, 'application/octet-stream'),
                        (metadata_directive, new_file_info, new_content_type)
                    )