######################################################################
#
# File: test/integration/test_raw_api.py
#
# Copyright 2021 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
import io
import os
import random
import re
import time
from test.integration.base import RawSingleBucket
from test.integration.helpers import raw_delete_file

import pytest

from b2sdk._internal.b2http import B2Http
from b2sdk._internal.encryption.setting import (
    EncryptionAlgorithm,
    EncryptionMode,
    EncryptionSetting,
)
from b2sdk._internal.exception import DisablingFileLockNotSupported, Unauthorized
from b2sdk._internal.file_lock import (
    BucketRetentionSetting,
    FileRetentionSetting,
    RetentionMode,
    RetentionPeriod,
)
from b2sdk._internal.raw_api import (
    ALL_CAPABILITIES,
    REALM_URLS,
    B2RawHTTPApi,
)
from b2sdk._internal.replication.setting import ReplicationConfiguration, ReplicationRule
from b2sdk._internal.replication.types import ReplicationStatus
from b2sdk._internal.utils import hex_sha1_of_stream

#
"""
Exercise the code in B2RawHTTPApi by making each call once, just
to make sure the parameters are passed in, and the result is
passed back.

The goal is to be a complete test of B2RawHTTPApi, so the tests for
the rest of the code can use the simulator.
"""


def cleanup_old_buckets():
    raw_api = B2RawHTTPApi(B2Http())
    auth_dict = authorize_raw_api(raw_api)
    bucket_list_dict = raw_api.list_buckets(
        auth_dict['apiUrl'], auth_dict['authorizationToken'], auth_dict['accountId']
    )
    _cleanup_old_buckets(raw_api, auth_dict, bucket_list_dict)


def authorize_raw_api(raw_api):
    application_key_id = os.environ.get('B2_TEST_APPLICATION_KEY_ID')
    application_key = os.environ.get('B2_TEST_APPLICATION_KEY')

    if application_key_id is None:
        pytest.fail('B2_TEST_APPLICATION_KEY_ID is not set.')

    if application_key is None:
        pytest.fail('B2_TEST_APPLICATION_KEY is not set.')

    realm = os.environ.get('B2_TEST_ENVIRONMENT', 'production')
    realm_url = REALM_URLS.get(realm, realm)
    auth_dict = raw_api.authorize_account(realm_url, application_key_id, application_key)
    return auth_dict


class RawApiIntegrationTestBase:
    raw_api: B2RawHTTPApi
    auth_dict: dict
    api_url: str
    account_auth_token: str
    account_id: str
    sse_b2_aes: EncryptionSetting

    @classmethod
    def setup_class(cls):
        # very verbose http debug:
        # import http.client; http.client.HTTPConnection.debuglevel = 1
        cls.raw_api = B2RawHTTPApi(B2Http())
        cls.sse_b2_aes = EncryptionSetting(
            mode=EncryptionMode.SSE_B2,
            algorithm=EncryptionAlgorithm.AES256,
        )

        cls.authorize_account()

    @classmethod
    def authorize_account(cls):
        print("b2_authorize_account")
        cls.auth_dict = authorize_raw_api(cls.raw_api)

        missing_capabilities = set(ALL_CAPABILITIES) - {'readBuckets', 'listAllBucketNames'} - set(
            cls.auth_dict['allowed']['capabilities']
        )
        assert not missing_capabilities, 'it appears that the raw_api integration test is being run with a non-full key. Missing capabilities: {}'.format(
            missing_capabilities,
        )

        cls.account_id = cls.auth_dict['accountId']
        cls.account_auth_token = cls.auth_dict['authorizationToken']
        cls.api_url = cls.auth_dict['apiUrl']
        cls.download_url = cls.auth_dict['downloadUrl']


@pytest.fixture(scope="class")
def check_dont_cleanup_old_buckets(request):
    request.cls.dont_cleanup_old_buckets = request.config.getoption("--dont-cleanup-old-buckets")


@pytest.mark.usefixtures("check_dont_cleanup_old_buckets")
class TestRawApiNonBucketTests(RawApiIntegrationTestBase):
    single_bucket: RawSingleBucket
    file_id: str
    file_name: str
    file_name_large: str
    file_contents: bytes
    file_info: dict

    upload_url: str
    upload_auth_token: str

    dont_cleanup_old_buckets: bool

    @classmethod
    def setup_class(cls):
        super().setup_class()

        # bucket_prefix needs to be changed because bucket settings collide with test-singlebucket
        cls.single_bucket = RawSingleBucket(
            cls.raw_api, cls.auth_dict, "test-raw-api", bucket_infix="sb-raw"
        )

        cls.file_name = cls.single_bucket.get_path_for_current_test('test.txt')
        cls.file_name_large = cls.single_bucket.get_path_for_current_test("test_large.txt")
        cls.copy_file_name = cls.single_bucket.get_path_for_current_test("test_copy.txt")

        cls.file_contents = b'Hello world'
        cls.file_info = {"color": "red"}

        cls.bucket_list_dict = None

        # tests below create state for other tests, so they must be run here for other tests
        cls.b2_get_download_authorization()
        cls.test_file_upload()

    @classmethod
    def teardown_class(cls):
        cls.single_bucket.clean_test_files(cls.dont_cleanup_old_buckets)

    @classmethod
    def b2_get_download_authorization(cls):
        print("b2_get_download_authorization")
        download_auth = cls.raw_api.get_download_authorization(
            cls.api_url, cls.account_auth_token, cls.single_bucket.bucket_id, cls.file_name[:-2],
            12345
        )
        cls.download_auth_token = download_auth['authorizationToken']

    @classmethod
    def test_file_upload(cls):
        print("b2_get_upload_url")
        upload_url_dict = cls.raw_api.get_upload_url(
            cls.api_url, cls.account_auth_token, cls.single_bucket.bucket_id
        )
        upload_url = upload_url_dict['uploadUrl']
        upload_auth_token = upload_url_dict['authorizationToken']

        print("b2_test_upload")

        file_sha1 = hex_sha1_of_stream(io.BytesIO(cls.file_contents), len(cls.file_contents))
        file_dict = cls.raw_api.upload_file(
            upload_url,
            upload_auth_token,
            cls.file_name,
            len(cls.file_contents),
            'text/plain',
            file_sha1,
            {
                'color': 'blue',
                'b2-cache-control': 'private, max-age=2222'
            },
            io.BytesIO(cls.file_contents),
            server_side_encryption=cls.sse_b2_aes,
            # custom_upload_timestamp=12345,
            file_retention=FileRetentionSetting(
                RetentionMode.GOVERNANCE,
                int(time.time() + 100) * 1000,
            )
        )
        cls.file_id = file_dict['fileId']

    def test_b2_large_file(self):
        """
        Start large file, get upload part url, upload part, copy part from file to large_file,
        list parts, list unfinished large files, finish large file
        """
        print("b2_start_large_file")
        large_info = self.raw_api.start_large_file(
            self.api_url,
            self.account_auth_token,
            self.single_bucket.bucket_id,
            self.file_name_large,
            'text/plain',
            self.file_info,
            server_side_encryption=self.sse_b2_aes,
        )
        large_file_id = large_info['fileId']

        print("b2_get_upload_part_url")
        upload_part_dict = self.raw_api.get_upload_part_url(
            self.api_url, self.account_auth_token, large_file_id
        )
        upload_part_url = upload_part_dict['uploadUrl']
        upload_path_auth = upload_part_dict['authorizationToken']

        print("b2_upload_part")
        part_contents = b'hello part'
        self.part_sha1 = hex_sha1_of_stream(io.BytesIO(part_contents), len(part_contents))
        self.raw_api.upload_part(
            upload_part_url, upload_path_auth, 1, len(part_contents), self.part_sha1,
            io.BytesIO(part_contents)
        )

        print("b2_copy_part")
        self.raw_api.copy_part(
            self.api_url, self.account_auth_token, self.file_id, large_file_id, 2, (0, 5)
        )

        print("b2_list_parts")
        parts_response = self.raw_api.list_parts(
            self.api_url, self.account_auth_token, large_file_id, 1, 100
        )
        assert [1, 2] == [part['partNumber'] for part in parts_response['parts']]

        print("b2_list_unfinished_large_file")
        unfinished_list = self.raw_api.list_unfinished_large_files(
            self.api_url, self.account_auth_token, self.single_bucket.bucket_id
        )

        unfinished_files_list = list(self.single_bucket.iter_test_files(unfinished_list['files']))

        assert [self.file_name_large] == [f_dict['fileName'] for f_dict in unfinished_files_list]
        assert self.file_info == unfinished_files_list[0]['fileInfo']

        print("b2_finish_large_file")
        try:
            self.raw_api.finish_large_file(
                self.api_url, self.account_auth_token, large_file_id, [self.part_sha1]
            )
            raise Exception('finish should have failed')
        except Exception as e:
            assert 'large files must have at least 2 parts' in str(e)
        # TODO: make another attempt to finish but this time successfully

    def test_b2_list_file_versions(self):
        list_versions_dict = self.raw_api.list_file_versions(
            self.api_url, self.account_auth_token, self.single_bucket.bucket_id
        )
        files = list(self.single_bucket.iter_test_files(list_versions_dict['files']))
        assert len(files) == 2

        for file in files:
            if file['fileName'] == self.file_name:
                assert file['fileInfo']['b2-cache-control'] == 'private, max-age=2222'
            elif file['fileName'] == self.file_name_large:
                assert file['fileInfo'][next(iter(self.file_info.keys()))] == next(
                    iter(self.file_info.values())
                )
            else:
                pytest.fail("unexpected file in listing")

    def test_b2_download_file_by_id_with_auth(self):
        url = self.raw_api.get_download_url_by_id(self.download_url, self.file_id)
        with self.raw_api.download_file_from_url(self.account_auth_token, url) as response:
            data = next(response.iter_content(chunk_size=len(self.file_contents)))
            assert data == self.file_contents, data

    def test_b2_download_file_by_id_no_auth(self):
        url = self.raw_api.get_download_url_by_id(self.download_url, self.file_id)
        with self.raw_api.download_file_from_url(None, url) as response:
            data = next(response.iter_content(chunk_size=len(self.file_contents)))
            assert data == self.file_contents, data

    def test_b2_download_file_by_name_with_auth(self):
        url = self.raw_api.get_download_url_by_name(
            self.download_url, self.single_bucket.bucket_name, self.file_name
        )
        with self.raw_api.download_file_from_url(self.account_auth_token, url) as response:
            data = next(response.iter_content(chunk_size=len(self.file_contents)))
            assert data == self.file_contents, data

    def test_b2_download_file_by_name_no_auth(self):
        url = self.raw_api.get_download_url_by_name(
            self.download_url, self.single_bucket.bucket_name, self.file_name
        )
        with self.raw_api.download_file_from_url(None, url) as response:
            data = next(response.iter_content(chunk_size=len(self.file_contents)))
            assert data == self.file_contents, data

    def test_b2_download_file_by_name_dl_auth(self):
        url = self.raw_api.get_download_url_by_name(
            self.download_url, self.single_bucket.bucket_name, self.file_name
        )
        with self.raw_api.download_file_from_url(self.download_auth_token, url) as response:
            data = next(response.iter_content(chunk_size=len(self.file_contents)))
            assert data == self.file_contents, data

    def test_b2_list_file_names(self):
        list_names_dict = self.raw_api.list_file_names(
            self.api_url, self.account_auth_token, self.single_bucket.bucket_id
        )
        assert [self.file_name] == [
            f_dict['fileName']
            for f_dict in self.single_bucket.iter_test_files(list_names_dict['files'])
        ]

    def test_b2_list_file_names_start_count(self):
        list_names_dict = self.raw_api.list_file_names(
            self.api_url,
            self.account_auth_token,
            self.single_bucket.bucket_id,
            start_file_name=self.file_name,
            max_file_count=5
        )
        assert [self.file_name] == [
            f_dict['fileName']
            for f_dict in self.single_bucket.iter_test_files(list_names_dict['files'])
        ]

    def test_b2_copy_file(self):
        self.raw_api.copy_file(
            self.api_url, self.account_auth_token, self.file_id, self.copy_file_name
        )

    def test_b2_get_file_info_by_id(self):
        file_info_dict = self.raw_api.get_file_info_by_id(
            self.api_url, self.account_auth_token, self.file_id
        )
        assert file_info_dict['fileName'] == self.file_name

    def test_b2_get_file_info_by_name_no_auth(self):
        info_headers = self.raw_api.get_file_info_by_name(
            self.download_url, None, self.single_bucket.bucket_name, self.file_name
        )
        assert info_headers['x-bz-file-id'] == self.file_id

    def test_b2_get_file_info_by_name_with_auth(self):
        info_headers = self.raw_api.get_file_info_by_name(
            self.download_url, self.account_auth_token, self.single_bucket.bucket_name,
            self.file_name
        )
        assert info_headers['x-bz-file-id'] == self.file_id

    def test_b2_get_file_info_by_name_dl_auth(self):
        info_headers = self.raw_api.get_file_info_by_name(
            self.download_url, self.download_auth_token, self.single_bucket.bucket_name,
            self.file_name
        )
        assert info_headers['x-bz-file-id'] == self.file_id

    def test_b2_hide_file(self):
        self.raw_api.hide_file(
            self.api_url, self.account_auth_token, self.single_bucket.bucket_id, self.file_name
        )

    def test_b2_delete_file_version(self, dont_cleanup_old_buckets):
        with pytest.raises(Unauthorized):
            self.raw_api.delete_file_version(
                self.api_url, self.account_auth_token, self.file_id, self.file_name
            )
        self.raw_api.delete_file_version(
            self.api_url, self.account_auth_token, self.file_id, self.file_name, True
        )


@pytest.mark.usefixtures('check_dont_cleanup_old_buckets')
class TestRawApiBucketTests(RawApiIntegrationTestBase):
    bucket_name: str
    bucket_list_dict: dict
    bucket_id: str
    dont_cleanup_old_buckets: bool

    @classmethod
    def setup_class(cls):
        super().setup_class()

        # tests below create state for other tests, so they cannot be run as unit tests
        cls.b2_create_bucket()
        cls.b2_list_buckets()

    @classmethod
    def b2_create_bucket(cls):
        print("b2_create_bucket")
        cls.bucket_name = 'test-raw-api-%s-%d-%d' % (
            cls.account_id, int(time.time()), random.randint(1000, 9999)
        )  # include account_id to make sure no collisions with other accounts occur

        bucket_dict = cls.raw_api.create_bucket(
            cls.api_url,
            cls.account_auth_token,
            cls.account_id,
            cls.bucket_name,
            'allPublic',
            is_file_lock_enabled=True,
        )
        cls.bucket_id = bucket_dict['bucketId']
        cls.first_bucket_revision = bucket_dict['revision']

    @classmethod
    def b2_list_buckets(cls):
        cls.bucket_list_dict = cls.raw_api.list_buckets(
            cls.api_url, cls.account_auth_token, cls.account_id
        )

    @classmethod
    def teardown_class(cls):
        # Clean up this test.
        _clean_and_delete_bucket(
            cls.raw_api, cls.api_url, cls.account_auth_token, cls.account_id, cls.bucket_id
        )

        if cls.dont_cleanup_old_buckets:
            return

        # Clean up from old tests. Empty and delete any buckets more than an hour old.
        _cleanup_old_buckets(
            cls.raw_api, cls.auth_dict, cls.bucket_list_dict or
            cls.raw_api.list_buckets(cls.api_url, cls.account_auth_token, cls.account_id)
        )  # or because bucket_list_dict is set by other test which may not have been run

    def test_b2_list_keys(self):
        print('b2_list_keys')
        self.raw_api.list_keys(self.api_url, self.account_auth_token, self.account_id, 10)

    def test_b2_create_and_delete_key(self):
        print("b2_create_key")
        self.key_dict = self.raw_api.create_key(
            self.api_url,
            self.account_auth_token,
            self.account_id,
            ['readFiles'],
            'testKey',
            None,
            None,
            None,
        )

        print("b2_delete_key")
        self.raw_api.delete_key(
            self.api_url, self.account_auth_token, self.key_dict['applicationKeyId']
        )

    def test_b2_replication(self):
        # 1) create source key (read permissions)
        replication_source_key_dict = self.raw_api.create_key(
            self.api_url,
            self.account_auth_token,
            self.account_id,
            [
                'listBuckets',
                'listFiles',
                'readFiles',
                'writeFiles',  # Pawel @ 2022-06-21: adding this to make tests pass with a weird server validator
            ],
            'testReplicationSourceKey',
            None,
            None,
            None,
        )
        replication_source_key = replication_source_key_dict['applicationKeyId']

        # 2) create source bucket with replication to destination - existing bucket
        try:
            # in order to test replication, we need to create a second bucket
            replication_source_bucket_name = 'test-raw-api-%s-%d-%d' % (
                self.account_id, int(time.time()), random.randint(1000, 9999)
            )
            replication_source_bucket_dict = self.raw_api.create_bucket(
                self.api_url,
                self.account_auth_token,
                self.account_id,
                replication_source_bucket_name,
                'allPublic',
                is_file_lock_enabled=True,
                replication=ReplicationConfiguration(
                    rules=[
                        ReplicationRule(
                            destination_bucket_id=self.bucket_id,
                            include_existing_files=True,
                            name='test-rule',
                        ),
                    ],
                    source_key_id=replication_source_key,
                ),
            )
            assert 'replicationConfiguration' in replication_source_bucket_dict
            assert replication_source_bucket_dict['replicationConfiguration'] == {
                'isClientAuthorizedToRead': True,
                'value':
                    {
                        "asReplicationSource":
                            {
                                "replicationRules":
                                    [
                                        {
                                            "destinationBucketId": self.bucket_id,
                                            "fileNamePrefix": "",
                                            "includeExistingFiles": True,
                                            "isEnabled": True,
                                            "priority": 128,
                                            "replicationRuleName": "test-rule"
                                        },
                                    ],
                                "sourceApplicationKeyId": replication_source_key,
                            },
                        "asReplicationDestination": None,
                    },
            }

            # 3) upload test file and check replication status
            upload_url_dict = self.raw_api.get_upload_url(
                self.api_url,
                self.account_auth_token,
                replication_source_bucket_dict['bucketId'],
            )
            file_contents = b'hello world'
            file_dict = self.raw_api.upload_file(
                upload_url_dict['uploadUrl'],
                upload_url_dict['authorizationToken'],
                'test.txt',
                len(file_contents),
                'text/plain',
                hex_sha1_of_stream(io.BytesIO(file_contents), len(file_contents)),
                {'color': 'blue'},
                io.BytesIO(file_contents),
            )

            assert ReplicationStatus[file_dict['replicationStatus'].upper()
                                    ] == ReplicationStatus.PENDING

        finally:
            self.raw_api.delete_key(self.api_url, self.account_auth_token, replication_source_key)

        # 4) create destination key (write permissions)
        replication_destination_key_dict = self.raw_api.create_key(
            self.api_url,
            self.account_auth_token,
            self.account_id,
            ['listBuckets', 'listFiles', 'writeFiles'],
            'testReplicationDestinationKey',
            None,
            None,
            None,
        )
        replication_destination_key = replication_destination_key_dict['applicationKeyId']

        # 5) update destination bucket to receive updates
        try:
            bucket_dict = self.raw_api.update_bucket(
                self.api_url,
                self.account_auth_token,
                self.account_id,
                self.bucket_id,
                'allPublic',
                replication=ReplicationConfiguration(
                    source_to_destination_key_mapping={
                        replication_source_key: replication_destination_key,
                    },
                ),
            )
            assert bucket_dict['replicationConfiguration'] == {
                'isClientAuthorizedToRead': True,
                'value':
                    {
                        'asReplicationDestination':
                            {
                                'sourceToDestinationKeyMapping':
                                    {
                                        replication_source_key: replication_destination_key,
                                    },
                            },
                        'asReplicationSource': None,
                    },
            }
        finally:
            self.raw_api.delete_key(
                self.api_url,
                self.account_auth_token,
                replication_destination_key_dict['applicationKeyId'],
            )

        # 6) cleanup: disable replication for destination and remove source
        bucket_dict = self.raw_api.update_bucket(
            self.api_url,
            self.account_auth_token,
            self.account_id,
            self.bucket_id,
            'allPublic',
            replication=ReplicationConfiguration(),
        )
        assert bucket_dict['replicationConfiguration'] == {
            'isClientAuthorizedToRead': True,
            'value': None,
        }

        _clean_and_delete_bucket(
            self.raw_api,
            self.api_url,
            self.account_auth_token,
            self.account_id,
            replication_source_bucket_dict['bucketId'],
        )

    def test_b2_update_bucket(self):
        sse_none = EncryptionSetting(mode=EncryptionMode.NONE)
        for encryption_setting, default_retention in [
            (
                sse_none,
                BucketRetentionSetting(
                    mode=RetentionMode.GOVERNANCE, period=RetentionPeriod(days=1)
                )
            ),
            (self.sse_b2_aes, None),
            (self.sse_b2_aes, BucketRetentionSetting(RetentionMode.NONE)),
        ]:
            self.raw_api.update_bucket(
                self.api_url,
                self.account_auth_token,
                self.account_id,
                self.bucket_id,
                'allPublic',
                default_server_side_encryption=encryption_setting,
                default_retention=default_retention,
            )

    def test_b2_update_bucket_revision_updates(self):
        updated_bucket = self.raw_api.update_bucket(
            self.api_url,
            self.account_auth_token,
            self.account_id,
            self.bucket_id,
            'allPrivate',
            bucket_info={'color': 'blue'},
            default_retention=BucketRetentionSetting(
                mode=RetentionMode.GOVERNANCE, period=RetentionPeriod(days=1)
            ),
            is_file_lock_enabled=True,
        )
        assert self.first_bucket_revision < updated_bucket['revision']

        # NOTE: this update_bucket call is only here to be able to find out the error code returned by
        # the server if an attempt is made to disable file lock.  It has to be done here since the CLI
        # by design does not allow disabling file lock at all (i.e. there is no --fileLockEnabled=false
        # option or anything equivalent to that).
        with pytest.raises(DisablingFileLockNotSupported):
            self.raw_api.update_bucket(
                self.api_url,
                self.account_auth_token,
                self.account_id,
                self.bucket_id,
                'allPrivate',
                is_file_lock_enabled=False,
            )


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
        raw_delete_file(version_dict, raw_api, api_url, account_auth_token)

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
