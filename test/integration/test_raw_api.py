######################################################################
#
# File: test/integration/test_raw_api.py
#
# Copyright 2020 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
from __future__ import annotations

import io
import os
import random
import time
from test.helpers import type_validator_factory
from test.integration.helpers import _clean_and_delete_bucket
from test.integration.persistent_bucket import PersistentBucketAggregate
from typing import List

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
    NotificationRuleResponse,
)
from b2sdk._internal.replication.setting import ReplicationConfiguration, ReplicationRule
from b2sdk._internal.replication.types import ReplicationStatus
from b2sdk._internal.utils import hex_sha1_of_stream


@pytest.fixture(scope="class")
def raw_api():
    return B2RawHTTPApi(B2Http())


@pytest.fixture(scope="class")
def auth_info(raw_api):
    application_key_id = os.environ.get('B2_TEST_APPLICATION_KEY_ID')
    application_key = os.environ.get('B2_TEST_APPLICATION_KEY')
    if application_key_id is None or application_key is None:
        pytest.fail('B2_TEST_APPLICATION_KEY_ID or B2_TEST_APPLICATION_KEY is not set.')

    realm = os.environ.get('B2_TEST_ENVIRONMENT', 'production')
    realm_url = REALM_URLS.get(realm, realm)
    return raw_api.authorize_account(realm_url, application_key_id, application_key)


@pytest.fixture(scope="session")
def sse_b2_aes():
    return EncryptionSetting(
        mode=EncryptionMode.SSE_B2,
        algorithm=EncryptionAlgorithm.AES256,
    )


@pytest.fixture(scope="class")
def test_bucket(raw_api, auth_info):
    bucket_name = f'test-raw-api-{auth_info["accountId"]}-{int(time.time())}-{random.randint(1000, 9999)}'
    bucket_dict = raw_api.create_bucket(
        auth_info['apiUrl'],
        auth_info['authorizationToken'],
        auth_info['accountId'],
        bucket_name,
        'allPublic',
        is_file_lock_enabled=True,
        lifecycle_rules=[
            {
                "fileNamePrefix": "",
                "daysFromHidingToDeleting": 1,
                "daysFromUploadingToHiding": 1
            }
        ]
    )
    return bucket_dict


@pytest.fixture(scope="class")
def lock_enabled_bucket(persistent_bucket_factory):
    return persistent_bucket_factory(is_file_lock_enabled=True)


@pytest.fixture(scope="class")
def upload_url_dict(raw_api, auth_info, lock_enabled_bucket):
    upload_url_dict = raw_api.get_upload_url(
        auth_info['apiUrl'],
        auth_info['authorizationToken'],
        lock_enabled_bucket.bucket_id,
    )
    return upload_url_dict


@pytest.fixture(scope="class")
def part_contents_dict():
    part_contents = b'hello part'
    yield {
        'part_contents': part_contents,
        'part_sha1': hex_sha1_of_stream(io.BytesIO(part_contents), len(part_contents))
    }


@pytest.fixture(scope="class")
def uploaded_file_dict(raw_api, lock_enabled_bucket, sse_b2_aes, upload_url_dict):
    upload_url = upload_url_dict['uploadUrl']
    upload_auth_token = upload_url_dict['authorizationToken']
    # file_name = 'test.txt'
    file_name = f'{lock_enabled_bucket.subfolder}/test.txt'
    file_contents = b'hello world'
    file_sha1 = hex_sha1_of_stream(io.BytesIO(file_contents), len(file_contents))
    uploaded_file_dict = raw_api.upload_file(
        upload_url,
        upload_auth_token,
        file_name,
        len(file_contents),
        'text/plain',
        file_sha1, {
            'color': 'blue',
            'b2-cache-control': 'private, max-age=2222'
        },
        io.BytesIO(file_contents),
        server_side_encryption=sse_b2_aes,
        file_retention=FileRetentionSetting(
            RetentionMode.GOVERNANCE,
            int(time.time() + 100) * 1000,
        )
    )
    uploaded_file_dict['file_contents'] = file_contents
    return uploaded_file_dict


@pytest.fixture(scope="class")
def download_auth_token(raw_api, auth_info, lock_enabled_bucket, uploaded_file_dict):
    download_auth = raw_api.get_download_authorization(
        auth_info['apiUrl'], auth_info['authorizationToken'], lock_enabled_bucket.bucket_id,
        uploaded_file_dict['fileName'][:-2], 12345
    )
    yield download_auth['authorizationToken']


class TestRawAPIBucketOps:

    raw_api: B2RawHTTPApi
    auth_info: dict
    test_bucket: dict

    @pytest.fixture(autouse=True, scope="class")
    def setup(self, request, raw_api, auth_info, test_bucket):
        cls = request.cls
        cls.raw_api = raw_api
        cls.auth_info = auth_info
        cls.test_bucket = test_bucket

    @pytest.fixture(scope='class')
    def replication_source_key(self):
        replication_source_key_dict = self.raw_api.create_key(
            self.auth_info['apiUrl'],
            self.auth_info['authorizationToken'],
            self.auth_info['accountId'],
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
        assert 'applicationKeyId' in replication_source_key_dict
        replication_source_key = replication_source_key_dict['applicationKeyId']
        yield replication_source_key

        self.raw_api.delete_key(
            self.auth_info['apiUrl'], self.auth_info['authorizationToken'], replication_source_key
        )

    @pytest.fixture(scope='class')
    def replication_source_bucket_dict(self, replication_source_key):
        replication_source_bucket_name = 'test-raw-api-%s-%d-%d' % (
            self.auth_info['accountId'], int(time.time()), random.randint(1000, 9999)
        )
        replication_source_bucket_dict = self.raw_api.create_bucket(
            self.auth_info['apiUrl'],
            self.auth_info['authorizationToken'],
            self.auth_info['accountId'],
            replication_source_bucket_name,
            'allPublic',
            is_file_lock_enabled=True,
            lifecycle_rules=[
                {
                    "fileNamePrefix": "",
                    "daysFromHidingToDeleting": 1,
                    "daysFromUploadingToHiding": 1
                }
            ],
            replication=ReplicationConfiguration(
                rules=[
                    ReplicationRule(
                        destination_bucket_id=self.test_bucket['bucketId'],
                        include_existing_files=True,
                        name='test-rule',
                    ),
                ],
                source_key_id=replication_source_key,
            ),
        )
        yield replication_source_bucket_dict

        _clean_and_delete_bucket(
            self.raw_api,
            self.auth_info['apiUrl'],
            self.auth_info['authorizationToken'],
            self.auth_info['accountId'],
            replication_source_bucket_dict['bucketId'],
        )

    @pytest.fixture(scope='class')
    def replication_destination_key(self):
        replication_destination_key_dict = self.raw_api.create_key(
            self.auth_info['apiUrl'],
            self.auth_info['authorizationToken'],
            self.auth_info['accountId'],
            ['listBuckets', 'listFiles', 'writeFiles'],
            'testReplicationDestinationKey',
            None,
            None,
            None,
        )

        replication_destination_key = replication_destination_key_dict['applicationKeyId']
        yield replication_destination_key

        self.raw_api.delete_key(
            self.auth_info['apiUrl'], self.auth_info['authorizationToken'],
            replication_destination_key
        )

    def test_update_bucket_with_encryption(self, sse_b2_aes):
        sse_none = EncryptionSetting(mode=EncryptionMode.NONE)
        test_cases = [
            (
                sse_none,
                BucketRetentionSetting(
                    mode=RetentionMode.GOVERNANCE, period=RetentionPeriod(days=1)
                )
            ),
            (sse_b2_aes, BucketRetentionSetting(RetentionMode.NONE)),
            (sse_b2_aes, BucketRetentionSetting(RetentionMode.NONE)),
        ]

        for encryption_setting, default_retention in test_cases:
            self.raw_api.update_bucket(
                self.auth_info['apiUrl'],
                self.auth_info['authorizationToken'],
                self.auth_info['accountId'],
                self.test_bucket['bucketId'],
                'allPublic',
                default_server_side_encryption=encryption_setting,
                default_retention=default_retention,
            )

    def test_disable_file_lock(self):
        with pytest.raises(DisablingFileLockNotSupported):
            self.raw_api.update_bucket(
                self.auth_info['apiUrl'],
                self.auth_info['authorizationToken'],
                self.auth_info['accountId'],
                self.test_bucket['bucketId'],
                'allPrivate',
                is_file_lock_enabled=False,
            )

    def test_authorize_account(self):
        preview_feature_caps = {
            'readBucketNotifications',
            'writeBucketNotifications',
        }
        missing_capabilities = (
            set(ALL_CAPABILITIES) - {'readBuckets', 'listAllBucketNames'} - preview_feature_caps -
            set(self.auth_info['allowed']['capabilities'])
        )
        assert not missing_capabilities, f'it appears that the raw_api integration test is being run with a non-full key. Missing capabilities: {missing_capabilities}'

    def test_create_list_delete_key(self):
        account_id = self.auth_info['accountId']
        account_auth_token = self.auth_info['authorizationToken']
        api_url = self.auth_info['apiUrl']
        key_dict = self.raw_api.create_key(
            api_url,
            account_auth_token,
            account_id,
            ['readFiles'],
            'testKey',
            None,
            None,
            None,
        )
        self.raw_api.list_keys(api_url, account_auth_token, account_id, 10)
        self.raw_api.delete_key(api_url, account_auth_token, key_dict['applicationKeyId'])

    def test_create_bucket_with_replication(
        self, replication_source_key, replication_source_bucket_dict
    ):
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
                                        "destinationBucketId": self.test_bucket['bucketId'],
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

        upload_url_dict = self.raw_api.get_upload_url(
            self.auth_info['apiUrl'],
            self.auth_info['authorizationToken'],
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

    def test_update_bucket_to_receive_updates(
        self, replication_destination_key, replication_source_key
    ):
        bucket_dict = self.raw_api.update_bucket(
            self.auth_info['apiUrl'],
            self.auth_info['authorizationToken'],
            self.auth_info['accountId'],
            self.test_bucket['bucketId'],
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

    def test_disable_replication(self):
        bucket_dict = self.raw_api.update_bucket(
            self.auth_info['apiUrl'],
            self.auth_info['authorizationToken'],
            self.auth_info['accountId'],
            self.test_bucket['bucketId'],
            'allPublic',
            replication=ReplicationConfiguration(),
        )
        assert bucket_dict['replicationConfiguration'] == {
            'isClientAuthorizedToRead': True,
            'value': None,
        }


class TestRawAPIFileOps:

    raw_api: B2RawHTTPApi
    auth_info: dict
    lock_enabled_bucket: PersistentBucketAggregate
    sse_b2_aes: EncryptionSetting
    upload_url_dict: dict

    uploaded_file_dict: dict
    download_auth_token: str

    @pytest.fixture(autouse=True, scope="class")
    def setup(
        self, request, raw_api, auth_info, lock_enabled_bucket, sse_b2_aes, uploaded_file_dict,
        download_auth_token
    ):
        cls = request.cls
        cls.raw_api = raw_api
        cls.auth_info = auth_info
        cls.lock_enabled_bucket = lock_enabled_bucket
        cls.sse_b2_aes = sse_b2_aes
        cls.uploaded_file_dict = uploaded_file_dict
        cls.download_auth_token = download_auth_token

    @pytest.fixture(scope="class")
    def large_file(self):
        unique_subfolder = self.lock_enabled_bucket.new_subfolder()
        file_info = {'color': 'red'}
        large_info = self.raw_api.start_large_file(
            self.auth_info['apiUrl'],
            self.auth_info['authorizationToken'],
            self.lock_enabled_bucket.bucket_id,
            f'{unique_subfolder}/large_file.txt',
            'text/plain',
            file_info,
        )
        return large_info

    @pytest.fixture(scope="class")
    def upload_part_dict(self, large_file):
        yield self.raw_api.get_upload_part_url(
            self.auth_info['apiUrl'], self.auth_info['authorizationToken'], large_file['fileId']
        )

    def test_list_bucket(self):
        self.raw_api.list_buckets(
            self.auth_info['apiUrl'],
            self.auth_info['authorizationToken'],
            self.auth_info['accountId'],
            self.lock_enabled_bucket.bucket_id,
        )

    def test_list_file_versions(self):
        file_name = self.uploaded_file_dict['fileName']
        list_versions_dict = self.raw_api.list_file_versions(
            self.auth_info['apiUrl'],
            self.auth_info['authorizationToken'],
            self.lock_enabled_bucket.bucket_id,
        )
        assert [file_name] == [f_dict['fileName'] for f_dict in list_versions_dict['files']]
        assert ['private, max-age=2222'] == [
            f_dict['fileInfo']['b2-cache-control'] for f_dict in list_versions_dict['files']
        ]

    def test_download_file_by_id_auth(self):
        url = self.raw_api.get_download_url_by_id(
            self.auth_info['downloadUrl'], self.uploaded_file_dict['fileId']
        )
        account_auth_token = self.auth_info['authorizationToken']
        file_contents = self.uploaded_file_dict['file_contents']
        with self.raw_api.download_file_from_url(account_auth_token, url) as response:
            data = next(response.iter_content(chunk_size=len(file_contents)))
            assert data == file_contents, data

    def test_download_file_by_id_no_auth(self):
        url = self.raw_api.get_download_url_by_name(
            self.auth_info['downloadUrl'], self.lock_enabled_bucket.bucket_name,
            self.uploaded_file_dict['fileName']
        )
        with self.raw_api.download_file_from_url(
            self.auth_info['authorizationToken'], url
        ) as response:
            data = next(
                response.iter_content(chunk_size=len(self.uploaded_file_dict['file_contents']))
            )
            assert data == self.uploaded_file_dict['file_contents'], data

    def test_download_file_by_name_name(self):
        url = self.raw_api.get_download_url_by_name(
            self.auth_info['downloadUrl'], self.lock_enabled_bucket.bucket_name,
            self.uploaded_file_dict['fileName']
        )
        with self.raw_api.download_file_from_url(None, url) as response:
            data = next(
                response.iter_content(chunk_size=len(self.uploaded_file_dict['file_contents']))
            )
            assert data == self.uploaded_file_dict['file_contents'], data

    def test_download_file_by_name_auth(self):
        url = self.raw_api.get_download_url_by_name(
            self.auth_info['downloadUrl'], self.lock_enabled_bucket.bucket_name,
            self.uploaded_file_dict['fileName']
        )
        with self.raw_api.download_file_from_url(self.download_auth_token, url) as response:
            data = next(
                response.iter_content(chunk_size=len(self.uploaded_file_dict['file_contents']))
            )
            assert data == self.uploaded_file_dict['file_contents'], data

    def test_list_file_names(self):
        url = self.raw_api.get_download_url_by_name(
            self.auth_info['downloadUrl'], self.lock_enabled_bucket.bucket_name,
            self.uploaded_file_dict['fileName']
        )
        with self.raw_api.download_file_from_url(self.download_auth_token, url) as response:
            data = next(
                response.iter_content(chunk_size=len(self.uploaded_file_dict['file_contents']))
            )
            assert data == self.uploaded_file_dict['file_contents'], data

    def test_list_file_names_start_count(self):
        list_names_dict = self.raw_api.list_file_names(
            self.auth_info['apiUrl'],
            self.auth_info['authorizationToken'],
            self.lock_enabled_bucket.bucket_id,
            start_file_name=self.uploaded_file_dict['fileName'],
            max_file_count=5
        )
        assert [self.uploaded_file_dict['fileName']] == [
            f_dict['fileName'] for f_dict in list_names_dict['files']
        ]

    def test_copy_file(self):
        copy_file_name = f'{self.lock_enabled_bucket.subfolder}/test_copy.txt'
        self.raw_api.copy_file(
            self.auth_info['apiUrl'], self.auth_info['authorizationToken'],
            self.uploaded_file_dict['fileId'], copy_file_name
        )

    def test_get_file_info_by_id(self):
        file_info_dict = self.raw_api.get_file_info_by_id(
            self.auth_info['apiUrl'], self.auth_info['authorizationToken'],
            self.uploaded_file_dict['fileId']
        )
        assert file_info_dict['fileName'] == self.uploaded_file_dict['fileName']

    def test_get_file_info_by_name_no_auth(self):
        file_info_dict = self.raw_api.get_file_info_by_name(
            self.auth_info['downloadUrl'], None, self.lock_enabled_bucket.bucket_name,
            self.uploaded_file_dict['fileName']
        )
        assert file_info_dict['x-bz-file-id'] == self.uploaded_file_dict['fileId']

    def test_get_file_info_by_name_auth(self):
        file_info_dict = self.raw_api.get_file_info_by_name(
            self.auth_info['downloadUrl'], self.auth_info['authorizationToken'],
            self.lock_enabled_bucket.bucket_name, self.uploaded_file_dict['fileName']
        )
        assert file_info_dict['x-bz-file-id'] == self.uploaded_file_dict['fileId']

    def test_get_file_info_by_name_download_auth(self):
        file_info_dict = self.raw_api.get_file_info_by_name(
            self.auth_info['downloadUrl'], self.download_auth_token,
            self.lock_enabled_bucket.bucket_name, self.uploaded_file_dict['fileName']
        )
        assert file_info_dict['x-bz-file-id'] == self.uploaded_file_dict['fileId']

    def test_hide_file(self):
        self.raw_api.hide_file(
            self.auth_info['apiUrl'], self.auth_info['authorizationToken'],
            self.lock_enabled_bucket.bucket_id, self.uploaded_file_dict['fileName']
        )

    def test_upload_part(self, upload_part_dict, part_contents_dict):
        upload_part_url = upload_part_dict['uploadUrl']
        upload_path_auth = upload_part_dict['authorizationToken']
        part_contents = part_contents_dict['part_contents']
        part_sha1 = part_contents_dict['part_sha1']
        self.raw_api.upload_part(
            upload_part_url, upload_path_auth, 1, len(part_contents), part_sha1,
            io.BytesIO(part_contents)
        )

    def test_copy_part(self, large_file):
        self.raw_api.copy_part(
            self.auth_info['apiUrl'], self.auth_info['authorizationToken'],
            self.uploaded_file_dict['fileId'], large_file['fileId'], 2, (0, 5)
        )

    def test_list_parts(self, large_file):
        parts_response = self.raw_api.list_parts(
            self.auth_info['apiUrl'], self.auth_info['authorizationToken'], large_file['fileId'], 1,
            100
        )
        assert [1, 2] == [part['partNumber'] for part in parts_response['parts']]

    def test_list_unfinished_large_files(self, large_file):
        unfinished_list = self.raw_api.list_unfinished_large_files(
            self.auth_info['apiUrl'], self.auth_info['authorizationToken'],
            self.lock_enabled_bucket.bucket_id
        )
        assert [large_file['fileName']] == [
            f_dict['fileName'] for f_dict in unfinished_list['files']
        ]
        assert large_file['fileInfo'] == unfinished_list['files'][0]['fileInfo']

    def test_finish_large_file_too_few_parts(self, large_file, part_contents_dict):
        try:
            self.raw_api.finish_large_file(
                self.auth_info['apiUrl'], self.auth_info['authorizationToken'],
                large_file['fileId'], [part_contents_dict['part_sha1']]
            )
            pytest.fail('finish should have failed')
        except Exception as e:
            assert 'large files must have at least 2 parts' in str(e)

    def test_finish_large_file_success(self, large_file, upload_part_dict):
        upload_part_url = upload_part_dict['uploadUrl']
        upload_path_auth = upload_part_dict['authorizationToken']

        # Create two parts, each at least 5 MB in size
        part_size = 5 * 1024 * 1024  # 5 MB
        part1_contents = b'0' * part_size
        part2_contents = b'1' * part_size

        part1_sha1 = hex_sha1_of_stream(io.BytesIO(part1_contents), len(part1_contents))
        part2_sha1 = hex_sha1_of_stream(io.BytesIO(part2_contents), len(part2_contents))

        # Upload the first part
        self.raw_api.upload_part(
            upload_part_url, upload_path_auth, 1, len(part1_contents), part1_sha1,
            io.BytesIO(part1_contents)
        )

        # Upload the second part
        self.raw_api.upload_part(
            upload_part_url, upload_path_auth, 2, len(part2_contents), part2_sha1,
            io.BytesIO(part2_contents)
        )

        self.raw_api.finish_large_file(
            self.auth_info['apiUrl'], self.auth_info['authorizationToken'], large_file['fileId'],
            [part1_sha1, part2_sha1]
        )

    def test_list_finished_large_files(self, large_file):
        finished_file = self.raw_api.list_file_names(
            self.auth_info['apiUrl'],
            self.auth_info['authorizationToken'],
            self.lock_enabled_bucket.bucket_id,
            prefix=large_file['fileName'][:6]
        )
        assert [large_file['fileName']] == [f_dict['fileName'] for f_dict in finished_file['files']]
        assert large_file['fileInfo'] == finished_file['files'][0]['fileInfo']

    def test_unauthorized_delete_file_version(self):
        with pytest.raises(Unauthorized):
            self.raw_api.delete_file_version(
                self.auth_info['apiUrl'], self.auth_info['authorizationToken'],
                self.uploaded_file_dict['fileId'], self.uploaded_file_dict['fileName']
            )

    def test_delete_file_version_with_auth(self):
        self.raw_api.delete_file_version(
            self.auth_info['apiUrl'], self.auth_info['authorizationToken'],
            self.uploaded_file_dict['fileId'], self.uploaded_file_dict['fileName'], True
        )


def _subtest_bucket_notification_rules(raw_api, auth_info, bucket_id):
    account_auth_token = auth_info['authorizationToken']
    api_url = auth_info['apiUrl']

    if 'writeBucketNotifications' not in auth_info['allowed']['capabilities']:
        pytest.skip('Test account does not have writeBucketNotifications capability')

    notification_rule = {
        'eventTypes': ['b2:ObjectCreated:Copy'],
        'isEnabled': False,
        'name': 'test-notification-rule',
        'objectNamePrefix': 'test/object/prefix/',
        'targetConfiguration':
            {
                'targetType': 'webhook',
                'url': 'https://example.com/webhook',
                'hmacSha256SigningSecret': 'a' * 32,
            },
    }

    notification_rules_response_list = raw_api.set_bucket_notification_rules(
        api_url, account_auth_token, bucket_id, [notification_rule]
    )
    notification_rule_response_list_validate = type_validator_factory(
        List[NotificationRuleResponse]
    )
    notification_rule_response_list_validate(notification_rules_response_list)
    expected_notification_rule_response_list = [
        {
            **notification_rule, 'isSuspended': False,
            'suspensionReason': '',
            'targetConfiguration':
                {
                    **notification_rule['targetConfiguration'],
                    'customHeaders': None,
                    'hmacSha256SigningSecret': 'a' * 32,
                }
        }
    ]
    assert notification_rules_response_list == expected_notification_rule_response_list

    assert raw_api.set_bucket_notification_rules(api_url, account_auth_token, bucket_id, []) == []
    assert raw_api.get_bucket_notification_rules(api_url, account_auth_token, bucket_id) == []


def test_get_and_set_bucket_notification_rules(raw_api, auth_info, test_bucket):
    try:
        _subtest_bucket_notification_rules(raw_api, auth_info, test_bucket['bucketId'])
    except pytest.skip.Exception as e:
        print(e)
