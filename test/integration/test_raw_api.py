######################################################################
#
# File: test/integration/test_raw_api.py
#
# Copyright 2020 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
import io

from random import randint
from time import time

import pytest

from b2sdk.encryption.setting import EncryptionMode, EncryptionSetting
from b2sdk.file_lock import BucketRetentionSetting, RetentionMode, RetentionPeriod
from b2sdk.replication.setting import ReplicationConfiguration, ReplicationDestinationConfiguration, ReplicationRule, ReplicationSourceConfiguration
from b2sdk.replication.types import ReplicationStatus
from b2sdk.utils import hex_sha1_of_stream

from .bucket_cleaner import _clean_and_delete_bucket, _cleanup_old_buckets

"""
Try each of the calls to the raw api.

This uses a Backblaze account that is just for this test.
The account uses the free level of service, which should
be enough to run this test a reasonable number of times
each day.  If somebody abuses the account for other things,
this test will break and we'll have to do something about
it.
"""


@pytest.fixture(scope='module', autouse=True)
def cleanup_buckets(raw_api, account_id, account_auth_token, api_url, dont_cleanup_old_buckets):
    """ Remove all "stale" test buckets """

    if dont_cleanup_old_buckets:
        return

    bucket_list_dict = raw_api.list_buckets(api_url, account_auth_token, account_id)

    _cleanup_old_buckets(raw_api, api_url, account_auth_token, account_id, bucket_list_dict)


def test_auth(auth_dict):
    pass  # `auth_dict` implicitly invokes testing


def test_keys(raw_api, api_url, account_auth_token, account_id):
    key_dict = raw_api.create_key(
        api_url,
        account_auth_token,
        account_id,
        ['readFiles'],
        'testKey',
        None,
        None,
        None,
    )
    raw_api.list_keys(api_url, account_auth_token, account_id, 10)
    raw_api.delete_key(api_url, account_auth_token, key_dict['applicationKeyId'])


def test_bucket_creation(bucket_dict):
    pass  # `bucket_dict` implicitly invokes testing


class TestReplication:
    @pytest.fixture(scope='class')
    def source_key_id(self, raw_api, api_url, account_auth_token, account_id):
        key_dict = raw_api.create_key(
            api_url,
            account_auth_token,
            account_id,
            ['listBuckets', 'listFiles', 'readFiles'],
            'testReplicationSourceKey',
            None,
            None,
            None,
        )
        key_id = key_dict['applicationKeyId']
        yield key_id
        raw_api.delete_key(
            api_url,
            account_auth_token,
            key_id,
        )

    @pytest.fixture(scope='class')
    def source_bucket_dict(
        self, raw_api, api_url, account_auth_token, account_id, source_key_id, bucket_id,
        bucket_name,
    ):
        bucket_name = f'test-raw-api-{account_id}-{time():.0f}-{randint(1000, 9999)}'
        bucket = raw_api.create_bucket(
            api_url,
            account_auth_token,
            account_id,
            bucket_name,
            'allPublic',
            is_file_lock_enabled=True,
            replication=ReplicationConfiguration(
                as_replication_source=ReplicationSourceConfiguration(
                    rules=[
                        ReplicationRule(
                            destination_bucket_id=bucket_id,
                            include_existing_files=True,
                            name='test-rule',
                        ),
                    ],
                    source_application_key_id=source_key_id,
                ),
            ),
        )
        yield bucket
        _clean_and_delete_bucket(
            raw_api,
            api_url,
            account_auth_token,
            account_id,
            bucket['bucketId'],
        )

    @pytest.fixture(scope='class')
    def destination_key_id(self, raw_api, api_url, account_auth_token, account_id):
        key_dict = raw_api.create_key(
            api_url,
            account_auth_token,
            account_id,
            ['listBuckets', 'listFiles', 'writeFiles'],
            'testReplicationDestinationKey',
            None,
            None,
            None,
        )
        key_id = key_dict['applicationKeyId']
        yield key_id
        raw_api.delete_key(
            api_url,
            account_auth_token,
            key_id,
        )

    def test_replication(
        self, raw_api, api_url, account_auth_token, account_id, source_key_id, source_bucket_dict,
        bucket_id, destination_key_id,
    ):
        assert 'replicationConfiguration' in source_bucket_dict
        assert source_bucket_dict['replicationConfiguration'] == {
            'isClientAuthorizedToRead': True,
            'value':
                {
                    "asReplicationSource":
                        {
                            "replicationRules":
                                [
                                    {
                                        "destinationBucketId": bucket_id,
                                        "fileNamePrefix": "",
                                        "includeExistingFiles": True,
                                        "isEnabled": True,
                                        "priority": 128,
                                        "replicationRuleName": "test-rule"
                                    },
                                ],
                            "sourceApplicationKeyId": source_key_id,
                        },
                    "asReplicationDestination": None,
                },
        }

        # upload test file and check replication status
        upload_url_dict = raw_api.get_upload_url(
            api_url,
            account_auth_token,
            source_bucket_dict['bucketId'],
        )
        file_contents = b'hello world'
        file_dict = raw_api.upload_file(
            upload_url_dict['uploadUrl'],
            upload_url_dict['authorizationToken'],
            'test.txt',
            len(file_contents),
            'text/plain',
            hex_sha1_of_stream(io.BytesIO(file_contents), len(file_contents)),
            {'color': 'blue'},
            io.BytesIO(file_contents),
        )

        assert ReplicationStatus[
            file_dict['replicationStatus'].upper()
        ] == ReplicationStatus.PENDING

        # update destination bucket to receive updates
        bucket_dict = raw_api.update_bucket(
            api_url,
            account_auth_token,
            account_id,
            bucket_id,
            'allPublic',
            replication=ReplicationConfiguration(
                as_replication_destination=ReplicationDestinationConfiguration(
                    source_to_destination_key_mapping={source_key_id: destination_key_id},
                ),
            ),
        )
        assert bucket_dict['replicationConfiguration'] == {
            'isClientAuthorizedToRead': True,
            'value':
                {
                    'asReplicationDestination':
                        {
                            'sourceToDestinationKeyMapping':
                                {source_key_id: destination_key_id},
                        },
                    'asReplicationSource': None,
                },
        }

        bucket_dict = raw_api.update_bucket(
            api_url,
            account_auth_token,
            account_id,
            bucket_id,
            'allPublic',
            replication=ReplicationConfiguration(),
        )
        assert bucket_dict['replicationConfiguration'] == {
            'isClientAuthorizedToRead': True,
            'value': None,
        }


def test_update_bucket(raw_api, api_url, account_auth_token, account_id, bucket_id, sse_none, sse_b2_aes):
    for encryption_setting, default_retention in [
        (
            sse_none,
            BucketRetentionSetting(mode=RetentionMode.GOVERNANCE, period=RetentionPeriod(days=1))
        ),
        (sse_b2_aes, None),
        (sse_b2_aes, BucketRetentionSetting(RetentionMode.NONE)),
    ]:
        raw_api.update_bucket(
            api_url,
            account_auth_token,
            account_id,
            bucket_id,
            'allPublic',
            default_server_side_encryption=encryption_setting,
            default_retention=default_retention,
        )


def test_list_buckets(raw_api, api_url, account_auth_token, account_id):
    raw_api.list_buckets(api_url, account_auth_token, account_id)


def test_upload_url(upload_url_dict):
    pass


def test_file_upload(file_dict):
    pass


def test_list_file_versions(raw_api, api_url, account_auth_token, bucket_id, file_dict, file_name):
    list_versions_dict = raw_api.list_file_versions(api_url, account_auth_token, bucket_id)
    assert [file_name] == [f_dict['fileName'] for f_dict in list_versions_dict['files']]


def test_download_file_by_id_with_auth(raw_api, download_url, file_dict, account_auth_token, file_contents):
    url = raw_api.get_download_url_by_id(download_url, file_dict['fileId'])
    with raw_api.download_file_from_url(account_auth_token, url) as response:
        data = next(response.iter_content(chunk_size=len(file_contents)))
        assert data == file_contents, data


def test_download_file_by_id_no_auth(raw_api, download_url, file_dict, file_contents):
    url = raw_api.get_download_url_by_id(download_url, file_dict['fileId'])
    with raw_api.download_file_from_url(None, url) as response:
        data = next(response.iter_content(chunk_size=len(file_contents)))
        assert data == file_contents, data


def test_download_file_by_name_with_auth(raw_api, download_url, file_name, bucket_name, account_auth_token, file_contents):
    url = raw_api.get_download_url_by_name(download_url, bucket_name, file_name)
    with raw_api.download_file_from_url(account_auth_token, url) as response:
        data = next(response.iter_content(chunk_size=len(file_contents)))
        assert data == file_contents, data


def test_download_file_by_name_no_auth(raw_api, download_url, file_name, bucket_name, file_contents):
    url = raw_api.get_download_url_by_name(download_url, bucket_name, file_name)
    with raw_api.download_file_from_url(None, url) as response:
        data = next(response.iter_content(chunk_size=len(file_contents)))
        assert data == file_contents, data


def test_get_download_authorization(download_auth_dict):
    pass


def test_download_file_by_name_download_auth(download_auth_dict, raw_api, download_url, bucket_name, file_name, file_contents):
    download_auth_token = download_auth_dict['authorizationToken']
    url = raw_api.get_download_url_by_name(download_url, bucket_name, file_name)
    with raw_api.download_file_from_url(download_auth_token, url) as response:
        data = next(response.iter_content(chunk_size=len(file_contents)))
        assert data == file_contents, data


def test_list_file_names(raw_api, api_url, account_auth_token, bucket_id, file_name):
    list_names_dict = raw_api.list_file_names(api_url, account_auth_token, bucket_id)
    assert [file_name] == [f_dict['fileName'] for f_dict in list_names_dict['files']]


def test_list_file_names_start_count(raw_api, api_url, account_auth_token, bucket_id, file_name):
    list_names_dict = raw_api.list_file_names(
        api_url, account_auth_token, bucket_id, start_file_name=file_name, max_file_count=5
    )
    assert [file_name] == [f_dict['fileName'] for f_dict in list_names_dict['files']]


def test_copy_file(raw_api, api_url, account_auth_token, file_id):
    copy_file_name = 'test_copy.txt'
    raw_api.copy_file(api_url, account_auth_token, file_id, copy_file_name)


def test_get_file_info_by_id(raw_api, api_url, account_auth_token, file_id, file_name):
    file_info_dict = raw_api.get_file_info_by_id(api_url, account_auth_token, file_id)
    assert file_info_dict['fileName'] == file_name


def test_get_file_info_by_name_no_auth(raw_api, api_url, account_id, bucket_name, file_name, file_id, download_url):
    info_headers = raw_api.get_file_info_by_name(download_url, None, bucket_name, file_name)
    assert info_headers['x-bz-file-id'] == file_id


def test_get_file_info_by_name_with_auth(raw_api, download_url, account_auth_token, bucket_name, file_name, file_id):
    info_headers = raw_api.get_file_info_by_name(
        download_url, account_auth_token, bucket_name, file_name
    )
    assert info_headers['x-bz-file-id'] == file_id


def test_get_file_info_by_name_download_auth(raw_api, download_url, download_auth_token, bucket_name, file_name, file_id):
    info_headers = raw_api.get_file_info_by_name(
        download_url, download_auth_token, bucket_name, file_name
    )
    assert info_headers['x-bz-file-id'] == file_id


def test_hide_file(raw_api, api_url, account_auth_token, bucket_id, file_name):
    raw_api.hide_file(api_url, account_auth_token, bucket_id, file_name)


class TestLargeFile:

    @pytest.fixture(scope='class')
    def file_info(self) -> dict:
        return {'color': 'red'}

    @pytest.fixture(scope='class')
    def large_file_id(self, raw_api, api_url, account_auth_token, bucket_id, file_name, sse_b2_aes, file_info) -> str:
        large_info = raw_api.start_large_file(
            api_url,
            account_auth_token,
            bucket_id,
            file_name,
            'text/plain',
            file_info,
            server_side_encryption=sse_b2_aes,
        )
        return large_info['fileId']

    @pytest.fixture(scope='class')
    def part_contents(self) -> bytes:
        return b'hello part'

    @pytest.fixture(scope='class')
    def part_sha1(self, part_contents) -> bytes:
        return hex_sha1_of_stream(io.BytesIO(part_contents), len(part_contents))

    def test_upload_part(self, raw_api, api_url, account_auth_token, large_file_id, file_contents, part_contents, part_sha1):
        upload_part_dict = raw_api.get_upload_part_url(api_url, account_auth_token, large_file_id)
        upload_part_url = upload_part_dict['uploadUrl']
        upload_path_auth = upload_part_dict['authorizationToken']

        raw_api.upload_part(
            upload_part_url, upload_path_auth, 1, len(part_contents), part_sha1,
            io.BytesIO(part_contents)
        )

    def test_copy_part(self, raw_api, api_url, account_auth_token, file_id, large_file_id):
        raw_api.copy_part(api_url, account_auth_token, file_id, large_file_id, 2, (0, 5))

    def test_list_parts(self, raw_api, api_url, account_auth_token, large_file_id):
        parts_response = raw_api.list_parts(api_url, account_auth_token, large_file_id, 1, 100)
        assert [1, 2] == [part['partNumber'] for part in parts_response['parts']]

    def test_list_unfinished_large_files(self, raw_api, api_url, account_auth_token, bucket_id, file_name, file_info):
        unfinished_list = raw_api.list_unfinished_large_files(api_url, account_auth_token, bucket_id)
        assert [file_name] == [f_dict['fileName'] for f_dict in unfinished_list['files']]
        assert file_info == unfinished_list['files'][0]['fileInfo']

    def test_finish_large_file(self, raw_api, api_url, account_auth_token, large_file_id, part_sha1):
        with pytest.raises(Exception, match='large files must have at least 2 parts'):
            raw_api.finish_large_file(api_url, account_auth_token, large_file_id, [part_sha1])

    # TODO: make another attempt to finish but this time successfully


def test_update_bucket_revision(raw_api, api_url, account_auth_token, bucket_dict, bucket_id, account_id):
    updated_bucket = raw_api.update_bucket(
        api_url,
        account_auth_token,
        account_id,
        bucket_id,
        'allPrivate',
        bucket_info={'color': 'blue'},
        default_retention=BucketRetentionSetting(
            mode=RetentionMode.GOVERNANCE, period=RetentionPeriod(days=1)
        ),
    )
    assert bucket_dict['revision'] < updated_bucket['revision']
