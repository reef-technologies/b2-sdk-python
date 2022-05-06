######################################################################
#
# File: test/integration/bucket_cleaner.py
#
# Copyright 2022 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

import re
import time

from typing import Optional

from b2sdk.bucket import Bucket
from b2sdk.file_lock import NO_RETENTION_FILE_SETTING, LegalHold, RetentionMode
from b2sdk.utils import current_time_millis
from b2sdk.v2 import *

from .helpers import BUCKET_CREATED_AT_MILLIS, GENERAL_BUCKET_NAME_PREFIX, authorize

ONE_HOUR_MILLIS = 60 * 60 * 1000


class BucketCleaner:
    def __init__(
        self,
        dont_cleanup_old_buckets: bool,
        b2_application_key_id: str,
        b2_application_key: str,
        current_run_prefix: Optional[str] = None
    ):
        self.current_run_prefix = current_run_prefix
        self.dont_cleanup_old_buckets = dont_cleanup_old_buckets
        self.b2_application_key_id = b2_application_key_id
        self.b2_application_key = b2_application_key

    def _should_remove_bucket(self, bucket: Bucket):
        if self.current_run_prefix and bucket.name.startswith(self.current_run_prefix):
            return True
        if self.dont_cleanup_old_buckets:
            return False
        if bucket.name.startswith(GENERAL_BUCKET_NAME_PREFIX):
            if BUCKET_CREATED_AT_MILLIS in bucket.bucket_info:
                if int(bucket.bucket_info[BUCKET_CREATED_AT_MILLIS]
                      ) < current_time_millis() - ONE_HOUR_MILLIS:
                    return True
        return False

    def cleanup_buckets(self):
        b2_api, _ = authorize((self.b2_application_key_id, self.b2_application_key))
        buckets = b2_api.list_buckets()
        for bucket in buckets:
            if not self._should_remove_bucket(bucket):
                print('Skipping bucket removal:', bucket.name)
            else:
                print('Trying to remove bucket:', bucket.name)
                files_leftover = False
                file_versions = bucket.ls(latest_only=False, recursive=True)
                for file_version_info, _ in file_versions:
                    if file_version_info.file_retention:
                        if file_version_info.file_retention.mode == RetentionMode.GOVERNANCE:
                            print('Removing retention from file version:', file_version_info.id_)
                            b2_api.update_file_retention(
                                file_version_info.id_, file_version_info.file_name,
                                NO_RETENTION_FILE_SETTING, True
                            )
                        elif file_version_info.file_retention.mode == RetentionMode.COMPLIANCE:
                            if file_version_info.file_retention.retain_until > current_time_millis():  # yapf: disable
                                print(
                                    'File version: %s cannot be removed due to compliance mode retention'
                                    % (file_version_info.id_,)
                                )
                                files_leftover = True
                                continue
                        elif file_version_info.file_retention.mode == RetentionMode.NONE:
                            pass
                        else:
                            raise ValueError(
                                'Unknown retention mode: %s' %
                                (file_version_info.file_retention.mode,)
                            )
                    if file_version_info.legal_hold.is_on():
                        print('Removing legal hold from file version:', file_version_info.id_)
                        b2_api.update_file_legal_hold(
                            file_version_info.id_, file_version_info.file_name, LegalHold.OFF
                        )
                    print('Removing file version:', file_version_info.id_)
                    b2_api.delete_file_version(file_version_info.id_, file_version_info.file_name)

                if files_leftover:
                    print('Unable to remove bucket because some retained files remain')
                else:
                    print('Removing bucket:', bucket.name)
                    b2_api.delete_bucket(bucket)


def _cleanup_old_buckets(raw_api, api_url, account_auth_token, account_id,  bucket_list_dict):
    for bucket_dict in bucket_list_dict['buckets']:
        bucket_id = bucket_dict['bucketId']
        bucket_name = bucket_dict['bucketName']
        if _should_delete_bucket(bucket_name):
            print('cleaning up old bucket: ' + bucket_name)
            _clean_and_delete_bucket(
                raw_api,
                api_url,
                account_auth_token,
                account_id,
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
