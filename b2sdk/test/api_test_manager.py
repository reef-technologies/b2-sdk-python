######################################################################
#
# File: b2sdk/test/api_test_manager.py
#
# Copyright 2023 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
import time
import uuid

from datetime import datetime
from os import environ
from typing import Union

import backoff

from .bucket_tracking import BucketTrackingMixin
from b2sdk.v2 import (
    NO_RETENTION_FILE_SETTING, B2Api, Bucket, InMemoryAccountInfo, InMemoryCache, LegalHold,
    RetentionMode
)
from b2sdk.v2.exception import BucketIdNotFound, DuplicateBucketName, FileNotPresent, TooManyRequests, NonExistentBucket

SHORT_SHA = environ.get('GITHUB_SHA', 'local')[:10]
BUCKET_NAME_PREFIX = f"b2test-{SHORT_SHA}"


def generate_bucket_name() -> str:
    return f"{BUCKET_NAME_PREFIX}-{uuid.uuid4()}"


def current_time_millis() -> int:
    return int(round(time.time() * 1000))


class ApiTestManager(BucketTrackingMixin, B2Api):
    """
    B2Api wrapper which should only be used for testing purposes!
    """

    def __init__(self, account_id: str, application_key: str, realm: str, *args, **kwargs):
        info = InMemoryAccountInfo()
        cache = InMemoryCache()
        super().__init__(info, cache=cache, *args, **kwargs)
        self.authorize_account(realm, account_id, application_key)

    @backoff.on_exception(
        backoff.constant,
        DuplicateBucketName,
        max_tries=8,
    )
    def create_test_bucket(self, bucket_type="allPublic", **kwargs) -> Bucket:
        bucket_name = generate_bucket_name()
        print(f'Creating bucket: {bucket_name}')
        try:
            return self.create_bucket(bucket_name, bucket_type, **kwargs)
        except DuplicateBucketName:
            self._duplicated_bucket_name_debug_info(bucket_name)
            raise

    @backoff.on_exception(
        backoff.expo,
        TooManyRequests,
        max_tries=8,
    )
    def clean_bucket(self, bucket: Union[Bucket, str]) -> None:
        if isinstance(bucket, str):
            bucket = self.get_bucket_by_name(bucket)

        files_leftover = False
        file_versions = bucket.ls(latest_only=False, recursive=True)

        for file_version_info, _ in file_versions:
            if file_version_info.file_retention:
                if file_version_info.file_retention.mode == RetentionMode.GOVERNANCE:
                    print(f'Removing retention from file version: {file_version_info.id_}')
                    self.update_file_retention(
                        file_version_info.id_,
                        file_version_info.file_name,
                        NO_RETENTION_FILE_SETTING,
                        bypass_governance=True
                    )
                elif file_version_info.file_retention.mode == RetentionMode.COMPLIANCE:
                    if file_version_info.file_retention.retain_until > current_time_millis():  # yapf: disable
                        print(
                            f'File version: {file_version_info.id_} cannot be removed due to compliance mode retention'
                        )
                        files_leftover = True
                        continue
                elif file_version_info.file_retention.mode == RetentionMode.NONE:
                    pass
                else:
                    raise ValueError(
                        f'Unknown retention mode: {file_version_info.file_retention.mode}'
                    )
            if file_version_info.legal_hold.is_on():
                print(f'Removing legal hold from file version: {file_version_info.id_}')
                self.update_file_legal_hold(
                    file_version_info.id_, file_version_info.file_name, LegalHold.OFF
                )
            print(f'Removing file version: {file_version_info.id_}')
            try:
                self.delete_file_version(file_version_info.id_, file_version_info.file_name)
            except FileNotPresent:
                print(
                    f'It seems that file version {file_version_info.id_} has already been removed'
                )

        if files_leftover:
            print('Unable to remove bucket because some retained files remain')
        else:
            print(f'Removing bucket: {bucket.name}')
            try:
                self.delete_bucket(bucket)
            except (BucketIdNotFound, NonExistentBucket):
                print(f'It seems that bucket {bucket.name} has already been removed')
        print()

    def clean_buckets(self) -> None:
        self.count_and_print_buckets()
        for bucket in self.buckets:
            self.clean_bucket(bucket)
        self.buckets = []

    def clean_all_buckets(self) -> None:
        buckets = self.list_buckets()
        print(f'Total bucket count: {len(buckets)}')

        for bucket in buckets:
            if not bucket.name.startswith(BUCKET_NAME_PREFIX):
                print(f'Skipping bucket removal: "{bucket.name}"')
                continue
            self.clean_bucket(bucket)

        buckets = self.list_buckets()
        print(f'Total bucket count after cleanup: {len(buckets)}')
        for bucket in buckets:
            print(bucket)

    def count_and_print_buckets(self) -> None:
        buckets = self.buckets
        count = len(buckets)
        print(f'Total bucket count at {datetime.now()}: {count}')
        for i, bucket in enumerate(buckets, start=1):
            print(f'- {i}\t{bucket.name} [{bucket.id_}]')

    def _duplicated_bucket_name_debug_info(self, bucket_name: str) -> None:
        # Trying to obtain as much information as possible about this bucket.
        print(' DUPLICATED BUCKET DEBUG START '.center(60, '='))
        bucket = self.get_bucket_by_name(bucket_name)

        print('Bucket metadata:')
        bucket_dict = bucket.as_dict()
        for info_key, info in bucket_dict.items():
            print('\t%s: "%s"' % (info_key, info))

        print('All files (and their versions) inside the bucket:')
        ls_generator = bucket.ls(recursive=True, latest_only=False)
        for file_version, _directory in ls_generator:
            # as_dict() is bound to have more info than we can use,
            # but maybe some of it will cast some light on the issue.
            print('\t%s (%s)' % (file_version.file_name, file_version.as_dict()))

        print(' DUPLICATED BUCKET DEBUG END '.center(60, '='))
