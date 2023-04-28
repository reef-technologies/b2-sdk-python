import contextlib
import random
import string
import time

from datetime import datetime
from os import environ
from typing import Union

import backoff

from .bucket_tracking import BucketTrackingMixin
from .._v3.exception import BucketIdNotFound as v3BucketIdNotFound
from ..v2 import NO_RETENTION_FILE_SETTING, B2Api, Bucket, InMemoryAccountInfo, InMemoryCache, LegalHold, RetentionMode
from ..v2.exception import BucketIdNotFound, DuplicateBucketName, FileNotPresent, TooManyRequests, NonExistentBucket

ONE_HOUR_MILLIS = 60 * 60 * 1000
ONE_DAY_MILLIS = ONE_HOUR_MILLIS * 24

BUCKET_NAME_LENGTH = 50
BUCKET_NAME_CHARS = string.ascii_letters + string.digits + '-'

BUCKET_NAME_PREFIX = 'b2tst'

# RUNNER_NAME is the only variable exposed by the GitHub CI that was changing for each matrix entry.
# Example values are "GitHub Actions N" (with N being a whole number, starting from 2) and "Hosted Agent".
# Here, we're using these names as long as time as seeds to start the random number generator.
# Name fraction is used for runners inside the same matrix, time fraction is used for runners in different runs.
# To avoid collision when the same runners are fired in different commits at the same time we also use GITHUB_SHA
random.seed(
    environ.get('RUNNER_NAME', 'local') + environ.get('GITHUB_SHA', 'local') + str(time.time_ns())
)


def generate_bucket_name() -> str:
    suffix_length = BUCKET_NAME_LENGTH - len(BUCKET_NAME_PREFIX)
    suffix = ''.join(random.choice(BUCKET_NAME_CHARS) for _ in range(suffix_length))
    return f"{BUCKET_NAME_PREFIX}{suffix}"


def current_time_millis() -> int:
    return int(round(time.time() * 1000))


class Api(BucketTrackingMixin, B2Api):
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
        print('Creating bucket:', bucket_name)
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
                    print('Removing retention from file version:', file_version_info.id_)
                    self.update_file_retention(
                        file_version_info.id_, file_version_info.file_name,
                        NO_RETENTION_FILE_SETTING, True
                    )
                elif file_version_info.file_retention.mode == RetentionMode.COMPLIANCE:
                    if file_version_info.file_retention.retain_until > current_time_millis():  # yapf: disable
                        print(
                            'File version: %s cannot be removed due to compliance mode retention' %
                            (file_version_info.id_,)
                        )
                        files_leftover = True
                        continue
                elif file_version_info.file_retention.mode == RetentionMode.NONE:
                    pass
                else:
                    raise ValueError(
                        'Unknown retention mode: %s' % (file_version_info.file_retention.mode,)
                    )
            if file_version_info.legal_hold.is_on():
                print('Removing legal hold from file version:', file_version_info.id_)
                self.update_file_legal_hold(
                    file_version_info.id_, file_version_info.file_name, LegalHold.OFF
                )
            print('Removing file version:', file_version_info.id_)
            try:
                self.delete_file_version(file_version_info.id_, file_version_info.file_name)
            except FileNotPresent:
                print(
                    'It seems that file version %s has already been removed' %
                    (file_version_info.id_,)
                )

        if files_leftover:
            print('Unable to remove bucket because some retained files remain')
        else:
            print('Removing bucket:', bucket.name)
            try:
                self.delete_bucket(bucket)
            except BucketIdNotFound:
                print('It seems that bucket %s has already been removed' % (bucket.name,))
        print()

    def clean_buckets(self) -> None:
        for bucket in self.buckets:
            with contextlib.suppress(BucketIdNotFound, v3BucketIdNotFound, NonExistentBucket):
                self.clean_bucket(bucket)
        self.buckets = []

    def clean_all_buckets(self) -> None:
        buckets = self.list_buckets()
        print(f'Total bucket count: {len(buckets)}')

        for bucket in buckets:
            if not bucket.name.startswith(BUCKET_NAME_PREFIX):
                print(f'Skipping bucket removal: "{bucket.name}"')
                continue

            print(f'Removing bucket: "{bucket.name}"')
            try:
                self.clean_bucket(bucket)
            except (BucketIdNotFound, v3BucketIdNotFound):
                print(f'It seems that bucket "{bucket.name}" has already been removed')

        buckets = self.list_buckets()
        print(f'Total bucket count after cleanup: {len(buckets)}')
        for bucket in buckets:
            print(bucket)

    def count_and_print_buckets(self) -> int:
        buckets = self.list_buckets()
        count = len(buckets)
        print(f'Total bucket count at {datetime.now()}: {count}')
        for i, bucket in enumerate(buckets, start=1):
            print(f'- {i}\t{bucket.name} [{bucket.id_}]')
        return count

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
