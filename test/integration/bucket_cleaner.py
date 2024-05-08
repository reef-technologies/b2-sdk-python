######################################################################
#
# File: test/integration/bucket_cleaner.py
#
# Copyright 2022 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
from __future__ import annotations

import logging

from b2sdk.v2 import (
    B2Api,
    Bucket,
    current_time_millis,
)
from b2sdk.v2.exception import BadRequest

from .helpers import BUCKET_CREATED_AT_MILLIS, GENERAL_BUCKET_NAME_PREFIX, delete_file

ONE_HOUR_MILLIS = 60 * 60 * 1000

logger = logging.getLogger(__name__)


class BucketCleaner:
    def __init__(
        self, dont_cleanup_old_buckets: bool, b2_api: B2Api, current_run_prefix: str | None = None
    ):
        self.current_run_prefix = current_run_prefix
        self.dont_cleanup_old_buckets = dont_cleanup_old_buckets
        self.b2_api = b2_api

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
        buckets = self.b2_api.list_buckets()
        for bucket in buckets:
            self.cleanup_bucket(bucket)

    def cleanup_bucket(self, bucket: Bucket):
        b2_api = self.b2_api
        if not self._should_remove_bucket(bucket):
            logger.info('Skipping bucket removal:', bucket.name)
            return

        logger.info('Trying to remove bucket:', bucket.name)
        try:
            b2_api.delete_bucket(bucket)
            return
        except BadRequest:
            logger.info('Bucket is not empty, removing files')

        files_remained = False

        for file_version, _ in bucket.ls(latest_only=False, recursive=True):
            if not delete_file(file_version, b2_api, logger):
                files_remained = True

        if files_remained:
            logger.info('Unable to remove bucket because some retained files remain')
            return

        b2_api.delete_bucket(bucket)
        logger.info('Removed bucket:', bucket.name)
