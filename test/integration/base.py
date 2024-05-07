######################################################################
#
# File: test/integration/base.py
#
# Copyright 2022 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
from __future__ import annotations

import hashlib
import logging
import os
import posixpath
import random
import re
import string
import time
from abc import ABC, abstractmethod
from test.integration.helpers import (
    BUCKET_CREATED_AT_MILLIS,
    GENERAL_BUCKET_NAME_PREFIX,
    delete_file,
    raw_delete_file,
)
from typing import Generator

import pytest

from b2sdk._internal.bucket import Bucket
from b2sdk._internal.raw_api import B2RawHTTPApi
from b2sdk._internal.utils import current_time_millis
from b2sdk.v2 import B2Api

logger = logging.getLogger(__name__)

# Path to a file containing some random data that will be used to generate
# a name for singlebucket, for local development

SINGLEBUCKET_STRING_PATH = ".singlebucket_local_dev_config"


@pytest.mark.usefixtures("cls_setup")
class IntegrationTestBase:
    test_prefix: str
    b2_api: B2Api
    single_bucket: NonRawSingleBucket

    @pytest.fixture(autouse=True, scope="class")
    def cls_setup(self, request, b2_api, b2_auth_data, bucket_name_prefix):
        cls = request.cls
        cls.b2_auth_data = b2_auth_data
        cls.b2_api = b2_api
        cls.info = b2_api.account_info
        cls.single_bucket = NonRawSingleBucket(cls.b2_api, cls.test_prefix)


class AbstractSingleBucket(ABC):
    """Access to a bucket that persists across tests, one per repository

    Inside this bucket test separate their files using "directories".
    This does not handle bucket operations, so it does not guard against
    tests creating files outside their "directory",
    it just allows for prepending filenames with a "directory".
    """
    account_id: str
    bucket_id: str
    bucket_dict: dict

    def __init__(self, test_prefix, bucket_infix="sb"):
        self.test_prefix = test_prefix
        self.current_test_prefix = f"{test_prefix}-{''.join(random.choices(string.ascii_letters, k=4))}-{int(time.time())}"
        self.bucket_name = self.get_bucket_name(bucket_infix)

    @staticmethod
    def _create_local_dev_string_if_not_exists():
        if not os.path.isfile(SINGLEBUCKET_STRING_PATH):
            with open(SINGLEBUCKET_STRING_PATH, "w", encoding="UTF-8") as f:
                f.write(
                    "Contents of this file, when running integration tests locally, are used to create a short digest, "
                    "which is included in the name of the test buckets.\n"
                )
                f.write(''.join(random.choices(string.ascii_letters, k=64)))

    def get_bucket_name(self, bucket_infix):
        """Get a bucket name from:
        general bucket name prefix - used by every integration test
        bucket infix - from this class
        digest - digest is based either
            1) on git remote origin url when running in Ci - github actions
            2) on a random string stored in a persistent file - local development
        account_id - from this class
        """
        template = f"{GENERAL_BUCKET_NAME_PREFIX}-{bucket_infix}-{{digest}}-{self.account_id}"

        if 'GITHUB_ACTIONS' in os.environ:
            return template.format(
                digest=hashlib.sha256(
                    os.popen("git remote get-url origin").read().strip().encode("UTF-8")
                ).hexdigest()[:12]
            )

        # not in GitHub CI
        self._create_local_dev_string_if_not_exists()

        # get short digest from it
        with open(SINGLEBUCKET_STRING_PATH, "rb") as f:
            return template.format(digest=hashlib.sha256(f.read()).hexdigest()[:12])

    def get_path_for_current_test(self, file_name):
        return posixpath.join(self.current_test_prefix, file_name)

    @staticmethod
    @abstractmethod
    def get_file_name(file_version) -> str:
        pass

    def iter_test_files(self, file_versions: dict) -> Generator:
        return filter(
            lambda fv: self.get_file_name(fv).startswith(self.current_test_prefix), file_versions
        )

    def _match_old_file(self, file_version):
        match = re.match(fr'^{self.test_prefix}([0-9]+)', self.get_file_name(file_version))
        if match is None:
            return False

        # Is it more than an hour old?
        bucket_time = int(match.group(1))
        now = time.time()
        return bucket_time + 3600 <= now

    def clean_test_files(self, dont_cleanup_old_files):
        """Cleans files in bucket created by test with current_test_prefix
        If dont_cleanup_old_files is False will also clean files with matching test_prefix that are older than 1 hr
        """
        for file_version in self.get_matching_file_versions(
            lambda fv: self.get_file_name(fv).startswith(self.current_test_prefix)
        ):
            self.delete_file(file_version)

        if dont_cleanup_old_files:
            return

        for file_version in self.get_matching_file_versions(self._match_old_file):
            self.delete_file(file_version)

    def clear_entire_bucket(self):
        """Cleans every file in bucket"""
        for file_version in self.get_matching_file_versions(lambda _: True):
            self.delete_file(file_version)

    @abstractmethod
    def get_or_create_bucket(self):
        pass

    @abstractmethod
    def get_matching_file_versions(self, condition):
        pass

    @abstractmethod
    def delete_file(self, version_dict):
        pass


class RawSingleBucket(AbstractSingleBucket):
    """AbstractSingleBucket implemented for raw_api test"""

    def __init__(self, raw_api: B2RawHTTPApi, auth_dict, test_prefix, bucket_infix="sb"):
        """Create a Single Bucket for use across tests. Access to B2 is by B2RawHTTPApi.
        test_prefix is used as a folder name INSIDE bucket
        bucket_infix can be specified by tests which need to use a different bucket from other tests"""
        self.raw_api = raw_api
        self.api_url = auth_dict["apiUrl"]
        self.account_id = auth_dict["accountId"]
        self.account_auth_token = auth_dict["authorizationToken"]

        super().__init__(test_prefix, bucket_infix=bucket_infix)

        self.bucket_dict = self.get_or_create_bucket()
        self.bucket_id = self.bucket_dict["bucketId"]

    def get_or_create_bucket(self):
        buckets = self.raw_api.list_buckets(self.api_url, self.account_auth_token,
                                            self.account_id)["buckets"]

        for bucket_dict in buckets:
            if bucket_dict["bucketName"] == self.bucket_name:
                return bucket_dict

        return self.raw_api.create_bucket(
            self.api_url,
            self.account_auth_token,
            self.account_id,
            self.bucket_name,
            'allPublic',
            is_file_lock_enabled=True,  #  TODO: should it be True?
        )

    @staticmethod
    def get_file_name(file_version) -> str:
        return file_version["fileName"]

    def get_matching_file_versions(self, condition):
        files = self.raw_api.list_file_versions(
            self.api_url, self.account_auth_token, self.bucket_dict["bucketId"]
        )['files']
        return filter(condition, files)

    def delete_file(self, version_dict):
        raw_delete_file(version_dict, self.raw_api, self.api_url, self.account_auth_token)


class NonRawSingleBucket(AbstractSingleBucket):
    """AbstractSingleBucket implemented for non-raw api test"""
    bucket: Bucket

    def __init__(self, b2_api: B2Api, test_prefix):
        """Create a Single Bucket for use across tests. Access to B2 is by B2Api.
        test_prefix is used as a folder name INSIDE bucket
        """
        self.b2_api = b2_api
        self.account_id = b2_api.account_info._account_id

        super().__init__(test_prefix)

        self.bucket = self.get_or_create_bucket()
        self.bucket_dict = self.bucket.as_dict()
        self.bucket_id = self.bucket_dict["bucketId"]

    def get_or_create_bucket(self):
        for bucket in self.b2_api.list_buckets():
            if bucket.name == self.bucket_name:
                return bucket

        return self.b2_api.create_bucket(
            self.bucket_name,
            'allPublic',
            bucket_info={BUCKET_CREATED_AT_MILLIS: str(current_time_millis())}
        )

    @staticmethod
    def get_file_name(file_version) -> str:
        return file_version.file_name

    def get_matching_file_versions(self, condition):
        file_versions = self.bucket.ls(recursive=True, latest_only=False)

        return filter(condition, (fv[0] for fv in file_versions))

    def delete_file(self, file_version):
        delete_file(file_version, self.b2_api, logger)
