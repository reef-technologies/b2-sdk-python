######################################################################
#
# File: b2sdk/v1/api.py
#
# Copyright 2021 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

from typing import Any, Dict, Optional
from b2sdk import _v2 as v2
from b2sdk.api import Services
from .account_info import AbstractAccountInfo
from .bucket import Bucket, BucketFactory
from .cache import AbstractCache
from .file_version import FileVersionInfo, FileVersionInfoFactory, file_version_info_from_id_and_name
from .session import B2Session


# override to use legacy no-request method of creating a bucket from bucket_id and retain `check_bucket_restrictions`
# public API method
# and to use v1.Bucket
# and to retain cancel_large_file return type
# and to retain old style get_file_info return type
# and to accept old-style raw_api argument
class B2Api(v2.B2Api):
    SESSION_CLASS = staticmethod(B2Session)
    BUCKET_FACTORY_CLASS = staticmethod(BucketFactory)
    BUCKET_CLASS = staticmethod(Bucket)
    FILE_VERSION_FACTORY_CLASS = staticmethod(FileVersionInfoFactory)

    def __init__(
        self,
        account_info: Optional[AbstractAccountInfo] = None,
        cache: Optional[AbstractCache] = None,
        max_upload_workers: int = 10,
        max_copy_workers: int = 10,
        raw_api: v2.B2RawHTTPApi = None,
        api_config: Optional[v2.B2HttpApiConfig] = None,
    ):
        """
        Initialize the API using the given account info.

        :param account_info: To learn more about Account Info objects, see here
                      :class:`~b2sdk.v1.SqliteAccountInfo`

        :param cache: It is used by B2Api to cache the mapping between bucket name and bucket ids.
                      default is :class:`~b2sdk.cache.DummyCache`

        :param max_upload_workers: a number of upload threads
        :param max_copy_workers: a number of copy threads
        :param raw_api:
        :param api_config:
        """
        self.session = self.SESSION_CLASS(
            account_info=account_info,
            cache=cache,
            raw_api=raw_api,
            api_config=api_config,
        )
        self.file_version_factory = self.FILE_VERSION_FACTORY_CLASS(self)
        self.services = Services(
            self,
            max_upload_workers=max_upload_workers,
            max_copy_workers=max_copy_workers,
        )

    def get_file_info(self, file_id: str) -> Dict[str, Any]:
        """
        Gets info about file version.

        :param str file_id: the id of the file who's info will be retrieved.
        """
        return self.session.get_file_info_by_id(file_id)

    def get_bucket_by_id(self, bucket_id):
        """
        Return a bucket object with a given ID.  Unlike ``get_bucket_by_name``, this method does not need to make any API calls.

        :param str bucket_id: a bucket ID
        :return: a Bucket object
        :rtype: b2sdk.v1.Bucket
        """
        return self.BUCKET_CLASS(self, bucket_id)

    def check_bucket_restrictions(self, bucket_name):
        """
        Check to see if the allowed field from authorize-account has a bucket restriction.

        If it does, checks if the bucket_name for a given api call matches that.
        If not, it raises a :py:exc:`b2sdk.v1.exception.RestrictedBucket` error.

        :param str bucket_name: a bucket name
        :raises b2sdk.v1.exception.RestrictedBucket: if the account is not allowed to use this bucket
        """
        self.check_bucket_name_restrictions(bucket_name)

    def cancel_large_file(self, file_id: str) -> FileVersionInfo:
        file_id_and_name = super().cancel_large_file(file_id)
        return file_version_info_from_id_and_name(file_id_and_name, self)
