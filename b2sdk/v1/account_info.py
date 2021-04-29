######################################################################
#
# File: b2sdk/v1/account_info.py
#
# Copyright 2021 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
import inspect
from typing import Optional

from b2sdk import _v2 as v2
from b2sdk.account_info.sqlite_account_info import DEFAULT_ABSOLUTE_MINIMUM_PART_SIZE


# Retain legacy get_minimum_part_size and translate legacy "minimum_part_size" to new style "recommended_part_size"
class OldAccountInfoMethods:
    def set_auth_data(
        self,
        account_id,
        auth_token,
        api_url,
        download_url,
        minimum_part_size,
        application_key,
        realm,
        allowed=None,
        application_key_id=None,
        s3_api_url=None,
    ):

        if 's3_api_url' in inspect.getfullargspec(super()._set_auth_data).args:
            s3_kwargs = dict(s3_api_url=s3_api_url)
        else:
            s3_kwargs = {}

        if allowed is None:
            allowed = self.DEFAULT_ALLOWED
        assert self.allowed_is_valid(allowed)

        self._set_auth_data(
            account_id=account_id,
            auth_token=auth_token,
            api_url=api_url,
            download_url=download_url,
            minimum_part_size=minimum_part_size,
            application_key=application_key,
            realm=realm,
            allowed=allowed,
            application_key_id=application_key_id,
            **s3_kwargs,
        )

    def _set_auth_data(
            self, account_id, auth_token, api_url, download_url, minimum_part_size,
            application_key, realm, s3_api_url=None, allowed=None, application_key_id=None
    ):
        if 's3_api_url' in inspect.getfullargspec(super()._set_auth_data).args:
            s3_kwargs = dict(s3_api_url=s3_api_url)
        else:
            s3_kwargs = {}
        return super()._set_auth_data(
            account_id=account_id,
            auth_token=auth_token,
            api_url=api_url,
            download_url=download_url,
            recommended_part_size=minimum_part_size,
            absolute_minimum_part_size=DEFAULT_ABSOLUTE_MINIMUM_PART_SIZE,
            application_key=application_key,
            realm=realm,
            allowed=allowed,
            application_key_id=application_key_id,
            **s3_kwargs,
        )

    def get_minimum_part_size(self):
        return self.get_recommended_part_size()


class AbstractAccountInfo(OldAccountInfoMethods, v2.AbstractAccountInfo):
    def get_s3_api_url(self):
        """
        Return s3_api_url or raises MissingAccountData exception.

        :rtype: str
        """
        # Removed @abstractmethod decorators

    def get_bucket_name_or_none_from_bucket_id(self, bucket_id: str) -> Optional[str]:
        """
        Look up the bucket name for the given bucket id.
        """
        # Removed @abstractmethod decorator


class InMemoryAccountInfo(OldAccountInfoMethods, v2.InMemoryAccountInfo):
    pass


class UrlPoolAccountInfo(OldAccountInfoMethods, v2.UrlPoolAccountInfo):
    pass


class SqliteAccountInfo(OldAccountInfoMethods, v2.SqliteAccountInfo):
    pass


class StubAccountInfo(OldAccountInfoMethods, v2.StubAccountInfo):
    pass
