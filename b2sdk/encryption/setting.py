######################################################################
#
# File: b2sdk/encryption/setting.py
#
# Copyright 2021 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

import base64
import binascii
import hashlib
import logging
from typing import Optional

from ..utils import hex_md5_of_bytes
from .types import ENCRYPTION_MODES_WITH_MANDATORY_ALGORITHM, ENCRYPTION_MODES_WITH_MANDATORY_KEY
from .types import EncryptionAlgorithm, EncryptionKey, EncryptionMode

logger = logging.getLogger(__name__)

UNKNOWN_KEY = 'UNKNOWN_KEY'  # EncryptionSetting.key for EncryptionSetting created from server response


class EncryptionSetting:
    """
    Hold information about encryption mode, algorithm and key (for bucket default,
    file version info or even upload)
    """

    def __init__(
        self,
        mode: EncryptionMode,
        algorithm: EncryptionAlgorithm = None,
        key: EncryptionKey = None,
        key_hex: str = None,
        key_id: Optional[str] = None,
    ):
        """
        :param b2sdk.v1.EncryptionMode mode: encryption mode
        :param b2sdk.v1.EncryptionAlgorithm algorithm: encryption algorithm
        :param b2sdk.v1.EncryptionKey key: encryption key object for SSE-C
        :param str key_hex: hex form of encryption key object for SSE-C, used interchangebly with :param key
        :param str key_id: encryption key id for SSE-C, stored in fileInfo
        """
        self.mode = mode
        self.algorithm = algorithm
        if key is not None and key_hex is not None:
            raise ValueError("can only specify 'key' or 'key_hex', not both")
        if key_hex is not None:
            key = binascii.unhexlify(key_hex)
        self.key = key
        self.key_id = key_id
        if self.mode == EncryptionMode.NONE and (self.algorithm or self.key):
            raise ValueError("cannot specify algorithm or key for 'plaintext' encryption mode")
        if self.mode in ENCRYPTION_MODES_WITH_MANDATORY_ALGORITHM and not self.algorithm:
            raise ValueError('must specify algorithm for encryption mode %s' % (self.mode,))
        if self.mode in ENCRYPTION_MODES_WITH_MANDATORY_KEY and not self.key:
            raise ValueError(
                'must specify key for encryption mode %s and algorithm %s' %
                (self.mode, self.algorithm)
            )

    def __eq__(self, other):
        if other is None:
            raise ValueError('cannot compare a known encryption setting to an unknown one')
        return self.mode == other.mode and self.algorithm == other.algorithm and self.key == other.key

    def as_value_dict(self):
        """
        Dump EncryptionSetting as dict for serializing a to json for requests
        :return: dict
        """
        if self.key == UNKNOWN_KEY:
            raise ValueError('cannot use UNKNOWN_KEY in transmission')
        return self.repr_as_dict()

    def repr_as_dict(self):
        """
        Dump EncryptionSetting as dict for representing
        :return: dict
        """
        result = {'mode': self.mode.value}
        if self.algorithm is not None:
            result['algorithm'] = self.algorithm.value
        if self.mode == EncryptionMode.SSE_C:
            if self.key == UNKNOWN_KEY:
                result['customerKey'] = self.key
                result['customerKeyMd5'] = ''
            else:
                result['customerKey'] = self._key_b64()
                result['customerKeyMd5'] = self._key_md5()
        return result

    def add_to_upload_headers(self, headers):
        if self.mode == EncryptionMode.NONE:
            # as of 2021-03-16, server always fails it
            headers['X-Bz-Server-Side-Encryption'] = self.mode.name
        elif self.mode == EncryptionMode.SSE_B2:
            headers['X-Bz-Server-Side-Encryption'] = self.algorithm.name
        elif self.mode == EncryptionMode.SSE_C:
            if self.key == UNKNOWN_KEY:
                raise ValueError('Cannot use UNKOWN_KEY in upload headers')
            headers['X-Bz-Server-Side-Encryption-Customer-Algorithm'] = self.algorithm.name
            headers['X-Bz-Server-Side-Encryption-Customer-Key'] = self._key_b64()
            headers['X-Bz-Server-Side-Encryption-Customer-Key-Md5'] = self._key_md5()
            headers['X-Bz-Info-sse-c-key-id'] = self.key_id
        else:
            raise NotImplementedError('unsupported encryption setting: %s' % (self,))

    def add_to_download_headers(self, headers):
        if self.mode == EncryptionMode.NONE:
            return
        elif self.mode == EncryptionMode.SSE_B2:
            headers['X-Bz-Server-Side-Encryption'] = self.algorithm.name
        elif self.mode == EncryptionMode.SSE_C:
            if self.key == UNKNOWN_KEY:
                raise ValueError('Cannot use UNKOWN_KEY in upload headers')
            headers['X-Bz-Server-Side-Encryption-Customer-Algorithm'] = self.algorithm.name
            headers['X-Bz-Server-Side-Encryption-Customer-Key'] = self._key_b64()
            headers['X-Bz-Server-Side-Encryption-Customer-Key-Md5'] = self._key_md5()
        else:
            raise NotImplementedError('unsupported encryption setting: %s' % (self,))

    def __repr__(self):
        key_repr = '******'
        if self.key is None:
            key_repr = None
        if self.key == UNKNOWN_KEY:
            key_repr = 'Unknown Key'
        return '<%s(%s, %s, %s)>' % (self.__class__.__name__, self.mode, self.algorithm, key_repr)

    def _key_b64(self):
        return base64.b64encode(self.key).decode()

    def _key_md5(self):
        return base64.b64encode(hashlib.md5(self.key).digest()).decode()


class EncryptionSettingFactory:
    # 2021-03-17: for the bucket the response of the server is:
    # if authorized to read:
    #    "mode": "none"
    #    or
    #    "mode": "SSE-B2"
    # if not authorized to read:
    #    isClientAuthorizedToRead is False and there is no value, so no mode
    #
    # BUT file_version_info (get_file_info, list_file_versions, upload_file etc)
    # if the file is encrypted, then
    #     "serverSideEncryption": {"algorithm": "AES256", "mode": "SSE-B2"},
    #     or
    #     "serverSideEncryption": {"algorithm": "AES256", "mode": "SSE-C"},
    # if the file is not encrypted, then "serverSideEncryption" is not present at all
    @classmethod
    def from_file_version_dict(cls, file_version_dict: dict) -> EncryptionSetting:
        """
        Returns EncryptionSetting for the given file_version_dict retrieved from the api

        .. code-block:: python

            ...
            "serverSideEncryption": {"algorithm": "AES256", "mode": "SSE-B2"},
            ...

        """
        sse = file_version_dict.get('serverSideEncryption')
        if sse is None:
            return EncryptionSetting(EncryptionMode.NONE)
        return cls._from_value_dict(sse)

    @classmethod
    def from_bucket_dict(cls, bucket_dict: dict) -> Optional[EncryptionSetting]:
        """
        Returns EncryptionSetting for the given bucket dict retrieved from the api, or None if unautorized

        Example inputs:

        .. code-block:: python

            ...
            "defaultServerSideEncryption": {
                "isClientAuthorizedToRead" : true,
                "value": {
                  "algorithm" : "AES256",
                  "mode" : "SSE-B2"
                }
            }
            ...

        unset:

        .. code-block:: python

             ...
            "defaultServerSideEncryption": {
                "isClientAuthorizedToRead" : true,
                "value": {
                  "mode" : "none"
                }
            }
            ...

        unknown:

        .. code-block:: python

            ...
            "defaultServerSideEncryption": {
                "isClientAuthorizedToRead" : false
            }
            ...

        """
        default_sse = bucket_dict.get(
            'defaultServerSideEncryption',
            {'isClientAuthorizedToRead': False},
        )

        if not default_sse['isClientAuthorizedToRead']:
            return EncryptionSetting(EncryptionMode.UNKNOWN)

        assert 'value' in default_sse
        return cls._from_value_dict(default_sse['value'])

    @classmethod
    def _from_value_dict(cls, value_dict):
        kwargs = {}
        if value_dict is None:
            kwargs['mode'] = EncryptionMode.NONE
        else:
            kwargs['mode'] = EncryptionMode(value_dict['mode'])

            algorithm = value_dict.get('algorithm')
            if algorithm is not None:
                kwargs['algorithm'] = EncryptionAlgorithm(algorithm)

        return cls._from_server_response(**kwargs)

    @classmethod
    def from_response_headers(cls, headers):
        kwargs = {
            'mode': EncryptionMode(headers.get('X-Bz-Server-Side-Encryption', 'none'),),
        }
        algorithm = headers.get('X-Bz-Server-Side-Encryption-Customer-Algorithm')
        if algorithm is not None:
            kwargs['algorithm'] = EncryptionAlgorithm(algorithm)

        return cls._from_server_response(**kwargs)

    @classmethod
    def _from_server_response(cls, mode=None, **kwargs):
        if mode == EncryptionMode.SSE_C:
            kwargs['key'] = UNKNOWN_KEY
        return EncryptionSetting(**kwargs, mode=mode)
