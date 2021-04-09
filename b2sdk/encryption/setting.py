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
import hashlib
import logging
from typing import Optional

from ..utils import b64_of_bytes, md5_of_bytes
from .types import ENCRYPTION_MODES_WITH_MANDATORY_ALGORITHM, ENCRYPTION_MODES_WITH_MANDATORY_KEY
from .types import EncryptionAlgorithm, EncryptionMode

logger = logging.getLogger(__name__)


class EncryptionKey:
    """
    Hold information about encryption key: the key itself, and its id. The id may be None, if it's not set
    in encrypted file's fileInfo. The secret may be None, if encryption metadata is read from the server.
    """
    secret_repr = '******'
    def __init__(self, secret: Optional[bytes], id: Optional[str]):
        self.secret = secret
        self.id = id

    def __eq__(self, other):
        return self.secret == other.secret and self.id == other.id

    def __repr__(self):
        key_repr = self.secret_repr
        if self.secret is None:
            key_repr = None
        return '<%s(%s, %s)>' % (self.__class__.__name__, key_repr, self.id)

    def key_b64(self):
        return b64_of_bytes(self.secret)

    def key_md5(self):
        return b64_of_bytes(md5_of_bytes(self.secret))


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
    ):
        """
        :param b2sdk.v1.EncryptionMode mode: encryption mode
        :param b2sdk.v1.EncryptionAlgorithm algorithm: encryption algorithm
        :param b2sdk.v1.EncryptionKey key: encryption key object for SSE-C
        """
        self.mode = mode
        self.algorithm = algorithm
        self.key = key
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
        Dump EncryptionSetting as dict for serializing a to json for requests.
        """
        if self.key and self.key.secret is None:
            raise ValueError('cannot use an unknown key in transmission')
        return self.repr_as_dict()

    def repr_as_dict(self):
        """
        Dump EncryptionSetting as dict for representing.
        """
        result = {'mode': self.mode.value}
        if self.algorithm is not None:
            result['algorithm'] = self.algorithm.value
        if self.mode == EncryptionMode.SSE_C:
            if self.key.secret is None:
                result['customerKey'] = EncryptionKey.secret_repr
                result['customerKeyMd5'] = EncryptionKey.secret_repr
            else:
                result['customerKey'] = self.key.key_b64()
                result['customerKeyMd5'] = self.key.key_md5()
        return result

    def add_to_upload_headers(self, headers):
        if self.mode == EncryptionMode.NONE:
            # as of 2021-03-16, server always fails it
            headers['X-Bz-Server-Side-Encryption'] = self.mode.name
        elif self.mode == EncryptionMode.SSE_B2:
            headers['X-Bz-Server-Side-Encryption'] = self.algorithm.name
        elif self.mode == EncryptionMode.SSE_C:
            if self.key.secret is None:
                raise ValueError('Cannot use an unknown key in upload headers')
            headers['X-Bz-Server-Side-Encryption-Customer-Algorithm'] = self.algorithm.name
            headers['X-Bz-Server-Side-Encryption-Customer-Key'] = self.key.key_b64()
            headers['X-Bz-Server-Side-Encryption-Customer-Key-Md5'] = self.key.key_md5()
            headers['X-Bz-Info-sse-c-key-id'] = self.key.id
        else:
            raise NotImplementedError('unsupported encryption setting: %s' % (self,))

    def add_to_download_headers(self, headers):
        if self.mode == EncryptionMode.NONE:
            return
        elif self.mode == EncryptionMode.SSE_B2:
            headers['X-Bz-Server-Side-Encryption'] = self.algorithm.name
        elif self.mode == EncryptionMode.SSE_C:
            if self.key.secret is None:
                raise ValueError('Cannot use an unknown key in upload headers')
            headers['X-Bz-Server-Side-Encryption-Customer-Algorithm'] = self.algorithm.name
            headers['X-Bz-Server-Side-Encryption-Customer-Key'] = self.key.key_b64()
            headers['X-Bz-Server-Side-Encryption-Customer-Key-Md5'] = self.key.key_md5()
        else:
            raise NotImplementedError('unsupported encryption setting: %s' % (self,))

    def add_key_id_to_file_info(self, file_info: Optional[dict]):
        if self.key is None or self.key.id is None:
            return file_info
        if file_info is None:
            file_info = {}
        file_info['sse_c_key_id'] = self.key.id
        return file_info

    def __repr__(self):
        return '<%s(%s, %s, %s)>' % (self.__class__.__name__, self.mode, self.algorithm, self.key)


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
            "fileInfo": {"sse_c_key_id": "key-identifier"}
            ...

        """
        sse = file_version_dict.get('serverSideEncryption')
        if sse is None:
            return EncryptionSetting(EncryptionMode.NONE)
        key_id = None
        file_info = file_version_dict.get('fileInfo')
        if file_info is not None:
            key_id = file_info.get('sse_c_key_id')

        return cls._from_value_dict(sse, key_id=key_id)

    @classmethod
    def from_bucket_dict(cls, bucket_dict: dict) -> Optional[EncryptionSetting]:
        """
        Returns EncryptionSetting for the given bucket dict retrieved from the api, or None if unauthorized

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
    def _from_value_dict(cls, value_dict, key_id=None):
        kwargs = {}
        if value_dict is None:
            kwargs['mode'] = EncryptionMode.NONE
        else:
            mode = EncryptionMode(value_dict['mode'])
            kwargs['mode'] = mode

            algorithm = value_dict.get('algorithm')
            if algorithm is not None:
                kwargs['algorithm'] = EncryptionAlgorithm(algorithm)

            if mode == EncryptionMode.SSE_C:
                kwargs['key'] = EncryptionKey(id=key_id, secret=None)

        return EncryptionSetting(**kwargs)

    @classmethod
    def from_response_headers(cls, headers):

        mode = EncryptionMode(headers.get('X-Bz-Server-Side-Encryption', 'none'))
        kwargs = {
            'mode': mode,
        }
        if mode == EncryptionMode.SSE_C:
            kwargs['key'] = EncryptionKey(secret=None, id=None)
        algorithm = headers.get('X-Bz-Server-Side-Encryption-Customer-Algorithm')
        if algorithm is not None:
            kwargs['algorithm'] = EncryptionAlgorithm(algorithm)

        return EncryptionSetting(**kwargs)
