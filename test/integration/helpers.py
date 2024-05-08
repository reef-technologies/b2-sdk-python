######################################################################
#
# File: test/integration/helpers.py
#
# Copyright 2022 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
from __future__ import annotations

import os
import secrets

from b2sdk._internal.file_lock import NO_RETENTION_FILE_SETTING, LegalHold, RetentionMode
from b2sdk._internal.utils import current_time_millis
from b2sdk.v2 import (
    BUCKET_NAME_CHARS_UNIQ,
    BUCKET_NAME_LENGTH_RANGE,
    DEFAULT_HTTP_API_CONFIG,
    B2Api,
    InMemoryAccountInfo,
)

GENERAL_BUCKET_NAME_PREFIX = 'sdktst'
BUCKET_NAME_LENGTH = BUCKET_NAME_LENGTH_RANGE[1]
BUCKET_CREATED_AT_MILLIS = 'created_at_millis'

RNG = secrets.SystemRandom()


def _bucket_name_prefix_part(length: int) -> str:
    return ''.join(RNG.choice(BUCKET_NAME_CHARS_UNIQ) for _ in range(length))


def get_bucket_name_prefix(rnd_len: int = 8) -> str:
    return GENERAL_BUCKET_NAME_PREFIX + _bucket_name_prefix_part(rnd_len)


def random_bucket_name(prefix: str = GENERAL_BUCKET_NAME_PREFIX) -> str:
    return prefix + _bucket_name_prefix_part(BUCKET_NAME_LENGTH - len(prefix))


def authorize(b2_auth_data, api_config=DEFAULT_HTTP_API_CONFIG):
    info = InMemoryAccountInfo()
    b2_api = B2Api(info, api_config=api_config)
    realm = os.environ.get('B2_TEST_ENVIRONMENT', 'production')
    b2_api.authorize_account(realm, *b2_auth_data)
    return b2_api, info


def raw_delete_file(version_dict, raw_api, api_url, account_auth_token):
    """Deletes files, cancels if file is large in progress, removes locks, holds, hides and everything
    """
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


def delete_file(file_version, b2_api, logger) -> bool:
    """Returns True if deletion was successful and False if file remained due to compliance mode retention"""
    if file_version.file_retention:
        if file_version.file_retention.mode == RetentionMode.GOVERNANCE:
            logger.info('Removing retention from file version: %s', file_version.id_)
            b2_api.update_file_retention(
                file_version.id_, file_version.file_name, NO_RETENTION_FILE_SETTING, True
            )
        elif file_version.file_retention.mode == RetentionMode.COMPLIANCE:
            if file_version.file_retention.retain_until > current_time_millis():  # yapf: disable
                logger.info(
                    'File version: %s cannot be removed due to compliance mode retention',
                    file_version.id_,
                )
                return False
        elif file_version.file_retention.mode == RetentionMode.NONE:
            pass
        else:
            raise ValueError(f'Unknown retention mode: {file_version.file_retention.mode}')
    if file_version.legal_hold.is_on():
        logger.info('Removing legal hold from file version: %s', file_version.id_)
        b2_api.update_file_legal_hold(file_version.id_, file_version.file_name, LegalHold.OFF)
    logger.info('Removing file version:', file_version.id_)
    b2_api.delete_file_version(file_version.id_, file_version.file_name)
    return True


def write_zeros(file, number):
    line = b'0' * 1000 + b'\n'
    line_len = len(line)
    written = 0
    while written <= number:
        file.write(line)
        written += line_len
