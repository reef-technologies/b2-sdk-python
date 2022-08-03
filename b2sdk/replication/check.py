######################################################################
#
# File: b2sdk/replication/check.py
#
# Copyright 2022 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

import enum
import warnings

from dataclasses import dataclass
from typing import Dict, Generator, Optional, Tuple, Union

from b2sdk import version
from b2sdk.api import B2Api
from b2sdk.application_key import ApplicationKey
from b2sdk.bucket import Bucket, BucketFactory, BucketStructure
from b2sdk.exception import AccessDenied, BucketIdNotFound


class ReplicationFilter:
    def __init__(self, source_api: B2Api, destination_api: B2Api, filters: ...):
        self.source_api = source_api
        self.destination_api = destination_api

    # def get_checks


@dataclass
class TwoWayReplicationCheckGenerator:
    source_api: B2Api
    destination_api: B2Api
    filter_source_bucket_name: Optional[str] = None
    filter_destination_bucket_name: Optional[str] = None
    filter_replication_rule_name: Optional[str] = None
    file_name_prefix: Optional[str] = None

    def get_checks(self) -> Generator['ReplicationCheck']:
        source_buckets = self.source_api.list_buckets(bucket_name=self.filter_source_bucket_name)
        for source_bucket in source_buckets:
            yield from self.get_source_bucket_checks()

    def get_source_bucket_checks(self, source_bucket: Bucket) -> Generator['ReplicationCheck']:
        if not source_bucket.replication:
            return

        if not source_bucket.replication.rules:
            return

        source_key = _safe_get_key(self.source_api, source_bucket.replication.source_key_id)
        for rule in source_bucket.replication.rules:
            if (
                self.filter_replication_rule_name and rule.name != self.filter_replication_rule_name
            ):
                continue

            if self.file_name_prefix and rule.file_name_prefix != self.file_name_prefix:
                continue

            try:
                destination_bucket_list = self.destination_api.list_buckets(
                    bucket_id=rule.destination_bucket_id
                )
                if not destination_bucket_list:
                    raise BucketIdNotFound()
            except (AccessDenied, BucketIdNotFound):
                yield ReplicationSourceCheck.from_data(source_bucket, rule.replication_rule_name)
                continue

            if (
                self.filter_destination_bucket_name is not None and
                destination_bucket_list[0].name != self.filter_destination_bucket_name
            ):
                continue

            yield TwoWayReplicationCheck.from_data(
                source_bucket=source_bucket,
                replication_rule_name=rule.replication_rule_name,
                source_application_key=source_key,
                destination_bucket=destination_bucket_list[0],
                destination_application_keys=self._get_destination_bucket_keys(
                    destination_bucket_list[0]
                ),
            )

    @classmethod
    def _get_destination_bucket_keys(cls, destination_bucket: Bucket) -> \
            Dict[str, Union[None, ApplicationKey, 'AccessDeniedEnum']]:
        if not destination_bucket.replication:
            return {}

        key_ids = destination_bucket.replication.source_to_destination_key_mapping.values()
        try:
            return {key_id: destination_bucket.api.get_key(key_id) for key_id in key_ids}
        except AccessDenied:
            return dict.fromkeys(key_ids, AccessDeniedEnum.ACCESS_DENIED)


@enum.unique
class CheckState(enum.Enum):
    OK = 'ok'
    NOT_OK = 'not_ok'
    UNKNOWN = 'unknown'

    def is_ok(self):
        return self == self.OK

    @classmethod
    def from_bool(cls, value: bool) -> 'CheckState':
        return cls.OK if value else cls.NOT_OK


class AccessDeniedEnum(enum.Enum):
    ACCESS_DENIED = 'ACCESS_DENIED'


class ReplicationCheck:
    @classmethod
    def _check_key(
        cls,
        key: Union[Optional[ApplicationKey], AccessDeniedEnum],
        capability: str,
        replication_name_prefix: str,
        bucket_id: str,
    ) -> Tuple[CheckState, CheckState, CheckState, CheckState]:
        if key == AccessDeniedEnum.ACCESS_DENIED:
            return (CheckState.UNKNOWN,) * 4
        if key is None:
            return (CheckState.NOT_OK,) * 4
        return (
            CheckState.OK,
            CheckState.from_bool(key.bucket_id is None or key.bucket_id == bucket_id),
            CheckState.from_bool(capability in key.capabilities),
            CheckState.from_bool(
                key.name_prefix is None or replication_name_prefix.startswith(key.name_prefix)
            ),
        )


@dataclass
class ReplicationSourceCheck(ReplicationCheck):
    key_exists: CheckState
    key_read_capabilities: CheckState
    key_name_prefix_match: CheckState
    is_enabled: CheckState

    _bucket: Bucket
    _application_key: Union[None, AccessDeniedEnum, ApplicationKey]

    @classmethod
    def from_data(cls, bucket: Bucket, rule_name: str) -> 'ReplicationSourceCheck':
        kwargs = {
            '_bucket': bucket,
        }

        application_key = _safe_get_key(bucket.api, bucket.replication.source_key_id)
        kwargs['_application_key'] = application_key

        rules = [rule for rule in bucket.replication.rules if rule.name == rule_name]
        assert rules
        rule = rules[0]

        kwargs['is_enabled'] = rule.is_enabled

        (
            kwargs['key_exists'],
            _,  # kwargs['key_bucket_match'],
            kwargs['key_read_capabilities'],
            kwargs['key_name_prefix_match'],
        ) = cls._check_key(application_key, 'readFiles', rule.file_name_prefix, bucket.id_)

        return cls(**kwargs)

    def other_party_data(self):
        return OtherPartyReplicationCheckData(
            bucket=self._bucket,
            keys_mapping={self._bucket.replication.source_key_id: self._application_key},
        )


@dataclass
class ReplicationDestinationCheck:
    key_exist: Dict[str, CheckState]
    keys_write_capabilities: Dict[str, CheckState]
    keys_bucket_match: Dict[str, CheckState]

    _bucket: Bucket
    _keys: Dict[str, Union[Optional[ApplicationKey], AccessDeniedEnum]]

    @classmethod
    def from_data(cls, bucket: Bucket) -> 'ReplicationDestinationCheck':
        kwargs = {
            '_bucket': bucket,
            '_keys': {},
            'key_exist': {},
            'keys_write_capabilities': {},
            'keys_bucket_match': {},
        }

        keys_to_check = bucket.replication.source_to_destination_key_mapping.values()
        try:
            for key_id in keys_to_check:
                application_key = bucket.api.get_key(bucket.replication.source_key_id)
                kwargs['_keys'][key_id] = application_key

                if application_key:
                    kwargs['keys_exist'][key_id] = CheckState.OK
                    kwargs['keys_write_capabilities'][key_id] = CheckState.from_bool(
                        'writeFiles' in application_key.capabilities
                    )
                    kwargs['keys_bucket_match'][key_id] = CheckState.from_bool(
                        application_key.bucket_id is None or application_key.bucket_id == bucket.id_
                    )
                else:
                    kwargs['keys_exist'][key_id] = CheckState.NOT_OK
                    kwargs['keys_write_capabilities'][key_id] = CheckState.NOT_OK
                    kwargs['keys_bucket_match'][key_id] = CheckState.NOT_OK

        except AccessDenied:

            kwargs['_keys'] = dict.fromkeys(keys_to_check, None)
            kwargs['keys_exist'] = dict.fromkeys(keys_to_check, CheckState.UNKNOWN)
            kwargs['keys_write_capabilities'] = dict.fromkeys(keys_to_check, CheckState.UNKNOWN)
            kwargs['keys_bucket_match'] = dict.fromkeys(keys_to_check, CheckState.UNKNOWN)

        return cls(**kwargs)

    def other_party_data(self):
        return OtherPartyReplicationCheckData(
            bucket=self._bucket,
            keys_mapping=self._keys,
        )


@dataclass
class TwoWayReplicationCheck(ReplicationCheck):
    is_enabled: CheckState

    source_key_exists: CheckState
    source_key_bucket_match: CheckState
    source_key_read_capabilities: CheckState
    source_key_name_prefix_match: CheckState

    source_key_accepted_in_target_bucket: CheckState

    destination_key_exists: CheckState
    destination_key_bucket_match: CheckState
    destination_key_write_capabilities: CheckState
    destination_key_name_prefix_match: CheckState

    file_lock_match: CheckState

    @classmethod
    def from_data(
        cls,
        source_bucket: BucketStructure,
        replication_rule_name: str,
        source_application_key: Union[Optional[ApplicationKey], AccessDeniedEnum],
        destination_bucket: BucketStructure,
        destination_application_keys: Dict[str, Union[Optional[ApplicationKey]], AccessDeniedEnum],
    ) -> 'TwoWayReplicationCheck':
        kwargs = {}

        rules = [
            rule for rule in source_bucket.replication.rules if rule.name == replication_rule_name
        ]
        assert rules
        rule = rules[0]

        kwargs['is_enabled'] = CheckState.from_bool(rule.is_enabled),

        (
            kwargs['source_key_exists'],
            kwargs['source_key_bucket_match'],
            kwargs['source_key_read_capabilities'],
            kwargs['source_key_name_prefix_match'],
        ) = cls._check_key(
            source_application_key, 'readFiles', rule.file_name_prefix, source_bucket.id_
        )

        destination_application_key_id = destination_bucket.replication and destination_bucket.replication.source_to_destination_key_mapping.get(
            source_bucket.replication.source_key_id
        )

        kwargs['source_key_accepted_in_target_bucket'] = CheckState.from_bool(
            destination_application_key_id is not None
        )

        destination_application_key = destination_application_keys.get(
            destination_application_key_id
        )

        (
            kwargs['destination_key_exists'],
            kwargs['destination_key_bucket_match'],
            kwargs['destination_key_read_capabilities'],
            kwargs['destination_key_key_name_prefix_match'],
        ) = cls._check_key(
            destination_application_key, 'writeFiles', rule.file_name_prefix, destination_bucket.id_
        )

        if destination_bucket.is_file_lock_enabled:
            kwargs['file_lock_match'] = CheckState.OK
        elif source_bucket.is_file_lock_enabled is False:
            kwargs['file_lock_match'] = CheckState.OK
        elif source_bucket.is_file_lock_enabled is None or destination_bucket.is_file_lock_enabled is None:
            kwargs['file_lock_match'] = CheckState.UNKNOWN
        else:
            kwargs['file_lock_match'] = CheckState.NOT_OK

        return cls(**kwargs)


class OtherPartyReplicationCheckData:
    b2sdk_version = version.VERSION

    def __init__(
        self,
        bucket: BucketStructure,
        keys_mapping: Dict[str, Union[Optional[ApplicationKey], AccessDeniedEnum]],
        b2sdk_version: Optional[str] = None
    ):

        self.bucket = bucket
        self.keys_mapping = keys_mapping
        if b2sdk_version is None:
            self.b2sdk_version = type(self).b2sdk_version
        else:
            self.b2sdk_version = b2sdk_version

    @classmethod
    def _dump_key(self, key: Union[Optional[ApplicationKey], AccessDeniedEnum]):
        if key is None:
            return None
        if isinstance(key, AccessDeniedEnum):
            return key.value
        return key.as_dict()

    @classmethod
    def _parse_key(cls, key_representation: Union[None, str, dict]
                  ) -> Union[Optional[ApplicationKey], AccessDeniedEnum]:
        if key_representation is None:
            return None
        try:
            return AccessDeniedEnum(key_representation)
        except ValueError:
            pass
        return ApplicationKey.from_dict(key_representation)

    def as_dict(self):
        return {
            'b2sdk_version': self.b2sdk_version,
            'bucket': self.bucket.as_dict(),
            'keys_mapping': {k: self._dump_key(v)
                             for k, v in self.keys_mapping.items()},
        }

    @classmethod
    def from_dict(cls, dict_: dict):
        other_party_version = dict_['b2sdk_version']
        if other_party_version != cls.b2sdk_version:
            warnings.warn(
                f'Other party used a different version of b2sdk ({other_party_version}, this version: '
                f'{cls.b2sdk_version}) when dumping data for checking replication health. Check may not be '
                f'complete.'
            )

        return cls(
            b2sdk_version=other_party_version,
            bucket=BucketFactory.bucket_structure_from_dict(dict_['bucket']),
            keys_mapping={k: cls._parse_key(v)
                          for k, v in dict_['keys_mapping'].items()}
        )


def _safe_get_key(api: B2Api, key_id: str) -> Union[None, AccessDeniedEnum, ApplicationKey]:
    try:
        return api.get_key(key_id)
    except AccessDenied:
        return AccessDeniedEnum.ACCESS_DENIED
