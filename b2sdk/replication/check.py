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
from typing import Dict, Generator, Optional, Union

from b2sdk import version
from b2sdk.api import B2Api
from b2sdk.application_key import ApplicationKey
from b2sdk.bucket import Bucket, BucketFactory, BucketStructure
from b2sdk.exception import AccessDenied, BucketIdNotFound


def _safe_get_key(api: B2Api, key_id: str) -> Union[None, AccessDenied, ApplicationKey]:
    try:
        return api.get_key(key_id)
    except AccessDenied:
        return AccessDenied()


@dataclass
class TwoWayReplicationCheckGenerator:
    source_api: B2Api
    destination_api: B2Api
    filter_source_bucket_name: Optional[str] = None
    filter_destination_bucket_name: Optional[str] = None
    filter_replication_rule_name: Optional[str] = None
    file_name_prefix: Optional[str] = None

    def get_checks(self) -> Generator['ReplicationCheck', None, None]:
        source_buckets = self.source_api.list_buckets(bucket_name=self.filter_source_bucket_name)
        for source_bucket in source_buckets:
            yield from self._get_source_bucket_checks(source_bucket)

    def _get_source_bucket_checks(self, source_bucket: Bucket
                                 ) -> Generator['ReplicationCheck', None, None]:
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
                yield ReplicationSourceCheck.from_data(source_bucket, rule.name)
                continue

            if (
                self.filter_destination_bucket_name is not None and
                destination_bucket_list[0].name != self.filter_destination_bucket_name
            ):
                continue

            yield TwoWayReplicationCheck.from_data(
                source_bucket=source_bucket,
                replication_rule_name=rule.name,
                source_application_key=source_key,
                destination_bucket=destination_bucket_list[0],
                destination_application_keys=self._get_destination_bucket_keys(
                    destination_bucket_list[0]
                ),
            )

    @classmethod
    def _get_destination_bucket_keys(cls, destination_bucket: Bucket) -> \
            Dict[str, Union[None, ApplicationKey, AccessDenied]]:
        if not destination_bucket.replication:
            return {}

        key_ids = destination_bucket.replication.source_to_destination_key_mapping.values()
        try:
            return {key_id: destination_bucket.api.get_key(key_id) for key_id in key_ids}
        except AccessDenied:
            return dict.fromkeys(key_ids, AccessDenied())


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


class ReplicationCheck:
    @classmethod
    def _check_key(
        cls,
        key: Union[None, ApplicationKey, AccessDenied],
        capability: str,
        replication_name_prefix: str,
        bucket_id: str,
    ) -> Dict[str, CheckState]:

        result = {
            'key_exists': CheckState.UNKNOWN,
            'key_bucket_match': CheckState.UNKNOWN,
            'key_capabilities': CheckState.UNKNOWN,
            'key_name_prefix_match': CheckState.UNKNOWN,
        }

        if isinstance(key, AccessDenied):
            pass

        elif key is None:
            result = {k: CheckState.NOT_OK for k in result.keys()}

        else:
            result.update(
                {
                    'key_exists':
                        CheckState.OK,
                    'key_bucket_match':
                        CheckState.from_bool(key.bucket_id is None or key.bucket_id == bucket_id),
                    'key_capabilities':
                        CheckState.from_bool(capability in key.capabilities),
                    'key_name_prefix_match':
                        CheckState.from_bool(
                            key.name_prefix is None or
                            replication_name_prefix.startswith(key.name_prefix)
                        ),
                }
            )

        return result


@dataclass
class ReplicationSourceCheck(ReplicationCheck):
    key_exists: CheckState
    key_bucket_match: CheckState
    key_capabilities: CheckState
    key_name_prefix_match: CheckState

    is_enabled: CheckState

    _bucket: Bucket
    _application_key: Union[None, AccessDenied, ApplicationKey]

    @classmethod
    def from_data(cls, bucket: Bucket, rule_name: str) -> 'ReplicationSourceCheck':
        application_key = _safe_get_key(bucket.api, bucket.replication.source_key_id)

        rules = [rule for rule in bucket.replication.rules if rule.name == rule_name]
        assert rules
        rule = rules[0]

        kwargs = {
            '_bucket': bucket,
            '_application_key': application_key,
            'is_enabled': CheckState.from_bool(rule.is_enabled),
            **cls._check_key(application_key, 'readFiles', rule.file_name_prefix, bucket.id_),
        }

        return cls(**kwargs)

    def other_party_data(self):
        return OtherPartyReplicationCheckData(
            bucket=self._bucket,
            keys_mapping={self._bucket.replication.source_key_id: self._application_key},
        )


@dataclass
class ReplicationDestinationCheck(ReplicationCheck):
    key_exists: CheckState
    key_capabilities: CheckState
    key_bucket_match: CheckState
    key_name_prefix_match: CheckState

    _bucket: Bucket
    _application_key: Union[None, AccessDenied, ApplicationKey]

    @classmethod
    def iter_by_keys(cls, bucket: Bucket) -> Generator['ReplicationDestinationCheck', None, None]:
        keys_to_check = bucket.replication.source_to_destination_key_mapping.values()
        for key_id in keys_to_check:
            yield cls.from_data(bucket=bucket, key_id=key_id)

    @classmethod
    def from_data(cls, bucket: Bucket, key_id: str) -> 'ReplicationDestinationCheck':
        application_key = _safe_get_key(bucket.api, key_id)
        kwargs = {
            '_bucket': bucket,
            '_application_key': application_key,
            **cls._check_key(application_key, 'writeFiles', '', bucket.id_),
        }
        return cls(**kwargs)

    def other_party_data(self):
        return OtherPartyReplicationCheckData(
            bucket=self._bucket,
            keys_mapping=self._keys,
        )


@dataclass
class TwoWayReplicationCheck(ReplicationCheck):
    source: ReplicationSourceCheck
    destination: ReplicationDestinationCheck
    source_key_accepted_in_target_bucket: CheckState
    file_lock_match: CheckState

    @classmethod
    def from_data(
        cls,
        source_bucket: BucketStructure,
        replication_rule_name: str,
        source_application_key: Union[None, ApplicationKey, AccessDenied],
        destination_bucket: BucketStructure,
        destination_application_keys: Dict[str, Union[None, ApplicationKey, AccessDenied]],
    ) -> 'TwoWayReplicationCheck':

        destination_application_key_id = destination_bucket.replication and destination_bucket.replication.source_to_destination_key_mapping.get(
            source_bucket.replication.source_key_id
        )

        if destination_bucket.is_file_lock_enabled:
            file_lock_match = CheckState.OK
        elif source_bucket.is_file_lock_enabled is False:
            file_lock_match = CheckState.OK
        elif source_bucket.is_file_lock_enabled is None or destination_bucket.is_file_lock_enabled is None:
            file_lock_match = CheckState.UNKNOWN
        else:
            file_lock_match = CheckState.NOT_OK

        kwargs = {
            'source':
                ReplicationSourceCheck.from_data(
                    bucket=source_bucket,
                    rule_name=replication_rule_name,
                ),
            'destination':
                ReplicationDestinationCheck.from_data(
                    bucket=destination_bucket,
                    key_id=destination_application_key_id,
                ),
            'source_key_accepted_in_target_bucket':
                CheckState.from_bool(destination_application_key_id is not None),
            'file_lock_match':
                file_lock_match,
        }

        return cls(**kwargs)


@dataclass
class OtherPartyReplicationCheckData:
    bucket: BucketStructure
    keys_mapping: Dict[str, Union[None, ApplicationKey, AccessDenied]]
    b2sdk_version: version = version.VERSION

    @classmethod
    def _dump_key(self, key: Union[None, ApplicationKey, AccessDenied]):
        if key is None:
            return None
        if isinstance(key, AccessDenied):
            return key.__class__.__name__
        return key.as_dict()

    @classmethod
    def _parse_key(cls, key_representation: Union[None, str, dict]
                  ) -> Union[None, ApplicationKey, AccessDenied]:
        if key_representation is None:
            return None

        if key_representation == AccessDenied.__name__:
            return AccessDenied()

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
