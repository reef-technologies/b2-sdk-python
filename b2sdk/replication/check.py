import warnings
from typing import Optional, Dict, Union, Tuple

from b2sdk import version
from b2sdk.api import B2Api
from b2sdk.application_key import ApplicationKey
from b2sdk.bucket import BucketStructure, BucketFactory, Bucket
import enum

from b2sdk.exception import AccessDenied, BucketIdNotFound


class ReplicationFilter:
    def __init__(self, source_api: B2Api, destination_api: B2Api, filters: ...):
        self.source_api = source_api
        self.destination_api = destination_api

    # def get_checks


class TwoWayReplicationCheckGenerator:
    def __init__(
        self,
        source_api: B2Api,
        destination_api: B2Api,
        filter_source_bucket_name: Optional[str],
        filter_destination_bucket_name: Optional[str],
        filter_replication_rule_name: Optional[str],
        file_name_prefix: Optional[str],
    ):
        self.source_api = source_api
        self.destination_api = destination_api

        self.filter_source_bucket_name = filter_source_bucket_name
        self.filter_destination_bucket_name = filter_destination_bucket_name
        self.filter_replication_rule_name = filter_replication_rule_name
        self.file_name_prefix = file_name_prefix

    def get_checks(self):
        if self.filter_source_bucket_name is not None:
            source_buckets = self.source_api.list_buckets(
                bucket_name=self.filter_source_bucket_name
            )
        else:
            source_buckets = self.source_api.list_buckets()
        for source_bucket in source_buckets:
            if not source_bucket.replication:
                continue
            if not source_bucket.replication.as_replication_source:
                continue
            if not source_bucket.replication.as_replication_source.replication_rules:
                continue
            source_key = _safe_get_key(
                self.source_api,
                source_bucket.replication.as_replication_source.source_application_key_id
            )
            for rule in source_bucket.replication.as_replication_source.replication_rules:
                if (
                    self.filter_replication_rule_name is not None and
                    rule.replication_rule_name != self.filter_replication_rule_name
                ):
                    continue

                if self.file_name_prefix is not None and rule.file_name_prefix != self.file_name_prefix:
                    continue

                try:
                    destination_bucket_list = self.destination_api.list_buckets(
                        bucket_id=rule.destination_bucket_id
                    )
                    if not destination_bucket_list:
                        raise BucketIdNotFound
                except (AccessDenied, BucketIdNotFound):
                    yield ReplicationSourceCheck(source_bucket, rule.replication_rule_name)
                    continue

                if (
                    self.filter_destination_bucket_name is not None and
                    destination_bucket_list[0].name != self.filter_destination_bucket_name
                ):
                    continue

                yield TwoWayReplicationCheck(
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
        if not destination_bucket.replication.as_replication_destination:
            return {}
        key_ids = destination_bucket.replication.as_replication_destination.source_to_destination_key_mapping.values(
        )
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
        return self == type(self).OK


class AccessDeniedEnum(enum.Enum):
    ACCESS_DENIED = 'ACCESS_DENIED'


class ReplicationSourceCheck:
    """
    key_exists
    key_read_capabilities
    key_name_prefix_match
    is_enabled

    """

    def __init__(self, bucket: Bucket, rule_name: str):
        self.bucket = bucket
        self.application_key = _safe_get_key(
            self.bucket.api, self.bucket.replication.as_replication_source.source_application_key_id
        )
        rules = [
            r for r in self.bucket.replication.as_replication_source.replication_rules
            if r.replication_rule_name == rule_name
        ]
        assert rules
        self._rule = rules[0]

        self.is_enabled = self._rule.is_enabled

        (
            self.key_exists,
            self.key_bucket_match,
            self.key_read_capabilities,
            self.key_name_prefix_match,
        ) = _check_key(application_key, 'readFiles', self._rule.file_name_prefix, bucket.id_)

    def other_party_data(self):
        return OtherPartyReplicationCheckData(
            bucket=self.bucket,
            keys_mapping={
                self.bucket.replication.as_replication_source.source_application_key_id:
                    self.application_key
            }
        )


class ReplicationDestinationCheck:
    """
    keys_exist: {
        10053d55ae26b790000000004: True
        10053d55ae26b790030000004: True
        10053d55ae26b790050000004: False
    }
    keys_write_capabilities: {
        10053d55ae26b790000000004: True
        10053d55ae26b790030000004: False
        10053d55ae26b790050000004: False
    }
    keys_bucket_match: {
        10053d55ae26b790000000004: True
        10053d55ae26b790030000004: False
        10053d55ae26b790050000004: False
    }
    """

    def __init__(self, bucket: Bucket):
        self.bucket = bucket
        self.keys: Dict[str, Union[Optional[ApplicationKey], AccessDeniedEnum]] = {}
        self.keys_exist: Dict[str, CheckState] = {}
        self.keys_write_capabilities: Dict[str, CheckState] = {}
        self.keys_bucket_match: Dict[str, CheckState] = {}
        keys_to_check = bucket.replication.as_replication_destination.source_to_destination_key_mapping.values(
        )
        try:
            for key_id in keys_to_check:
                application_key = self.bucket.api.get_key(
                    self.bucket.replication.as_replication_source.source_application_key_id
                )
                self.keys[key_id] = application_key
                if application_key:
                    self.keys_exist[key_id] = CheckState.OK
                    self.keys_write_capabilities[
                        key_id
                    ] = CheckState.OK if 'writeFiles' in application_key.capabilities else CheckState.NOT_OK
                    self.keys_bucket_match[key_id] = (
                        CheckState.OK if application_key.bucket_id is None or
                        application_key.bucket_id == bucket.id_ else CheckState.NOT_OK
                    )
                else:
                    self.keys_exist[key_id] = CheckState.NOT_OK
                    self.keys_write_capabilities[key_id] = CheckState.NOT_OK
                    self.keys_bucket_match[key_id] = CheckState.NOT_OK

        except AccessDenied:

            self.keys = dict.fromkeys(keys_to_check, None)
            self.keys_exist = dict.fromkeys(keys_to_check, CheckState.UNKNOWN)
            self.keys_write_capabilities = dict.fromkeys(keys_to_check, CheckState.UNKNOWN)
            self.keys_bucket_match = dict.fromkeys(keys_to_check, CheckState.UNKNOWN)

    def other_party_data(self):
        return OtherPartyReplicationCheckData(
            bucket=self.bucket,
            keys_mapping=self.keys,
        )


class TwoWayReplicationCheck:
    """
    is_enabled

    source_key_exists
    source_key_bucket_match
    source_key_read_capabilities
    source_key_name_prefix_match

    source_key_accepted_in_target_bucket

    destination_key_exists
    destination_key_bucket_match
    destination_key_write_capabilities
    destination_key_name_prefix_match

    file_lock_match
    """

    def __init__(
        self,
        source_bucket: BucketStructure,
        replication_rule_name: str,
        source_application_key: Union[Optional[ApplicationKey], AccessDeniedEnum],
        destination_bucket: BucketStructure,
        destination_application_keys: Dict[str, Union[Optional[ApplicationKey]], AccessDeniedEnum],
    ):
        rules = [
            r for r in source_bucket.replication.as_replication_source.replication_rules
            if r.replication_rule_name == replication_rule_name
        ]
        assert rules
        self._rule = rules[0]
        self.is_enabled = CheckState.OK if self._rule.is_enabled else CheckState.NOT_OK

        (
            self.source_key_exists,
            self.source_key_bucket_match,
            self.source_key_read_capabilities,
            self.source_key_name_prefix_match,
        ) = self._check_key(
            source_application_key, 'readFiles', self._rule.file_name_prefix, source_bucket.id_
        )

        if destination_bucket.replication is None or destination_bucket.replication.as_replication_destination is None:
            destination_application_key_id = None
        else:
            destination_application_key_id = destination_bucket.replication.as_replication_destination.\
                source_to_destination_key_mapping.get(
                source_bucket.replication.as_replication_source.source_application_key_id)

        if destination_application_key_id is None:
            self.source_key_accepted_in_target_bucket = CheckState.NOT_OK
        else:
            self.source_key_accepted_in_target_bucket = CheckState.OK

        destination_application_key = destination_application_keys.get(
            destination_application_key_id
        )

        (
            self.destination_key_exists,
            self.destination_key_bucket_match,
            self.destination_key_read_capabilities,
            self.destination_key_key_name_prefix_match,
        ) = self._check_key(
            destination_application_key, 'writeFiles', self._rule.file_name_prefix,
            destination_bucket.id_
        )

        if destination_bucket.is_file_lock_enabled:
            self.file_lock_match = CheckState.OK
        elif source_bucket.is_file_lock_enabled == False:
            self.file_lock_match = CheckState.OK
        elif source_bucket.is_file_lock_enabled is None or destination_bucket.is_file_lock_enabled is None:
            self.file_lock_match = CheckState.UNKNOWN
        else:
            self.file_lock_match = CheckState.NOT_OK

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
            CheckState.OK
            if key.bucket_id is None or key.bucket_id == bucket_id else CheckState.NOT_OK,
            CheckState.OK if capability in key.capabilities else CheckState.NOT_OK,
            CheckState.OK if key.name_prefix is None or
            replication_name_prefix.startswith(key.name_prefix) else CheckState.NOT_OK,
        )


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


def _check_key(
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
        CheckState.OK if key.bucket_id is None or key.bucket_id == bucket_id else CheckState.NOT_OK,
        CheckState.OK if capability in key.capabilities else CheckState.NOT_OK,
        CheckState.OK if key.name_prefix is None or
        replication_name_prefix.startswith(key.name_prefix) else CheckState.NOT_OK,
    )
