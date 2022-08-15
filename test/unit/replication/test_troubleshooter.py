######################################################################
#
# File: test/unit/replication/test_troubleshooter.py
#
# Copyright 2022 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

import pytest

from apiver_deps import CheckState, EncryptionAlgorithm, EncryptionKey, EncryptionMode, EncryptionSetting, TwoWayReplicationCheck, TwoWayReplicationCheckGenerator
from more_itertools import one


@pytest.mark.apiver(from_ver=2)
def test_troubleshooter_source_bucket_name_filter(api, source_bucket, destination_bucket):
    bucket_name = source_bucket.name

    # check original name filter
    troubleshooter = TwoWayReplicationCheckGenerator(
        source_api=source_bucket.api,
        destination_api=destination_bucket.api,
        filter_source_bucket_name=bucket_name,
    )
    assert len(list(troubleshooter.iter_checks())) == 1

    # check other name filter
    troubleshooter = TwoWayReplicationCheckGenerator(
        source_api=source_bucket.api,
        destination_api=destination_bucket.api,
        filter_source_bucket_name=bucket_name + '-other',
    )
    assert len(list(troubleshooter.iter_checks())) == 0


@pytest.mark.apiver(from_ver=2)
def test_troubleshooter_rule_name_filter(api, source_bucket, destination_bucket):
    rule_name = source_bucket.replication.rules[0].name

    # check original name filter
    troubleshooter = TwoWayReplicationCheckGenerator(
        source_api=source_bucket.api,
        destination_api=destination_bucket.api,
        filter_replication_rule_name=rule_name,
    )
    assert len(list(troubleshooter.iter_checks())) == 1

    # check other name filter
    troubleshooter = TwoWayReplicationCheckGenerator(
        source_api=source_bucket.api,
        destination_api=destination_bucket.api,
        filter_replication_rule_name=rule_name + '-other',
    )
    assert len(list(troubleshooter.iter_checks())) == 0


@pytest.mark.apiver(from_ver=2)
def test_troubleshooter_all_ok(api, source_bucket, troubleshooter):
    check = one(troubleshooter.iter_checks())
    assert isinstance(check, TwoWayReplicationCheck)

    assert check.source.is_enabled == CheckState.OK
    assert check.source.key_exists == CheckState.OK
    assert check.source.key_bucket_match == CheckState.OK
    assert check.source.key_capabilities == CheckState.OK
    assert check.source.key_name_prefix_match == CheckState.OK
    assert check.source.is_sse_c_disabled == CheckState.OK

    assert check.source_key_accepted_in_target_bucket == CheckState.OK

    assert check.destination.key_exists == CheckState.OK
    assert check.destination.key_bucket_match == CheckState.OK
    assert check.destination.key_capabilities == CheckState.OK
    assert check.destination.key_name_prefix_match == CheckState.OK
    assert check.file_lock_match == CheckState.OK


@pytest.mark.apiver(from_ver=2)
def test_troubleshooter_source_not_enabled(api, source_bucket, troubleshooter):
    replication = source_bucket.replication
    replication.rules[0].is_enabled = False
    source_bucket.update(replication=replication)

    check = one(troubleshooter.iter_checks())
    assert check.source.is_enabled == CheckState.NOT_OK


@pytest.mark.apiver(from_ver=2)
def test_troubleshooter_source_key_does_not_exist(api, source_bucket, source_key, troubleshooter):
    api.delete_key(source_key)
    assert not api.get_key(source_key.id_)

    check = one(troubleshooter.iter_checks())
    assert check.source.key_exists == CheckState.NOT_OK


@pytest.mark.apiver(from_ver=2)
def test_troubleshooter_source_key_bucket_match(api, source_bucket, source_key, troubleshooter):
    key = api.raw_api.key_id_to_key[source_key.id_]

    key.bucket_id_or_none = None
    check = one(troubleshooter.iter_checks())
    assert check.source.key_bucket_match == CheckState.OK

    key.bucket_id_or_none = source_bucket.id_
    check = one(troubleshooter.iter_checks())
    assert check.source.key_bucket_match == CheckState.OK

    key.bucket_id_or_none = 'hehe-trololo'
    check = one(troubleshooter.iter_checks())
    assert check.source.key_bucket_match == CheckState.NOT_OK


@pytest.mark.apiver(from_ver=2)
def test_troubleshooter_source_key_capabilities(api, source_bucket, source_key, troubleshooter):
    key = api.raw_api.key_id_to_key[source_key.id_]

    key.capabilities = ['readFilesWithPepper']
    check = one(troubleshooter.iter_checks())
    assert check.source.key_capabilities == CheckState.NOT_OK


@pytest.mark.apiver(from_ver=2)
def test_troubleshooter_source_key_name_prefix_match(
    api, source_bucket, source_key, troubleshooter
):
    key = api.raw_api.key_id_to_key[source_key.id_]

    key.name_prefix_or_none = None
    check = one(troubleshooter.iter_checks())
    assert check.source.key_name_prefix_match == CheckState.OK

    key.name_prefix_or_none = 'folder/'
    check = one(troubleshooter.iter_checks())
    assert check.source.key_name_prefix_match == CheckState.OK

    key.name_prefix_or_none = 'hoho-trololo/'
    check = one(troubleshooter.iter_checks())
    assert check.source.key_name_prefix_match == CheckState.NOT_OK


@pytest.mark.apiver(from_ver=2)
def test_troubleshooter_source_sse_c_disabled(api, source_bucket, source_key, troubleshooter):
    source_bucket.update(
        default_server_side_encryption=EncryptionSetting(
            mode=EncryptionMode.SSE_B2,
            algorithm=EncryptionAlgorithm.AES256,
        ),
        replication=source_bucket.replication,
    )
    check = one(troubleshooter.iter_checks())
    assert check.source.is_sse_c_disabled == CheckState.OK

    source_bucket.update(
        default_server_side_encryption=EncryptionSetting(
            mode=EncryptionMode.SSE_C,
            algorithm=EncryptionAlgorithm.AES256,
            key=EncryptionKey(secret='hoho', key_id='haha'),
        ),
        replication=source_bucket.replication,
    )
    check = one(troubleshooter.iter_checks())
    assert check.source.is_sse_c_disabled == CheckState.NOT_OK


@pytest.mark.apiver(from_ver=2)
def test_troubleshooter_source_key_accepted_in_target_bucket(
    api, source_bucket, source_key, destination_bucket, troubleshooter
):
    destination_replication = destination_bucket.replication
    destination_replication.source_to_destination_key_mapping = {}
    destination_bucket.update(replication=destination_replication)

    check = one(troubleshooter.iter_checks())
    assert check.source_key_accepted_in_target_bucket == CheckState.NOT_OK


@pytest.mark.apiver(from_ver=2)
def test_troubleshooter_file_lock_match(
    api, source_bucket, source_key, destination_bucket, troubleshooter
):
    source_bucket_obj = source_bucket.api.raw_api.bucket_id_to_bucket[source_bucket.id_]
    destination_bucket_obj = destination_bucket.api.raw_api.bucket_id_to_bucket[
        destination_bucket.id_]

    # False, True
    source_bucket_obj.is_file_lock_enabled = False
    destination_bucket_obj.is_file_lock_enabled = True

    check = one(troubleshooter.iter_checks())
    assert check.file_lock_match == CheckState.OK

    # None, False
    source_bucket_obj.is_file_lock_enabled = None
    destination_bucket_obj.is_file_lock_enabled = False

    check = one(troubleshooter.iter_checks())
    assert check.file_lock_match == CheckState.UNKNOWN

    # True, None
    source_bucket_obj.is_file_lock_enabled = True
    destination_bucket_obj.is_file_lock_enabled = None

    check = one(troubleshooter.iter_checks())
    assert check.file_lock_match == CheckState.UNKNOWN

    # True, None
    source_bucket_obj.is_file_lock_enabled = True
    destination_bucket_obj.is_file_lock_enabled = False

    check = one(troubleshooter.iter_checks())
    assert check.file_lock_match == CheckState.NOT_OK


@pytest.mark.apiver(from_ver=2)
def test_troubleshooter_destination_key_exists(
    api, destination_bucket, destination_key, troubleshooter
):
    api.delete_key(destination_key)
    assert not api.get_key(destination_key.id_)

    check = one(troubleshooter.iter_checks())
    assert check.destination.key_exists == CheckState.NOT_OK


@pytest.mark.apiver(from_ver=2)
def test_troubleshooter_destination_key_bucket_match(
    api, destination_bucket, destination_key, troubleshooter
):
    key = api.raw_api.key_id_to_key[destination_key.id_]

    key.bucket_id_or_none = None
    check = one(troubleshooter.iter_checks())
    assert check.destination.key_bucket_match == CheckState.OK

    key.bucket_id_or_none = destination_bucket.id_
    check = one(troubleshooter.iter_checks())
    assert check.destination.key_bucket_match == CheckState.OK

    key.bucket_id_or_none = 'hehe-trololo'
    check = one(troubleshooter.iter_checks())
    assert check.destination.key_bucket_match == CheckState.NOT_OK


@pytest.mark.apiver(from_ver=2)
def test_troubleshooter_destination_key_capabilities(
    api, destination_bucket, destination_key, troubleshooter
):
    key = api.raw_api.key_id_to_key[destination_key.id_]

    key.capabilities = ['readFilesWithPepper']
    check = one(troubleshooter.iter_checks())
    assert check.destination.key_capabilities == CheckState.NOT_OK


@pytest.mark.apiver(from_ver=2)
def test_troubleshooter_destination_key_name_prefix_match(
    api, destination_bucket, destination_key, troubleshooter
):
    key = api.raw_api.key_id_to_key[destination_key.id_]

    key.name_prefix_or_none = None
    check = one(troubleshooter.iter_checks())
    assert check.destination.key_name_prefix_match == CheckState.OK

    key.name_prefix_or_none = ''
    check = one(troubleshooter.iter_checks())
    assert check.destination.key_name_prefix_match == CheckState.OK

    key.name_prefix_or_none = 'hoho-trololo/'
    check = one(troubleshooter.iter_checks())
    assert check.destination.key_name_prefix_match == CheckState.NOT_OK
