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

from apiver_deps import CheckState, TwoWayReplicationCheck, TwoWayReplicationCheckGenerator
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
