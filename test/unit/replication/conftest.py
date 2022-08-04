######################################################################
#
# File: test/unit/replication/conftest.py
#
# Copyright 2020 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

from typing import Union

import pytest

from apiver_deps import B2Api, B2HttpApiConfig, Bucket, FullApplicationKey, RawSimulator, ReplicationConfiguration, ReplicationMonitor, ReplicationRule, StubAccountInfo, TwoWayReplicationCheckGenerator


@pytest.fixture
def api() -> B2Api:
    account_info = StubAccountInfo()
    api = B2Api(
        account_info,
        api_config=B2HttpApiConfig(_raw_api_class=RawSimulator),
    )

    simulator = api.session.raw_api
    account_id, master_key = simulator.create_account()
    api.authorize_account('production', account_id, master_key)
    return api


@pytest.fixture
def destination_key(api) -> Union[FullApplicationKey, dict]:
    return api.create_key(capabilities='writeFiles', key_name='destination-key')


@pytest.fixture
def destination_key_id(destination_key) -> str:
    return destination_key.id_


@pytest.fixture
def source_key(api) -> Union[FullApplicationKey, dict]:
    return api.create_key(capabilities='readFiles', key_name='source-key')


@pytest.fixture
def source_key_id(source_key) -> str:
    return source_key.id_


@pytest.fixture
def destination_bucket(api, source_key_id, destination_key_id) -> Bucket:
    return api.create_bucket(
        name='destination-bucket',
        bucket_type='allPublic',
        is_file_lock_enabled=False,
        replication=ReplicationConfiguration(
            source_to_destination_key_mapping={
                source_key_id: destination_key_id,
            },
        ),
    )


@pytest.fixture
def source_bucket(api, destination_bucket, source_key_id) -> Bucket:
    return api.create_bucket(
        name='source-bucket',
        bucket_type='allPublic',
        is_file_lock_enabled=False,
        replication=ReplicationConfiguration(
            rules=[
                ReplicationRule(
                    destination_bucket_id=destination_bucket.id_,
                    name='name',
                    file_name_prefix='folder/',  # TODO: is last slash needed?
                ),
            ],
            source_key_id=source_key_id,
        ),
    )


@pytest.fixture
def test_file(tmpdir) -> str:
    file = tmpdir.join('test.txt')
    file.write('whatever')
    return file


@pytest.fixture
def test_file_reversed(tmpdir) -> str:
    file = tmpdir.join('test-reversed.txt')
    file.write('revetahw')
    return file


@pytest.fixture
def monitor(source_bucket) -> ReplicationMonitor:
    return ReplicationMonitor(
        source_bucket,
        rule=source_bucket.replication.rules[0],
    )


@pytest.fixture
def troubleshooter(source_bucket, destination_bucket) -> TwoWayReplicationCheckGenerator:
    return TwoWayReplicationCheckGenerator(
        source_api=source_bucket.api,
        destination_api=destination_bucket.api,
    )
