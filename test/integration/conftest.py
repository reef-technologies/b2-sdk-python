######################################################################
#
# File: test/integration/conftest.py
#
# Copyright 2021 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
from __future__ import annotations

import http
import http.client
import os
import secrets
from test.integration import get_b2_auth_data
from test.integration.bucket_cleaner import BucketCleaner
from test.integration.helpers import (
    BUCKET_CREATED_AT_MILLIS,
    authorize,
    get_bucket_name_prefix,
    random_bucket_name,
)
from test.integration.persistent_bucket import (
    PersistentBucketAggregate,
    get_or_create_persistent_bucket,
)
from typing import Callable

import pytest

from b2sdk._internal.b2http import B2Http
from b2sdk._internal.raw_api import REALM_URLS
from b2sdk._internal.utils import current_time_millis
from b2sdk.v2.raw_api import B2RawHTTPApi


def pytest_addoption(parser):
    """Add a flag for not cleaning up old buckets"""
    parser.addoption(
        "--dont-cleanup-old-buckets",
        action="store_true",
        default=False,
    )


@pytest.fixture(scope="session")
def dont_cleanup_old_buckets(request):
    return request.config.getoption("--dont-cleanup-old-buckets")


@pytest.fixture(autouse=True, scope="session")
def set_http_debug():
    if os.environ.get("B2_DEBUG_HTTP"):
        http.client.HTTPConnection.debuglevel = 1


@pytest.fixture(scope="session")
def b2_auth_data():
    try:
        return get_b2_auth_data()
    except ValueError as ex:
        pytest.fail(ex.args[0])


@pytest.fixture(scope="session")
def bucket_name_prefix():
    return get_bucket_name_prefix(8)


@pytest.fixture(scope="session")
def _b2_api(b2_auth_data):
    b2_api, _ = authorize(b2_auth_data)
    return b2_api


@pytest.fixture(scope="session")
def bucket_cleaner(bucket_name_prefix, dont_cleanup_old_buckets, _b2_api):
    cleaner = BucketCleaner(
        dont_cleanup_old_buckets,
        _b2_api,
        current_run_prefix=bucket_name_prefix,
    )
    yield cleaner
    cleaner.cleanup_buckets()


@pytest.fixture(scope="session")
def b2_api(_b2_api, bucket_cleaner):
    return _b2_api


@pytest.fixture
def bucket(b2_api, bucket_name_prefix, bucket_cleaner):
    bucket = b2_api.create_bucket(
        random_bucket_name(bucket_name_prefix),
        "allPrivate",
        bucket_info={
            "created_by": "b2-sdk integration test",
            BUCKET_CREATED_AT_MILLIS: str(current_time_millis()),
        },
    )
    yield bucket
    bucket_cleaner.cleanup_bucket(bucket)


@pytest.fixture
def b2_subfolder(bucket, request):
    subfolder_name = f"{request.node.name}_{secrets.token_urlsafe(4)}"
    return f"b2://{bucket.name}/{subfolder_name}"


@pytest.fixture(scope="class")
def raw_api():
    return B2RawHTTPApi(B2Http())


@pytest.fixture(scope="class")
def auth_info(b2_auth_data, raw_api):
    application_key_id, application_key = b2_auth_data
    realm = os.environ.get('B2_TEST_ENVIRONMENT', 'production')
    realm_url = REALM_URLS.get(realm, realm)
    return raw_api.authorize_account(realm_url, application_key_id, application_key)


# -- Persistent bucket fixtures --
@pytest.fixture(scope="session")
def persistent_bucket_factory(b2_api) -> Callable[[], PersistentBucketAggregate]:
    """
    Since all consumers of the `bucket_name` fixture expect a new bucket to be created,
    we need to mirror this behavior by appending a unique subfolder to the persistent bucket name.
    """

    def _persistent_bucket(**bucket_create_options):
        persistent_bucket = get_or_create_persistent_bucket(b2_api, **bucket_create_options)
        return PersistentBucketAggregate(persistent_bucket)

    yield _persistent_bucket


@pytest.fixture(scope="class")
def persistent_bucket(persistent_bucket_factory):
    return persistent_bucket_factory()
