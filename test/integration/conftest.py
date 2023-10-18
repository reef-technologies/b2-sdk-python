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

import http.client
import os
import random
import time

import pytest

from b2sdk.b2http import B2Http
from b2sdk.raw_api import REALM_URLS, B2RawHTTPApi

from . import get_b2_auth_data


def pytest_addoption(parser):
    """Add a flag for not cleaning up old buckets"""
    parser.addoption(
        '--dont-cleanup-old-buckets',
        action="store_true",
        default=False,
    )


@pytest.fixture
def dont_cleanup_old_buckets(request):
    return request.config.getoption("--dont-cleanup-old-buckets")


@pytest.fixture(scope="session")
def raw_api():
    return B2RawHTTPApi(B2Http())


@pytest.fixture(scope="session")
def auth_dict(raw_api):
    try:
        application_key_id, application_key = get_b2_auth_data()
    except ValueError as ex:
        pytest.fail(ex.args[0])
    else:
        realm = os.environ.get('B2_TEST_ENVIRONMENT', 'production')
        realm_url = REALM_URLS.get(realm, realm)
        return raw_api.authorize_account(realm_url, application_key_id, application_key)


@pytest.fixture(scope="session")
def bucket_dict(raw_api, auth_dict):
    bucket_name = 'test-raw-api-%s-%d-%d' % (
        auth_dict['accountId'], int(time.time()), random.randint(1000, 9999)
    )

    return raw_api.create_bucket(
        auth_dict['apiUrl'],
        auth_dict['authorizationToken'],
        auth_dict['accountId'],
        bucket_name,
        'allPublic',
        is_file_lock_enabled=True,
    )


@pytest.fixture(scope="session")
def upload_url_dict(raw_api, auth_dict, bucket_dict):
    return raw_api.get_upload_url(
        auth_dict['apiUrl'], auth_dict['authorizationToken'], bucket_dict['bucketId']
    )


@pytest.fixture
def http_sent_data(monkeypatch):
    orig_send = http.client.HTTPConnection.send
    sent_data = bytearray()

    def patched_send(self, data):
        sent_data.extend(data)
        return orig_send(self, data)

    monkeypatch.setattr(
        http.client.HTTPConnection,
        "send",
        patched_send,
    )

    return sent_data
