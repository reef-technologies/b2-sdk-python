######################################################################
#
# File: test/unit/test_session.py
#
# Copyright 2021 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
from __future__ import annotations

from unittest import mock

import pytest
from apiver_deps import AuthInfoCache, B2Session, DummyCache, InMemoryAccountInfo
from apiver_deps_exception import Unauthorized

from .account_info.fixtures import *  # noqa
from .fixtures import *  # noqa


class TestB2Session:
    @pytest.fixture(autouse=True)
    def setup(self, b2_session):
        self.b2_session = b2_session

    @pytest.mark.parametrize(
        'authorize_call_kwargs',
        [
            pytest.param(
                dict(
                    account_id=mock.ANY,
                    auth_token=mock.ANY,
                    api_url=mock.ANY,
                    download_url=mock.ANY,
                    recommended_part_size=mock.ANY,
                    absolute_minimum_part_size=mock.ANY,
                    application_key='456',
                    realm='dev',
                    s3_api_url=mock.ANY,
                    allowed=mock.ANY,
                    application_key_id='123',
                ),
                marks=pytest.mark.apiver(from_ver=2),
            ),
            pytest.param(
                dict(
                    account_id=mock.ANY,
                    auth_token=mock.ANY,
                    api_url=mock.ANY,
                    download_url=mock.ANY,
                    minimum_part_size=mock.ANY,
                    application_key='456',
                    realm='dev',
                    s3_api_url=mock.ANY,
                    allowed=mock.ANY,
                    application_key_id='123',
                ),
                marks=pytest.mark.apiver(to_ver=1),
            ),
        ],
    )
    def test_simple_authorization(self, authorize_call_kwargs):
        self.b2_session.authorize_account('dev', '123', '456')

        self.b2_session.raw_api.authorize_account.assert_called_once_with(
            'http://api.backblazeb2.xyz:8180', '123', '456'
        )
        assert self.b2_session.cache.clear.called is False
        self.b2_session.account_info.set_auth_data.assert_called_once_with(**authorize_call_kwargs)

    def test_clear_cache(self):
        self.b2_session.account_info.is_same_account.return_value = False

        self.b2_session.authorize_account('dev', '123', '456')

        assert self.b2_session.cache.clear.called is True

    @pytest.mark.apiver(from_ver=3)
    def test_app_key_info_no_info(self):
        self.b2_session.account_info.get_allowed.return_value = dict(
            buckets=None,
            capabilities=ALL_CAPABILITIES,
            namePrefix=None,
        )
        self.b2_session.raw_api.get_file_info_by_id.side_effect = Unauthorized('no_go', 'code')
        with pytest.raises(
            Unauthorized, match=r'no_go for application key with no restrictions \(code\)'
        ):
            self.b2_session.get_file_info_by_id(None)

    @pytest.mark.apiver(from_ver=3)
    def test_app_key_info_no_info_no_message(self):
        self.b2_session.account_info.get_allowed.return_value = dict(
            buckets=None,
            capabilities=ALL_CAPABILITIES,
            namePrefix=None,
        )
        self.b2_session.raw_api.get_file_info_by_id.side_effect = Unauthorized('', 'code')
        with pytest.raises(
            Unauthorized, match=r'unauthorized for application key with no restrictions \(code\)'
        ):
            self.b2_session.get_file_info_by_id(None)

    @pytest.mark.apiver(from_ver=3)
    def test_app_key_info_all_info(self):
        self.b2_session.account_info.get_allowed.return_value = dict(
            buckets=[
                {'id': '123456', 'name': 'my-bucket'},
                {'id': '456789', 'name': 'their-bucket'},
            ],
            capabilities=['readFiles'],
            namePrefix='prefix/',
        )
        self.b2_session.raw_api.get_file_info_by_id.side_effect = Unauthorized('no_go', 'code')

        with pytest.raises(
            Unauthorized,
            match=r"no_go for application key with capabilities 'readFiles', restricted to buckets \['my-bucket', 'their-bucket'\], restricted to files that start with 'prefix/' \(code\)",
        ):
            self.b2_session.get_file_info_by_id(None)


def test_session__with_in_memory_account_info(apiver_int):
    memory_info = InMemoryAccountInfo()
    b2_session = B2Session(
        account_info=memory_info,
    )

    assert b2_session.account_info is memory_info

    if apiver_int < 3:
        assert isinstance(b2_session.cache, DummyCache)
    else:
        assert isinstance(b2_session.cache, AuthInfoCache)
        assert b2_session.cache.info is memory_info
