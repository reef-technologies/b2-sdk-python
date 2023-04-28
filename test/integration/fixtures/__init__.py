######################################################################
#
# File: test/integration/fixtures/__init__.py
#
# Copyright 2021 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

import os

import pytest
from .. import get_b2_auth_data, get_realm


@pytest.fixture
def b2_auth_data():
    try:
        return get_b2_auth_data()
    except ValueError as ex:
        pytest.fail(ex.args[0])


@pytest.fixture
def realm():
    return get_realm()
