######################################################################
#
# File: b2sdk/v1/api.py
#
# Copyright 2021 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

from b2sdk import _v2 as v2
from .session import B2Session


class B2Api(v2.B2Api):
    SESSION_CLASS = staticmethod(B2Session)
