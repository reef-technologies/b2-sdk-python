from b2sdk import _v2 as v2
from .session import B2Session


class B2Api(v2.B2Api):
    SESSION_CLASS = staticmethod(B2Session)
