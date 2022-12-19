######################################################################
#
# File: b2sdk/utils/requests_factory.py
#
# Copyright 2022 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

import requests

from b2sdk.utils.session_config import SessionConfig
from b2sdk.utils.session_protocol import SessionProtocol


def requests_session_factory(session_config: SessionConfig) -> SessionProtocol:
    """
    This is currently a no-op, as there's nothing to be configured for requests.
    """

    # Enabling verbose mode for requests.
    if session_config.verbose:
        # Taken from https://requests.readthedocs.io/en/latest/api/#migrating-to-1-x
        from http.client import HTTPConnection
        import logging

        HTTPConnection.debuglevel = 1

        # It is assumed that logger is already present and set to level DEBUG.
        requests_log = logging.getLogger("urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    # TODO: Remove noqa once SessionProtocol becomes typing.Protocol.
    return requests.Session()  # noqa
