######################################################################
#
# File: b2sdk/utils/session_protocol.py
#
# Copyright 2020 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
import functools
import importlib
import os
from typing import (
    Dict,
    List,
    NamedTuple,
    Type,
)

from b2sdk.utils import str_to_bool


class SessionProtocolInfo(NamedTuple):
    """
    Structure used to declare possible/available session protocols.

    It will be used to import ``class_name`` from ``module_name``
    and will ensure that it's available if ``env_variable`` is set.
    """
    module_name: str
    class_name: str
    env_variable: str


# This list is to be ordered from the best to the worst.
# If environmental variable is set, only these libraries we try to load.
# That is, if multiple variables are set, the one from the top of the list
# will be actually used.
# Also, if it's impossible to import a library that was set as required,
# it's an error.
FROM_IMPORT_ENV_LIST = [
    SessionProtocolInfo('b2sdk.utils.curl', 'CurlSession', 'B2_USE_LIBCURL'),
    SessionProtocolInfo('requests', 'Session', 'B2_USE_REQUESTS'),
]


# TODO: use typing.Protocol when we drop 3.7
class SessionProtocol:
    """
    Basic http session interface description.
    It matches the requests library protocol.
    It's used for ``typing`` purposes only.
    """
    def request(self, *args, **kwargs):
        pass

    def post(self, *args, **kwargs):
        pass

    def get(self, *args, **kwargs):
        pass

    def head(self, *args, **kwargs):
        pass

    def mount(self, *args, **kwargs):
        pass


class Sessions(NamedTuple):
    """
    Structure holding all available (importable) protocol session objects
    and information about reasons of failure for the rest of them.
    """
    # List of classes that anyhow conform to SessionProtocol. Note that
    # none of them need to implement it to conform to it.
    enabled: List[Type[SessionProtocol]]

    # Dictionary containing full module-class string as a key and
    # a human-readable description of reason behind it not being in enabled group.
    disabled: Dict[str, str]


@functools.lru_cache(maxsize=None)
def get_session_protocols(enable_env_checking: bool = True) -> Sessions:
    """
    Tries to import all available session protocols. Returns a list ordered from "the best"
    to "the worst" and a dictionary with names of protocols that failed with a reason.
    """
    enabled_sessions = []
    errors = {}

    # List of protocols that we should consider.
    enabled_env_variables = set()

    if enable_env_checking:
        for protocol_info in FROM_IMPORT_ENV_LIST:
            is_env_set = str_to_bool(os.getenv(protocol_info.env_variable, default=''))
            if not is_env_set:
                continue
            enabled_env_variables.add(protocol_info.env_variable)

    for protocol_info in FROM_IMPORT_ENV_LIST:
        module_class = f'{protocol_info.module_name}.{protocol_info.class_name}'

        if len(enabled_env_variables) > 0 and \
            protocol_info.env_variable not in enabled_env_variables:
            errors[module_class] = \
                'Module is not on enabled sessions list set via environmental variables.'
            continue

        try:
            module = importlib.import_module(protocol_info.module_name)
            protocol = getattr(module, protocol_info.class_name)
            enabled_sessions.append(protocol)
        except (ImportError, AttributeError) as error:
            errors[module_class] = str(error)
            # This protocol had environmental variable set to enable it, and we failed to load the library.
            assert protocol_info.env_variable not in enabled_env_variables, \
                f'Unable to enable {protocol_info.env_variable}: {str(error)}'

    return Sessions(enabled_sessions, errors)
