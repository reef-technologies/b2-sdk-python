######################################################################
#
# File: b2sdk/utils/session_protocol.py
#
# Copyright 2022 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

import functools
import importlib
import os
from typing import Callable, Dict, List, NamedTuple, Type

from b2sdk.utils import str_to_bool
from b2sdk.utils.session_config import SessionConfig


class SessionProtocolInfo(NamedTuple):
    """
    Structure used to declare possible/available session protocols.

    It will be used to import ``factory_name`` from ``module_name``
    and will ensure that it's available if ``env_variable`` is set.
    """
    module_name: str
    factory_name: str
    env_variable: str


# This list is to be ordered from the best to the worst.
# If environmental variable is set, only these libraries we try to load.
# That is, if multiple variables are set, the one from the top of the list
# will be actually used.
# Also, if it's impossible to import a library that was set as required, it's an error.
FROM_IMPORT_ENV_LIST = [
    SessionProtocolInfo(
        'b2sdk.utils.curl',
        'curl_session_factory',
        'B2_USE_LIBCURL',
    ),
    SessionProtocolInfo(
        'b2sdk.utils.requests_factory',
        'requests_session_factory',
        'B2_USE_REQUESTS',
    ),
]


# TODO: use typing.Protocol when we drop 3.7
class Adapters:
    """
    Basic mount adapter interface description.
    It matches the basic requests library adapter protocol.
    It's used for ``typing`` purposes only.
    """

    def clear(self) -> None:
        pass


# TODO: use typing.Protocol when we drop 3.7
class SessionProtocol:
    """
    Basic http session interface description.
    It matches the basic requests library protocol.
    It's used for ``typing`` purposes only.
    """

    @property
    def adapters(self) -> Adapters:
        raise NotImplementedError

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


# Each factory can be configured with SessionConfig.
SessionProtocolFactory = Callable[[SessionConfig], SessionProtocol]


class Sessions(NamedTuple):
    """
    Structure holding all available (importable) protocol session objects
    and information about reasons of failure for the rest of them.
    """
    # List of classes that anyhow conform to SessionProtocol. Note that
    # none of them need to implement it to conform to it.
    enabled: List[Type[SessionProtocolFactory]]

    # Dictionary containing full module-factory string as a key and
    # a human-readable description of reason behind it not being in enabled group.
    disabled: Dict[str, str]


@functools.lru_cache(maxsize=None)
def get_session_protocol_factories(enable_env_checking: bool = True) -> Sessions:
    """
    Tries to import all available session protocols. Returns a list ordered from "the best"
    to "the worst" and a dictionary with names of protocols that failed with a reason.

    By using environmental variables, one can enable and disable specific protocols.
    It's considered an error if a protocol is enabled, but we're unable to import it.
    """
    enabled_sessions = []
    errors = {}

    env_variables: Dict[str, bool] = {}

    if enable_env_checking:
        for protocol_info in FROM_IMPORT_ENV_LIST:
            raw_env_value = os.getenv(protocol_info.env_variable)
            if raw_env_value is None:
                continue
            env_variables[protocol_info.env_variable] = str_to_bool(raw_env_value)

    for protocol_info in FROM_IMPORT_ENV_LIST:
        module_function = f'{protocol_info.module_name}.{protocol_info.factory_name}'

        # We assume that all protocols are enabled by default. Here we disable these
        # that were disabled via environmental variables.
        if not env_variables.get(protocol_info.env_variable, True):
            errors[module_function] = 'Module is disabled via environmental variables.'
            continue

        try:
            module = importlib.import_module(protocol_info.module_name)
            protocol = getattr(module, protocol_info.factory_name)
            enabled_sessions.append(protocol)
        except (ImportError, AttributeError) as error:
            errors[module_function] = str(error)
            # This protocol had environmental variable set to enable it, and we failed to load the library.
            assert env_variables.get(protocol_info.env_variable) != True, \
                f'Unable to enable {protocol_info.env_variable}: {str(error)}'

    return Sessions(enabled_sessions, errors)
