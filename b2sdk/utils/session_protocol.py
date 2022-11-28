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
    NamedTuple,
    Type,
)


class ProtocolInfo(NamedTuple):
    module_name: str
    class_name: str
    env_variable: str


# This list is to be ordered from the best to the worst.
# It contains pairs "module" "class" that is to be imported.
# Third element is name of the environmental variable
# That, if set, ensures that only this particular protocol
# is taken into account.
FROM_IMPORT_ENV_LIST = [
    ProtocolInfo('b2sdk.utils.curl', 'CurlSession', 'B2_USE_LIBCURL'),
    ProtocolInfo('requests', 'Session', 'B2_USE_REQUESTS'),
]


# TODO: use typing.Protocol when we drop 3.7
class SessionProtocol:
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


@functools.cache
def get_session_protocols(enable_env_checking: bool = True) -> tuple[list[Type[SessionProtocol]], dict[str, str]]:
    """
    Tries to import all available session protocols. Returns a list ordered from "the best"
    to "the worst" and a dictionary with names of protocols that failed with a reason.
    """
    protocols = []
    errors = {}

    # List of protocols that we should consider.
    enabled_protocols = set()

    if enable_env_checking:
        for protocol_info in FROM_IMPORT_ENV_LIST:
            env_value = os.getenv(protocol_info.env_variable)
            # We assume that any value assigned to these variables is enough. Only empty string and None are rejected.
            is_env_set = env_value is not None and len(env_value) > 0
            if not is_env_set:
                continue
            enabled_protocols.add(protocol_info.env_variable)

    for protocol_info in FROM_IMPORT_ENV_LIST:
        module_class = f'{protocol_info.module_name}.{protocol_info.class_name}'

        if len(enabled_protocols) > 0 and protocol_info not in enabled_protocols:
            errors[module_class] = f'Module is not on enabled protocols list set via environmental variables.'
            continue

        try:
            module = importlib.import_module(protocol_info.module_name)
            protocol = getattr(module, protocol_info.class_name)
            protocols.append(protocol)
        except (ImportError, AttributeError) as error:
            errors[module_class] = str(error)
            # This protocol had environmental variable set to enable it, and we failed to load the library.
            assert protocol_info.env_variable not in enabled_protocols, \
                f'Unable to enable {protocol_info.env_variable}: {str(error)}'

    return protocols, errors
