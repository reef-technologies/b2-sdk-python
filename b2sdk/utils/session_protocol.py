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
from typing import Type

# This list is to be ordered from the best to the worst.
# It contains pairs "module" "class" that is to be imported.
FROM_IMPORT_LIST = [
    ('b2sdk.utils.curl', 'CurlSession'),
    ('requests', 'Session'),
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
def get_session_protocols() -> tuple[list[Type[SessionProtocol]], dict[str, str]]:
    """
    Tries to import all available session protocols. Returns a list ordered from "the best"
    to "the worst" and a dictionary with names of protocols that failed with a reason.
    """
    protocols = []
    errors = {}

    for module_name, class_name in FROM_IMPORT_LIST:
        try:
            module = importlib.import_module(module_name)
            protocol = getattr(module, class_name)
            protocols.append(protocol)
        except (ImportError, AttributeError) as error:
            errors[f'{module_name}.{class_name}'] = str(error)

    return protocols, errors
