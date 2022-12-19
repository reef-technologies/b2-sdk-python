######################################################################
#
# File: b2sdk/api_config.py
#
# Copyright 2022 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

from typing import Optional, Type

from .raw_api import AbstractRawApi, B2RawHTTPApi
from .utils.session_config import SESSION_CONFIG, SessionConfig
from .utils.session_protocol import SessionProtocolFactory, get_session_protocol_factories

SESSION_FACTORIES = get_session_protocol_factories()
assert SESSION_FACTORIES.enabled, f'There are no session protocols available. Errors: {SESSION_FACTORIES.disabled}'
DEFAULT_SESSION_FACTORY = SESSION_FACTORIES.enabled[0]


class B2HttpApiConfig:

    DEFAULT_RAW_API_CLASS = B2RawHTTPApi

    def __init__(
        self,
        http_session_factory_base: SessionProtocolFactory = DEFAULT_SESSION_FACTORY,
        install_clock_skew_hook: bool = True,
        user_agent_append: Optional[str] = None,
        _raw_api_class: Optional[Type[AbstractRawApi]] = None,
        decode_content: bool = False,
        session_config: SessionConfig = SESSION_CONFIG,
    ):
        """
        A structure with params to be passed to low level API.

        :param http_session_factory_base: a callable that returns a requests.Session object (or a compatible one)
                                     conforming to a provided SessionConfig input.
        :param install_clock_skew_hook: if True, install a clock skew hook
        :param user_agent_append: if provided, the string will be appended to the User-Agent
        :param _raw_api_class: AbstractRawApi-compliant class
        :param decode_content: If true, the underlying http backend will try to decode encoded files when downloading,
                               based on the response headers
        :param session_config: Configuration for given session factory.
        """
        self.http_session_factory = lambda: http_session_factory_base(session_config)
        self.install_clock_skew_hook = install_clock_skew_hook
        self.user_agent_append = user_agent_append
        self.raw_api_class = _raw_api_class or self.DEFAULT_RAW_API_CLASS
        self.decode_content = decode_content


DEFAULT_HTTP_API_CONFIG = B2HttpApiConfig()
