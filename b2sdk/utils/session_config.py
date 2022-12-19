######################################################################
#
# File: b2sdk/utils/session_config.py
#
# Copyright 2022 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

from dataclasses import dataclass

# TODO: use value from constants, when they are merged with the master.
MEGABYTE = 1024 * 1024


@dataclass
class SessionConfig:
    """
    Configuration for newly created session objects.

    Note that not all the sessions have to use all the parameters from here.
    """

    # How long to wait for 100-continue before going with the rest of the request.
    expect_100_timeout_seconds: float = 10

    # When downloading data, how much memory should be used by a single internal buffer.
    single_download_buffer_size_bytes: int = 10 * MEGABYTE

    # When downloading data, how much Python memory we should keep at once. After that limit
    # downloading further data should be stopped until data is consumed below this point.
    max_download_memory_size_bytes: int = 200 * MEGABYTE

    # Should underlying mechanism log additional information.
    verbose: bool = False

    # Should underlying mechanism use signal handlers.
    use_signal_handlers: bool = True

    # Number of connections that we're trying to keep reused. Pass ``0`` to have no connection caching.
    reused_connections_count: int = 10


SESSION_CONFIG = SessionConfig()
