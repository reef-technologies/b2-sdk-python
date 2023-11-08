from random import random
from typing import Optional, NamedTuple, Tuple

from .retry_manager import RetryManager, RetryHandler


class LegacyRetryConfig(NamedTuple):
    retry_count: int
    idle_io_timeout_seconds: float

    connection_timeout_seconds: float = 3 + 6 + 12 + 24 + 1  # 4 standard tcp retransmissions + 1s latency

    initial_retry_delay_seconds: float = 1.0
    retry_delay_multiplier: float = 1.5
    max_retry_delay_seconds: float = 64.0


class LegacyRetryHandler(RetryHandler):
    CONFIGS = {
        'post_content': LegacyRetryConfig(retry_count=20, idle_io_timeout_seconds=128),
        # These two can take up to 20 minutes to complete.
        'b2_copy_file': LegacyRetryConfig(retry_count=20, idle_io_timeout_seconds=1200),
        'b2_copy_part': LegacyRetryConfig(retry_count=20, idle_io_timeout_seconds=1200),
        # The default config handles the remainder of the `json_content` cases.

        'get_content': LegacyRetryConfig(retry_count=20, idle_io_timeout_seconds=128),
        'head_content': LegacyRetryConfig(retry_count=5, idle_io_timeout_seconds=128),
        # Remaining cases are handled by the default config.
    }
    DEFAULT_CONFIG = LegacyRetryConfig(
        retry_count=5,
        idle_io_timeout_seconds=128,
    )

    def __init__(self, api_or_method_name: str):
        super().__init__()
        self.config = self.CONFIGS.get(api_or_method_name, self.DEFAULT_CONFIG)

        self.wait_time_seconds = None
        self.retry_count = self.config.retry_count

    def operation_failed(self) -> None:
        self.retry_count -= 1

        if self.wait_time_seconds is not None:
            self.wait_time_seconds *= self.config.retry_delay_multiplier
            # Avoid clients synchronizing and causing a wave of requests when connectivity is restored
            if self.wait_time_seconds > self.config.max_retry_delay_seconds:
                self.wait_time_seconds = self.config.max_retry_delay_seconds + random()
        else:
            self.wait_time_seconds = self.config.initial_retry_delay_seconds

    def get_session_timeouts(self) -> Tuple[float, float]:
        return self.config.connection_timeout_seconds, self.config.idle_io_timeout_seconds

    def should_retry(self) -> bool:
        return self.retry_count >= 0

    def get_retry_backoff(self, proposed_backoff_seconds: Optional[float] = None) -> Tuple[float, str]:
        if proposed_backoff_seconds is not None:
            return proposed_backoff_seconds, 'server asked us to'
        assert self.wait_time_seconds is not None, f'Operation should be marked as failed before asking for a backoff.'
        return self.wait_time_seconds, 'that is what the default exponential backoff is'


class LegacyRetryManager(RetryManager):
    def get_handler(self, api_or_method_name: str) -> RetryHandler:
        return LegacyRetryHandler(api_or_method_name)
