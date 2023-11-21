######################################################################
#
# File: b2sdk/retries/graceful_retry_manager.py
#
# Copyright 2023 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
import threading
from typing import Optional, Tuple, Callable

from .retry_manager import RetryHandler, RetryManager


class GracefulRetryHandler(RetryHandler):
    """
    This retry handler can be shared between threads and shares the behavior for all the parts at once.

    If multiple parts are uploaded in parallel, each contributes the configuration to the common pool.
    """
    def __init__(self, succeeded_function: Callable[[], None]):
        super().__init__()
        self.succeeded_function = succeeded_function
        self.lock = threading.Lock()
        self.counter = 0

    def bump_count(self) -> None:
        with self.lock:
            self.counter += 1

    def operation_succeeded(self) -> None:
        with self.lock:
            self.counter -= 1
            if self.counter == 0:
                self.succeeded_function()

    def operation_failed(self) -> None:
        pass

    def get_session_timeouts(self) -> Tuple[float, float]:
        pass

    def should_retry(self) -> bool:
        pass

    def get_retry_backoff(self, proposed_backoff_seconds: Optional[float] = None) -> Tuple[float, str]:
        pass


class GracefulRetryManager(RetryManager):
    def __init__(self):
        super().__init__()
        self.lock = threading.Lock()
        self.working_handlers = {}

    def get_handler(self, api_or_method_name: str, url: str) -> RetryHandler:
        with self.lock:
            handler = self.working_handlers.get(url)
            if handler is None:
                handler = GracefulRetryHandler(lambda bound_url=url: self._purge_handler(bound_url))
                self.working_handlers[url] = handler
            handler.bump_count()
            return handler

    def _purge_handler(self, url: str) -> None:
        with self.lock:
            del self.working_handlers[url]
