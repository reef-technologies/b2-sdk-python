######################################################################
#
# File: b2sdk/retries/retry_manager.py
#
# Copyright 2023 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
from typing import Optional, Tuple


class RetryHandler:
    def operation_succeeded(self) -> None:
        pass

    def operation_failed(self) -> None:
        pass

    def get_session_timeouts(self) -> Tuple[float, float]:
        pass

    def should_retry(self) -> bool:
        pass

    def get_retry_backoff(self, proposed_backoff_seconds: Optional[float] = None) -> Tuple[float, str]:
        pass


class RetryManager:
    def get_handler(self, api_or_method_name: str) -> RetryHandler:
        pass
