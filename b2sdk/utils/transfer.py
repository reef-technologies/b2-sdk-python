######################################################################
#
# File: b2sdk/utils/transfer.py
#
# Copyright 2023 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
from datetime import datetime, timedelta
from typing import Optional


class RetryCounter:
    MAXIMUM_RETRY_ATTEMPTS = 5

    def __init__(self, retry_time: Optional[timedelta] = None):
        """
        :param retry_time: maximum retry time when a transfer fails. If it's not given, it will perform constant number of retries.
        """
        self.retry_time = retry_time

    def start(self):
        if self.retry_time:
            self.start_time = datetime.now()
        else:
            self.retries_left = self.MAXIMUM_RETRY_ATTEMPTS

    def count_and_check(self):
        if self.retry_time:
            return (datetime.now() - self.start_time) < self.retry_time
        else:
            self.retries_left -= 1
            return self.retries_left >= 0

    def get_remaining_attempts(self):
        if self.retry_time:
            return (self.retry_time - (datetime.now() - self.start_time)).total_seconds()
        else:
            return self.retries_left
