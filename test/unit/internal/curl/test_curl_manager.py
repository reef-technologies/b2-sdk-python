######################################################################
#
# File: test/unit/internal/curl/test_curl_manager.py
#
# Copyright 2022 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

import threading
import unittest.mock
from concurrent.futures import (
    ThreadPoolExecutor,
    wait,
)
from typing import (
    Any,
    Tuple,
)

from test.unit.test_base import TestBase

try:
    import pycurl
    from b2sdk.utils.curl import CurlManager

    DISABLE_TESTS = False
except (ImportError, ModuleNotFoundError):
    DISABLE_TESTS = True


@unittest.skipIf(DISABLE_TESTS, 'pycurl not available on the system')
class TestCurlManager(TestBase):
    MEMORY_LIMIT_BYTES = 20

    def setUp(self) -> None:
        super().setUp()

        with unittest.mock.patch('pycurl.CurlMulti'):
            self.manager = CurlManager(self.MEMORY_LIMIT_BYTES)

        self.manager.multi.perform.return_value = (pycurl.E_MULTI_OK, None)
        self.manager.multi.info_read.return_value = (0, [], [])

    def test_too_much_data_skips_iteration(self):
        buffer = self.manager.buffers_factory.get_buffer()
        self.manager.run_iteration()
        self.assertEqual(1, self.manager.multi.perform.call_count)
        buffer.write(b'1' * self.MEMORY_LIMIT_BYTES)
        self.manager.run_iteration()
        self.assertEqual(1, self.manager.multi.perform.call_count)
        buffer.read(1)
        self.manager.run_iteration()
        self.assertEqual(2, self.manager.multi.perform.call_count)

    def test_informing_streamer_when_done(self):
        streamer = unittest.mock.MagicMock()
        streamer.curl = unittest.mock.MagicMock()
        self.manager.add_curl(streamer)

        side_effects = [
            (0, [], []),
            (0, [], []),
            (0, [streamer.curl], []),
        ]

        self.manager.multi.info_read.side_effect = side_effects

        for idx in range(len(side_effects)):
            self.manager.run_iteration()
            if idx < (len(side_effects) - 1):
                streamer.close.assert_not_called()
            else:
                streamer.close.assert_called_once()

    def test_at_most_one_iteration_in_parallel(self):
        parallel_factor = 5
        events = [threading.Event() for _ in range(parallel_factor)]

        def runner(manager, event):
            manager.run_iteration()
            event.set()

        def waiter() -> Tuple[int, Any]:
            # If we're the first to get here, we should be blocking everyone else, so
            # we're just checking whether enough events are set before releasing.
            # This loop is a hard timeout on the operation.
            for _ in range(100):
                count_done = sum([1 for event in events if event.is_set()])
                if count_done >= (parallel_factor - 1):
                    break

                unset_events = [event for event in events if not event.is_set()]
                # It's possible that in the meantime all events were finished.
                if len(unset_events) > 0:
                    first_unset_event = unset_events[0]
                    first_unset_event.wait(self.manager.ACQUIRE_SLEEP_SECONDS)
            else:
                raise ValueError

            return pycurl.E_MULTI_OK, None

        self.manager.multi.perform.side_effect = waiter

        with ThreadPoolExecutor(max_workers=parallel_factor) as pool:
            futures = []
            for idx in range(parallel_factor):
                futures.append(pool.submit(runner, self.manager, events[idx]))

            wait(futures)

            # Just in case, check for exceptions raised.
            for future in futures:
                future.result()

            self.manager.multi.perform.assert_called_once()
