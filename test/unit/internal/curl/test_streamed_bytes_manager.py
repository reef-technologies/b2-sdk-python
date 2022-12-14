######################################################################
#
# File: test/unit/internal/curl/test_streamed_bytes_manager.py
#
# Copyright 2022 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

from b2sdk.utils.streamed_bytes import StreamedBytesFactory
from test.unit.test_base import TestBase


class TestStreamedBytes(TestBase):
    def setUp(self) -> None:
        super().setUp()
        self.factory = StreamedBytesFactory()

    def test_total_length(self):
        buffers = []
        for _ in range(10):
            buffers.append(self.factory.get_buffer())

        test_data = b'test-data'
        for idx, buffer in enumerate(buffers):
            buffer.write(test_data)
            self.assertEqual((idx + 1) * len(test_data), self.factory.get_total_buffer_memory())

        for idx, buffer in enumerate(buffers):
            buffer.read(len(test_data))
            self.assertEqual(
                (len(buffers) - idx - 1) * len(test_data),
                self.factory.get_total_buffer_memory(),
            )

    def test_total_length_of_empty_buffers(self):
        buffers = []
        for _ in range(10):
            buffers.append(self.factory.get_buffer())
        self.assertEqual(0, self.factory.get_total_buffer_memory())

    def test_reclaimed_non_empty_buffers_error(self):
        buffer = self.factory.get_buffer()
        buffer.write(b'test-data')
        with self.assertRaises(AssertionError):
            self.factory.release_buffer(buffer)
