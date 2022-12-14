######################################################################
#
# File: test/unit/internal/curl/test_streamed_bytes.py
#
# Copyright 2022 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

import unittest.mock

from b2sdk.utils.streamed_bytes import StreamedBytes
from test.unit.test_base import TestBase


class TestStreamedBytes(TestBase):
    DATA_LEN_MULTIPLIER = 1024
    TEST_DATA = b'DEADBEEF' * DATA_LEN_MULTIPLIER

    def setUp(self) -> None:
        super().setUp()

        self.owner = unittest.mock.MagicMock()
        self.release_buffer_mock = self.owner.release_buffer
        self.buffer = StreamedBytes(self.owner)

    def test_length(self):
        data_len = 0

        def add_data(data: bytes) -> None:
            nonlocal data_len
            self.buffer.write(data)
            data_len += len(data)
            self.assertEqual(data_len, len(self.buffer))

        def remove_data(size: int) -> None:
            nonlocal data_len
            self.assertGreaterEqual(data_len, size)
            data = self.buffer.read(size)
            data_len -= len(data)
            self.assertEqual(size, len(data))
            self.assertEqual(data_len, len(self.buffer))

        add_data(b'test-1')
        add_data(b'very-long-data' * 1024)
        remove_data(data_len - 10)
        add_data(b'1' * 10)
        remove_data(data_len - 10)
        for _ in range(1000):
            add_data(b'1')
        for _ in range(data_len):
            remove_data(1)

    def test_release(self):
        self.buffer.write(self.TEST_DATA)
        self.buffer.mark_for_release()
        self.release_buffer_mock.assert_not_called()
        leave_data = 10
        self.buffer.read(len(self.TEST_DATA) - leave_data)
        self.release_buffer_mock.assert_not_called()
        self.buffer.read(leave_data)
        self.release_buffer_mock.assert_called_once_with(self.buffer)
        self.buffer.read(1)
        self.release_buffer_mock.assert_called_once_with(self.buffer)

    def test_release_from_empty_buffer(self):
        self.buffer.mark_for_release()
        self.release_buffer_mock.assert_not_called()
        self.buffer.read(1)
        self.release_buffer_mock.assert_called_once_with(self.buffer)
        self.buffer.read(1)
        self.release_buffer_mock.assert_called_once_with(self.buffer)

    def test_writing_to_marked_for_release(self):
        self.buffer.mark_for_release()
        with self.assertRaises(AssertionError):
            self.buffer.write(b'data')

    def test_reading_more_than_available(self):
        self.assertEqual(b'', self.buffer.read(1024))
        test_data = b'test-data'
        self.buffer.write(test_data)
        split_index = len(test_data) // 2
        part_1 = self.buffer.read(split_index)
        self.assertEqual(test_data[:split_index], part_1)
        part_2 = self.buffer.read(len(test_data))
        self.assertEqual(test_data[split_index:], part_2)
        self.assertEqual(b'', self.buffer.read(1024))

    def assert_test_write_and_read(self, data: bytes, write_size: int, read_size: int) -> None:
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + write_size]
            self.assertEqual(len(chunk), self.buffer.write(chunk))
            offset += len(chunk)

        read_data = bytearray()
        while len(read_data) < len(data):
            chunk = self.buffer.read(read_size)
            self.assertEqual(read_size, len(chunk))
            read_data += chunk
        self.assertEqual(data, read_data)

    def test_small_write_large_read(self):
        self.assert_test_write_and_read(
            self.TEST_DATA,
            write_size=1,
            read_size=self.DATA_LEN_MULTIPLIER,
        )

    def test_large_write_small_read(self):
        self.assert_test_write_and_read(
            self.TEST_DATA,
            write_size=self.DATA_LEN_MULTIPLIER,
            read_size=1,
        )
