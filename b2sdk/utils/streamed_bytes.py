######################################################################
#
# File: b2sdk/utils/streamed_bytes.py
#
# Copyright 2022 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

import collections
import threading
from contextlib import ExitStack
from typing import Optional


class StreamedBytes:
    """
    Structure that works "kinda" like an unlimited ring buffer.

    We can put the data on one side and read it from the other,
    and the data read is lost (memory is released).
    """

    def __init__(self, owner: 'StreamedBytesFactory'):
        # We store our data in chunks in a deque. Whenever data is requested,
        # we remove them from deque up to the size, and put back the reminder.
        self.deque = collections.deque()
        self.lock = threading.Lock()
        self.first_write_event = threading.Event()
        self.length = 0
        self.owner = owner
        self.is_marked_for_release = threading.Event()

    def is_empty(self) -> bool:
        with self.lock:
            return len(self.deque) == 0

    def mark_for_release(self) -> None:
        self.is_marked_for_release.set()

    def __len__(self):
        return self.length

    def write(self, buffer: bytes) -> int:
        # pycurl.Curl.setopt with pycurl.WRITEDATA will use a `write` method of provided object.
        # Thus, this method must be named `write`.
        with self.lock:
            assert not self.is_marked_for_release.is_set(), \
                'Trying to write to a buffer marked for release'

            if len(buffer) == 0:
                return 0

            # Whole buffer is stored in a deque (double-linked list).
            # This way we have fewer, (hopefully) larger elements.
            self.deque.append(buffer)
            self.length += len(buffer)

            # If we haven't informed everyone yet, it's the time. We've received
            # first buffer of data. This is used to indicate that all the headers
            # are already downloaded.
            if not self.first_write_event.is_set():
                self.first_write_event.set()

            return len(buffer)

    def read(self, size: Optional[int] = None) -> bytes:
        stack = ExitStack()
        stack.enter_context(self.lock)
        stack.push(self._check_and_release_buffer)

        with stack:
            result = bytearray()

            if len(self.deque) == 0:
                return result

            while True:
                entry = self.deque.popleft()
                new_len_result = len(result) + len(entry)

                if new_len_result > size:
                    oversize = new_len_result - size
                    # Return over-sized buffer to the queue.
                    oversize_buffer = entry[-oversize:]
                    self.deque.appendleft(oversize_buffer)
                    # Cut down next entry.
                    entry = entry[:-oversize]

                result += entry

                if (size != -1 and len(result) == size) or len(self.deque) == 0:
                    break

            self.length -= len(result)
            return result

    def _check_and_release_buffer(self, *_args) -> bool:
        if self.is_marked_for_release.is_set() and self.length == 0:
            self.owner.release_buffer(self)
            self.is_marked_for_release.clear()
        return True


class StreamedBytesFactory:
    """
    Source of StreamedBytes buffers.

    Keeps track of all the fetched buffers and allows for a simple
    check of a total amount of memory used by them.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.buffers = []

    def get_buffer(self) -> StreamedBytes:
        with self.lock:
            buffer = StreamedBytes(owner=self)
            self.buffers.append(buffer)
            return buffer

    def release_buffer(self, buffer: StreamedBytes) -> None:
        with self.lock:
            assert len(buffer) == 0, 'Non-empty buffer released'
            self.buffers.remove(buffer)

    def get_total_buffer_memory(self) -> int:
        with self.lock:
            return sum([len(entry) for entry in self.buffers])
