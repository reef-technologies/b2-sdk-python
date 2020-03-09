######################################################################
#
# File: b2sdk/stream/hashing.py
#
# Copyright 2020 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

import hashlib
import io

from b2sdk.stream.wrapper import StreamWithLengthWrapper
from b2sdk.stream.base import ReadOnlyStreamMixin


class StreamWithHash(ReadOnlyStreamMixin, StreamWithLengthWrapper):
    """
    Wrap a file-like object, calculates SHA1 while reading
    and appends hash at the end.
    """

    def __init__(self, stream, stream_length):
        """
        :param stream: the stream to read from
        """
        self.digest = self.get_digest()
        super(StreamWithHash, self).__init__(stream, stream_length + self.digest.digest_size * 2)
        self.hash = None
        self.hash_read = 0

    def seek(self, pos, whence=0):
        """
        Seek to a given position in the stream.

        :param int pos: position in the stream
        """
        if pos != 0 or whence != 0:
            raise io.UnsupportedOperation('Stream with hash can only be seeked to beginning')
        self.digest = self.get_digest()
        self.hash = None
        self.hash_read = 0
        return super(StreamWithHash, self).seek(0)

    def read(self, size=None):
        """
        Read data from the stream.

        :param int size: number of bytes to read
        :return: read data
        :rtype: bytes|None
        """
        data = b''
        if self.hash is None:
            data = super(StreamWithHash, self).read(size)
            # Update hash
            self.digest.update(data)

            # Check for end of stream
            if size is None or len(data) < size:
                self.hash = self.digest.hexdigest()
                if size is not None:
                    size -= len(data)

        if self.hash is not None:
            # The end of stream was reached, return hash now
            size = size or len(self.hash)
            data += str.encode(self.hash[self.hash_read:self.hash_read + size])
            self.hash_read += size
        return data

    @classmethod
    def get_digest(cls):
        return hashlib.sha1()