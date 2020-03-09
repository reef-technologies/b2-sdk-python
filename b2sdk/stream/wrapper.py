import io


class BaseStreamWrapper(io.IOBase):
    """
    Base wrapper for a file-like object.

    It does not implement public constructor so subclasses have to define `stream` attribute
    """

    stream = NotImplemented

    def seekable(self):
        return self.stream.seekable()

    def seek(self, pos, whence=0):
        """
        Seek to a given position in the stream.

        :param int pos: position in the stream
        """
        return self.stream.seek(pos, whence)

    def tell(self):
        """
        Return current stream position.

        :rtype: int
        """
        return self.stream.tell()

    def truncate(self, size=None):
        return self.stream.truncate(size)

    def flush(self):
        """
        Flush the stream.
        """
        self.stream.flush()

    def readable(self):
        return self.stream.readable()

    def read(self, size=None):
        """
        Read data from the stream.

        :param int size: number of bytes to read
        :return: data read from the stream
        """
        return self.stream.read(size)

    def writable(self):
        return self.stream.writable()

    def write(self, data):
        """
        Write data to the stream.

        :param data: a data to write to the stream
        """
        return self.stream.write(data)

    def close(self):
        super(BaseStreamWrapper, self).close()
        self.stream.close()


class StreamWrapper(BaseStreamWrapper):
    """
    Basic wrapper for a file-like object.
    """

    def __init__(self, stream):
        """
        :param stream: the stream to read from or write to
        """
        self.stream = stream


class StreamWithLengthWrapper(StreamWrapper):
    def __init__(self, stream, length):
        super(StreamWithLengthWrapper, self).__init__(stream)
        self.length = length

    def __len__(self):
        return self.length