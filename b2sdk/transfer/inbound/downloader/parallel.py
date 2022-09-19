######################################################################
#
# File: b2sdk/transfer/inbound/downloader/parallel.py
#
# Copyright 2020 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

from concurrent import futures
from io import IOBase
from typing import Optional
import logging
import queue
import threading
import abc
import os
from pathlib import Path

from requests.models import Response
from liburing import io_uring, io_uring_queue_init, io_uring_queue_exit, io_uring_cqes

from .abstract import AbstractDownloader
from b2sdk.encryption.setting import EncryptionSetting
from b2sdk.file_version import DownloadVersion
from b2sdk.session import B2Session
from b2sdk.utils.range_ import Range

logger = logging.getLogger(__name__)

# ---------------------------------------
from liburing import *

def open(ring, cqes, path, flags, mode=0o660, dir_fd=AT_FDCWD):
    _path = path if isinstance(path, bytes) else str(path).encode()
    # if `path` is relative and `dir_fd` is `AT_FDCWD`, then `path` is relative to current working
    # directory. Also `_path` must be in bytes

    sqe = io_uring_get_sqe(ring)  # sqe(submission queue entry)
    io_uring_prep_openat(sqe, dir_fd, _path, flags, mode)
    return _submit_and_wait(ring, cqes)  # returns fd


def write(ring, cqes, fd, data, offset=0):
    buffer = bytearray(data)
    iov = iovec(buffer)

    sqe = io_uring_get_sqe(ring)
    io_uring_prep_write(sqe, fd, iov[0].iov_base, iov[0].iov_len, offset)
    return _submit_and_wait(ring, cqes)  # returns length(s) of bytes written


def read(ring, cqes, fd, length, offset=0):
    buffer = bytearray(length)
    iov = iovec(buffer)

    sqe = io_uring_get_sqe(ring)
    io_uring_prep_read(sqe, fd, iov[0].iov_base, iov[0].iov_len, offset)
    read_length = _submit_and_wait(ring, cqes)  # get actual length of file read.
    return buffer[:read_length]


def close(ring, cqes, fd):
    sqe = io_uring_get_sqe(ring)
    io_uring_prep_close(sqe, fd)
    _submit_and_wait(ring, cqes)  # no error means success!


def _submit_and_wait(ring, cqes):
    io_uring_submit(ring)  # submit entry
    io_uring_wait_cqe(ring, cqes)  # wait for entry to finish
    cqe = cqes[0]  # cqe(completion queue entry)
    result = trap_error(cqe.res)  # auto raise appropriate exception if failed
    # note `cqe.res` returns results, if `< 0` its an error, if `>= 0` its the value

    # done with current entry so clear it from completion queue.
    io_uring_cqe_seen(ring, cqe)
    return result  # type: int

# -----------------------------------


class Writer(abc.ABC):
    def __init__(self, file, max_queue_depth):
        ...

    def __enter__(self):
        ...

    def __exit__(self, exc_type, exc_val, exc_tb):
        ...


class WriterThread(threading.Thread, Writer):
    """
    A thread responsible for keeping a queue of data chunks to write to a file-like object and for actually writing them down.
    Since a single thread is responsible for synchronization of the writes, we avoid a lot of issues between userspace and kernelspace
    that would normally require flushing buffers between the switches of the writer. That would kill performance and not synchronizing
    would cause data corruption (probably we'd end up with a file with unexpected blocks of zeros preceding the range of the writer
    that comes second and writes further into the file).

    The object of this class is also responsible for backpressure: if items are added to the queue faster than they can be written
    (see GCP VMs with standard PD storage with faster CPU and network than local storage,
    https://github.com/Backblaze/B2_Command_Line_Tool/issues/595), then ``obj.queue.put(item)`` will block, slowing down the producer.

    The recommended minimum value of ``max_queue_depth`` is equal to the amount of producer threads, so that if all producers
    submit a part at the exact same time (right after network issue, for example, or just after starting the read), they can continue
    their work without blocking. The writer should be able to store at least one data chunk before a new one is retrieved, but
    it is not guaranteed.

    Therefore, the recommended value of ``max_queue_depth`` is higher - a double of the amount of producers, so that spikes on either
    end (many producers submit at the same time / consumer has a latency spike) can be accommodated without sacrificing performance.

    Please note that a size of the chunk and the queue depth impact the memory footprint. In a default setting as of writing this,
    that might be 10 downloads, 8 producers, 1MB buffers, 2 buffers each = 8*2*10 = 160 MB (+ python buffers, operating system etc).
    """

    def __init__(self, file, max_queue_depth):
        self.file = file
        self.queue = queue.Queue(max_queue_depth)
        self.total = 0
        super(WriterThread, self).__init__()

    def run(self):
        file = self.file
        queue_get = self.queue.get
        while 1:
            shutdown, offset, data = queue_get()
            if shutdown:
                break
            file.seek(offset)
            file.write(data)
            self.total += len(data)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.queue.put((True, None, None))
        self.join()


class ParallelDownloader(AbstractDownloader):
    # situations to consider:
    #
    # local file start                                         local file end
    # |                                                                     |
    # |                                                                     |
    # |      write range start                        write range end       |
    # |      |                                                      |       |
    # v      v                                                      v       v
    # #######################################################################
    #        |          |          |          |          |          |
    #         \        / \        / \        / \        / \        /
    #           part 1     part 2     part 3     part 4     part 5
    #         /        \ /        \ /        \ /        \ /        \
    #        |          |          |          |          |          |
    #      #######################################################################
    #      ^                                                                     ^
    #      |                                                                     |
    #      cloud file start                                         cloud file end
    #
    FINISH_HASHING_BUFFER_SIZE = 1024**2
    WRITER_CLASS: Writer = WriterThread

    def __init__(self, min_part_size: int, max_streams: Optional[int] = None, **kwargs):
        """
        :param max_streams: maximum number of simultaneous streams
        :param min_part_size: minimum amount of data a single stream will retrieve, in bytes
        """
        super().__init__(**kwargs)
        self.max_streams = max_streams
        self.min_part_size = min_part_size

    def is_suitable(self, download_version: DownloadVersion, allow_seeking: bool) -> bool:
        if not super().is_suitable(download_version, allow_seeking):
            return False
        return self._get_number_of_streams(
            download_version.content_length
        ) >= 2 and download_version.content_length >= 2 * self.min_part_size

    def _get_number_of_streams(self, content_length):
        num_streams = content_length // self.min_part_size
        if self.max_streams is not None:
            num_streams = min(num_streams, self.max_streams)
        else:
            max_threadpool_workers = getattr(self._thread_pool, '_max_workers', None)
            if max_threadpool_workers is not None:
                num_streams = min(num_streams, max_threadpool_workers)
        return num_streams

    def download(
        self,
        file: IOBase,
        response: Response,
        download_version: DownloadVersion,
        session: B2Session,
        encryption: Optional[EncryptionSetting] = None,
    ):
        """
        Download a file from given url using parallel download sessions and stores it in the given download_destination.
        """
        remote_range = self._get_remote_range(response, download_version)
        actual_size = remote_range.size()
        start_file_position = file.tell()
        parts_to_download = list(
            gen_parts(
                remote_range,
                Range(start_file_position, start_file_position + actual_size - 1),
                part_count=self._get_number_of_streams(download_version.content_length),
            )
        )

        first_part = parts_to_download[0]

        hasher = self._get_hasher()

        with self.WRITER_CLASS(file, max_queue_depth=len(parts_to_download) * 2) as writer:
            self._get_parts(
                response,
                session,
                writer,
                hasher,
                first_part,
                parts_to_download[1:],
                self._get_chunk_size(actual_size),
                encryption=encryption,
            )
        bytes_written = writer.total

        # At this point the hasher already consumed the data until the end of first stream.
        # Consume the rest of the file to complete the hashing process
        if self._check_hash:
            # we skip hashing if we would not check it - hasher object is actually a EmptyHasher instance
            # but we avoid here reading whole file (except for the first part) from disk again
            self._finish_hashing(first_part, file, hasher, download_version.content_length)

        return bytes_written, hasher.hexdigest()

    def _finish_hashing(self, first_part, file, hasher, content_length):
        end_of_first_part = first_part.local_range.end + 1
        file.seek(end_of_first_part)
        file_read = file.read

        last_offset = first_part.local_range.start + content_length
        current_offset = end_of_first_part
        stop = False
        while 1:
            data = file_read(self.FINISH_HASHING_BUFFER_SIZE)
            if not data:
                break
            if current_offset + len(data) >= last_offset:
                to_hash = data[:last_offset - current_offset]
                stop = True
            else:
                to_hash = data
            hasher.update(data)
            current_offset += len(to_hash)
            if stop:
                break

    def _get_parts(
        self, response, session, writer, hasher, first_part, parts_to_download, chunk_size,
        encryption
    ):
        from concurrent.futures import ThreadPoolExecutor
        self._thread_pool = ThreadPoolExecutor(max_workers=1)
        stream = self._thread_pool.submit(
            download_first_part,
            response,
            hasher,
            session,
            writer,
            first_part,
            chunk_size,
            encryption=encryption,
        )
        streams = [stream]

        for part in parts_to_download:
            stream = self._thread_pool.submit(
                download_non_first_part,
                response.request.url,
                session,
                writer,
                part,
                chunk_size,
                encryption=encryption,
            )
            streams.append(stream)

        futures.wait(streams)


class LiburingWriter(Writer):
    file_path = Path('/tmp/downloaded_file')  # TODO: don't hardcode this
    file_descriptor = 0
    total = 0

    def __init__(self, file: IOBase, max_queue_depth: int):
        logging.debug('Initializing uring')
        self.file = file
        self.lock = threading.Lock()
        self.file_path.unlink(missing_ok=True)
        self.ring = io_uring()
        self.cqes = io_uring_cqes()

        # liburing.io_uring_queue_init(32, self.ring, 0)  # TODO max_queue_depth?

        class Queue:
            """ Dummy implementation of writer.queue.put(...) interface """
            @staticmethod
            def put(payload):
                _, offset, data = payload
                self._write(offset, data)

        self.queue = Queue

    def __enter__(self):
        logging.debug('Starting %s', self.__class__.__name__)
        io_uring_queue_init(8, self.ring, 0)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        io_uring_queue_exit(self.ring)

        # TODO: temp hack to read file content into IOBase
        self.file.seek(0)
        data = self.file_path.read_bytes()
        self.file.write(data)

    # def get_submission_queue_entry(self) -> int:  # not sure about return type
    #     return liburing.io_uring_get_sqe(self.ring)

    # def _submit(self):
    #     logger.debug('- Submitting an action')
    #     liburing.io_uring_submit(self.ring)

    # def _wait(self) -> int:
    #     logger.debug('- Waiting for completion')
    #     liburing.io_uring_wait_cqe(self.ring, self.completion_queue)
    #     completion_queue_entry = self.completion_queue[0]
    #     logger.debug('- Got completion queue entry: %s', completion_queue_entry)
    #     result = liburing.trap_error(completion_queue_entry.res)
    #     logger.debug('- Marking completion queue entry as seen')
    #     liburing.io_uring_cqe_seen(self.ring, completion_queue_entry)
    #     logger.debug('- Returning result: %s', result)
    #     return result

    # def _open(self):
    #     # with self.lock:
    #     assert not self.file_descriptor
    #     logger.debug('Preparing to open file')

    #     entry = self.get_submission_queue_entry()
    #     liburing.io_uring_prep_openat(
    #         entry,
    #         liburing.AT_FDCWD,
    #         str(self.file_path).encode(),
    #         os.O_CREAT | os.O_RDWR,
    #         0o660,
    #     )

    #     logger.debug('Submitting file open operation and waiting for result')
    #     self.file_descriptor = self._submit() or self._wait()
    #     assert self.file_path.exists()
    #     logger.debug('Success, opened file descriptor: %s', self.file_descriptor)

    #     # # TODO: TEST, REMOVE
    #     # self._fd = open(self._ring, self._cqes, str(self._test_file), os.O_CREAT | os.O_RDWR)
    #     # print('fd:', self._fd)

    #     # # TODO: TEST, REMOVE
    #     # length = write(self._ring, self._cqes, self._fd, b'hello world')
    #     # print('wrote:', length)
    #     # # content = read(self._ring, self._cqes, fd, length)
    #     # # print('read:', content)
    #     # if not hasattr(self, '_shut_up'):
    #     #     self._shut_up = True
    #     #     close(self._ring, self._cqes, self._fd)
    #     #     print('closed')
    #     #     io_uring_queue_exit(self._ring)
    #     #     assert self._test_file.exists()
    #     #     assert self._test_file.read_bytes() == b'hello world'
    #     #     assert False, "hoho trololo"

    def _write(self, offset: int, data: bytes):
        with self.lock:
            # self._open()
            # # logger.debug('Preparing file write operation')
            # iov = liburing.iovec(bytearray(data))
            # # breakpoint()
            # liburing.io_uring_prep_write(
            #     self.get_submission_queue_entry(),
            #     self.file_descriptor,
            #     iov[0].iov_base,
            #     iov[0].iov_len,
            #     offset,
            # )
            # # logger.debug('Submitting file write operation and waiting')
            # # self.total += self._submit_and_wait()
            # # logger.debug('File write operation completed')

            # logger.debug('Submitting file write operation')
            # self._submit() or self._wait()
            # self._close()
            # # liburing.io_uring_queue_exit(self.ring)
            # logger.debug('Submitted file write operation, not waiting')

            fd = open(self.ring, self.cqes, str(self.file_path), os.O_CREAT | os.O_RDWR)
            self.total += write(self.ring, self.cqes, fd, data, offset)
            close(self.ring, self.cqes, fd)


    # def _close(self):
    #     # with self.lock:
    #     # breakpoint()
    #     # assert self.file_descriptor

    #     # logger.debug('Closing, completion queue size: %s', len(self.completion_queue))
    #     # for i in range(len(self.completion_queue)):
    #     #     logger.debug('Waiting for completion queue entry #%s', i)
    #     #     liburing.io_uring_wait_cqe(self.ring, self.completion_queue)  # TODO: does it wait for one entry, or for all of them?
    #     #     completion_queue_entry = self.completion_queue[0]
    #     #     logger.debug('Retrieving completion queue entry %s result', completion_queue_entry)
    #     #     self.total += liburing.trap_error(completion_queue_entry.res)
    #     #     logger.debug('Marking completion queue entry %s as seen', completion_queue_entry)
    #     #     liburing.io_uring_cqe_seen(self.ring, completion_queue_entry)

    #     # logger.debug('Preparing file close operation')
    #     # liburing.io_uring_prep_close(self.get_submission_queue_entry(), self.file_descriptor)
    #     # logger.debug('Submitting file close operation and waiting')
    #     # self._submit() or self._wait()
    #     # self.file_descriptor = None
    #     # logger.debug('File closed')

    #     # for i in range(len(self.completion_queue) - 1):
    #     #     logger.debug(f'Waiting operation #{i}')
    #     #     self.total += self._wait()
    #     # self._wait()  # wait file close

    #     # breakpoint()



class LiburingDownloader(ParallelDownloader):
    WRITER_CLASS: Writer = LiburingWriter


def download_first_part(
    response: Response,
    hasher,
    session: B2Session,
    writer: WriterThread,
    first_part: 'PartToDownload',
    chunk_size: int,
    encryption: Optional[EncryptionSetting] = None,
) -> None:
    """
    :param response: response of the original GET call
    :param hasher: hasher object to feed to as the stream is written
    :param session: B2 API session
    :param writer: thread responsible for writing downloaded data
    :param first_part: definition of the part to be downloaded
    :param chunk_size: size (in bytes) of read data chunks
    :param encryption: encryption mode, algorithm and key
    """

    writer_queue_put = writer.queue.put
    hasher_update = hasher.update
    first_offset = first_part.local_range.start
    last_offset = first_part.local_range.end + 1
    actual_part_size = first_part.local_range.size()
    starting_cloud_range = first_part.cloud_range

    bytes_read = 0
    stop = False
    for data in response.iter_content(chunk_size=chunk_size):
        if first_offset + bytes_read + len(data) >= last_offset:
            to_write = data[:last_offset - bytes_read]
            stop = True
        else:
            to_write = data
        writer_queue_put((False, first_offset + bytes_read, to_write))
        hasher_update(to_write)
        bytes_read += len(to_write)
        if stop:
            break

    # since we got everything we need from original response, close the socket and free the buffer
    # to avoid a timeout exception during hashing and other trouble
    response.close()

    url = response.request.url
    tries_left = 5 - 1  # this is hardcoded because we are going to replace the entire retry interface soon, so we'll avoid deprecation here and keep it private
    while tries_left and bytes_read < actual_part_size:
        cloud_range = starting_cloud_range.subrange(
            bytes_read, actual_part_size - 1
        )  # first attempt was for the whole file, but retries are bound correctly
        logger.debug(
            'download attempts remaining: %i, bytes read already: %i. Getting range %s now.',
            tries_left, bytes_read, cloud_range
        )
        with session.download_file_from_url(
            url,
            cloud_range.as_tuple(),
            encryption=encryption,
        ) as response:
            for to_write in response.iter_content(chunk_size=chunk_size):
                writer_queue_put((False, first_offset + bytes_read, to_write))
                hasher_update(to_write)
                bytes_read += len(to_write)
        tries_left -= 1


def download_non_first_part(
    url: str,
    session: B2Session,
    writer: WriterThread,
    part_to_download: 'PartToDownload',
    chunk_size: int,
    encryption: Optional[EncryptionSetting] = None,
) -> None:
    """
    :param url: download URL
    :param session: B2 API session
    :param writer: thread responsible for writing downloaded data
    :param part_to_download: definition of the part to be downloaded
    :param chunk_size: size (in bytes) of read data chunks
    :param encryption: encryption mode, algorithm and key
    """
    writer_queue_put = writer.queue.put
    start_range = part_to_download.local_range.start
    actual_part_size = part_to_download.local_range.size()
    bytes_read = 0

    starting_cloud_range = part_to_download.cloud_range

    retries_left = 5  # this is hardcoded because we are going to replace the entire retry interface soon, so we'll avoid deprecation here and keep it private
    while retries_left and bytes_read < actual_part_size:
        cloud_range = starting_cloud_range.subrange(bytes_read, actual_part_size - 1)
        logger.debug(
            'download attempts remaining: %i, bytes read already: %i. Getting range %s now.',
            retries_left, bytes_read, cloud_range
        )
        with session.download_file_from_url(
            url,
            cloud_range.as_tuple(),
            encryption=encryption,
        ) as response:
            for to_write in response.iter_content(chunk_size=chunk_size):
                writer_queue_put((False, start_range + bytes_read, to_write))
                bytes_read += len(to_write)
        retries_left -= 1


class PartToDownload:
    """
    Hold the range of a file to download, and the range of the
    local file where it should be stored.
    """

    def __init__(self, cloud_range, local_range):
        self.cloud_range = cloud_range
        self.local_range = local_range

    def __repr__(self):
        return 'PartToDownload(%s, %s)' % (self.cloud_range, self.local_range)


def gen_parts(cloud_range, local_range, part_count):
    """
    Generate a sequence of PartToDownload to download a large file as
    a collection of parts.
    """
    assert cloud_range.size() == local_range.size(), (cloud_range.size(), local_range.size())
    assert 0 < part_count <= cloud_range.size()
    offset = 0
    remaining_size = cloud_range.size()
    for i in range(part_count):
        # This rounds down, so if the parts aren't all the same size,
        # the smaller parts will come first.
        this_part_size = remaining_size // (part_count - i)
        part = PartToDownload(
            cloud_range.subrange(offset, offset + this_part_size - 1),
            local_range.subrange(offset, offset + this_part_size - 1),
        )
        logger.debug('created part to download: %s', part)
        yield part
        offset += this_part_size
        remaining_size -= this_part_size
