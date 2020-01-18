import logging
import six

from b2sdk.exception import (
    AlreadyFailed,
    B2Error,
    MaxFileSizeExceeded,
    MaxRetriesExceeded,
)
from b2sdk.file_version import FileVersionInfoFactory
from b2sdk.progress import (ReadingStreamWithProgress, StreamWithHash)
from b2sdk.raw_api import HEX_DIGITS_AT_END
from b2sdk.utils import B2TraceMetaAbstract, choose_part_ranges, hex_sha1_of_stream, interruptible_get_result

from .large_file_upload_state import LargeFileUploadState
from .progress_reporter import PartProgressReporter
from .upload_source_part import UploadSourcePart

try:
    import concurrent.futures as futures
except ImportError:
    import futures

logger = logging.getLogger(__name__)


@six.add_metaclass(B2TraceMetaAbstract)
class UploadManager(object):
    """
    Handle complex actions around uploads to free raw_api from that responsibility.
    """

    MAX_UPLOAD_ATTEMPTS = 5
    MAX_LARGE_FILE_SIZE = 10 * 1000 * 1000 * 1000 * 1000  # 10 TB

    def __init__(self, session, services, max_upload_workers=10):
        """
        Initialize the CopyManager using the given session.

        :param session: an instance of :class:`~b2sdk.v1.B2Session`,
                      or any custom class derived from
                      :class:`~b2sdk.v1.B2Session`
        :param services: an instace of :class:`~b2sdk.v1.Services`
        :param int max_upload_workers: a number of upload threads, default is 10
        """
        self.session = session
        self.services = services

        self.upload_executor = None
        self.max_workers = max_upload_workers

    @property
    def account_info(self):
        return self.session.account_info

    def set_thread_pool_size(self, max_workers):
        """
        Set the size of the thread pool to use for uploads and downloads.

        Must be called before any work starts, or the thread pool will get
        the default size of 1.

        :param int max_workers: maximum allowed number of workers in a pool
        """
        if self.upload_executor is not None:
            raise Exception('thread pool already created')
        self.max_workers = max_workers

    def get_thread_pool(self):
        """
        Return the thread pool executor to use for uploads and downloads.
        """
        if self.upload_executor is None:
            self.upload_executor = futures.ThreadPoolExecutor(max_workers=self.max_workers)
        return self.upload_executor

    def upload(
        self,
        bucket_id,
        upload_source,
        file_name,
        content_type,
        file_info,
        progress_listener,
        min_large_file_size=None
    ):
        """
        Upload a file to B2, retrying as needed.

        The source of the upload is an UploadSource object that can be used to
        open (and re-open) the file.  The result of opening should be a binary
        file whose read() method returns bytes.

        :param :param str bucket_id: a bucket ID
        :param b2sdk.v1.UploadSource upload_source: an object that opens the source of the upload
        :param str file_name: the file name of the new B2 file
        :param str,None content_type: the MIME type, or ``None`` to accept the default based on file extension of the B2 file name
        :param dict,None file_info: a file info to store with the file or ``None`` to not store anything
        :param b2sdk.v1.AbstractProgressListener progress_listener: a progress listener object to use
        :param int,None min_large_file_size: the smallest size that would upload large file or ``None`` to determine automatically

        The function `opener` should return a file-like object, and it
        must be possible to call it more than once in case the upload
        is retried.
        """

        # We don't upload any large files unless all of the parts can be at least
        # the minimum part size.
        if min_large_file_size is None:
            min_large_file_size = self.account_info.get_minimum_part_size() * 2

        if upload_source.get_content_length() < min_large_file_size:
            # Run small uploads in the same thread pool as large file uploads,
            # so that they share resources during a sync.
            f = self.get_thread_pool().submit(
                self._upload_small_file,
                bucket_id,
                upload_source,
                file_name,
                content_type,
                file_info,
                progress_listener,
            )
            return f.result()
        else:
            return self._upload_large_file(
                bucket_id,
                upload_source,
                file_name,
                content_type,
                file_info,
                progress_listener,
            )

    def split_upload_source(self, upload_source):
        """
        Split upload source to upload source part for large file upload

        :param b2sdk.v1.UploadSource upload_source: an object that opens the source of the upload
        """
        minimum_part_size = self.account_info.get_minimum_part_size()
        part_ranges = choose_part_ranges(upload_source.get_content_length(), minimum_part_size)
        for (part_number, (source_offset, part_length)) in enumerate(part_ranges, 1):
            yield UploadSourcePart(upload_source, source_offset, part_length, part_number)

    def upload_part(
        self, bucket_id, file_id, upload_source_part, large_file_upload_state, finished_parts=None
    ):
        """
        Upload a file part to started large file.

        :param :param str bucket_id: a bucket ID
        :param file_id: a large file ID
        :param b2sdk.v1.UploadSourcePart upload_source_part: wrapper for upload source that reads only required range
        :param b2sdk.v1.LargeFileUploadState large_file_upload_state: state object for progress reporting
                                                                      on large file upload
        :param dict,None finished_parts: dictionary of known finished parts, keys are part numbers,
                                         values are instances of :class:`~b2sdk.v1.Part`
        """
        # Check if this part was uploaded before
        if finished_parts is not None and upload_source_part.part_number in finished_parts:
            # Report this part finished
            part = finished_parts[upload_source_part.part_number]
            large_file_upload_state.update_part_bytes(part.content_length)

            # Return SHA1 hash
            return {'contentSha1': part.content_sha1}

        # Set up a progress listener
        part_progress_listener = PartProgressReporter(large_file_upload_state)

        # Retry the upload as needed
        exception_list = []
        for _ in six.moves.xrange(self.MAX_UPLOAD_ATTEMPTS):
            # if another part has already had an error there's no point in
            # uploading this part
            if large_file_upload_state.has_error():
                raise AlreadyFailed(large_file_upload_state.get_error_message())

            try:
                with upload_source_part.range_of_input_stream() as range_stream:
                    input_stream = ReadingStreamWithProgress(range_stream, part_progress_listener)
                    hashing_stream = StreamWithHash(input_stream)
                    length_with_hash = upload_source_part.part_length + hashing_stream.hash_size()
                    response = self.session.upload_part(
                        file_id, upload_source_part.part_number, length_with_hash,
                        HEX_DIGITS_AT_END, hashing_stream
                    )
                    assert hashing_stream.hash == response['contentSha1']
                    return response

            except B2Error as e:
                if not e.should_retry_upload():
                    raise
                exception_list.append(e)
                self.account_info.clear_bucket_upload_data(bucket_id)

        large_file_upload_state.set_error(str(exception_list[-1]))
        raise MaxRetriesExceeded(self.MAX_UPLOAD_ATTEMPTS, exception_list)

    def _upload_small_file(
        self, bucket_id, upload_source, file_name, content_type, file_info, progress_listener
    ):
        content_length = upload_source.get_content_length()
        exception_info_list = []
        progress_listener.set_total_bytes(content_length)
        with progress_listener:
            for _ in six.moves.xrange(self.MAX_UPLOAD_ATTEMPTS):
                try:
                    with upload_source.open() as file:
                        input_stream = ReadingStreamWithProgress(file, progress_listener)
                        hashing_stream = StreamWithHash(input_stream)
                        length_with_hash = content_length + hashing_stream.hash_size()
                        response = self.session.upload_file(
                            bucket_id, file_name, length_with_hash, content_type, HEX_DIGITS_AT_END,
                            file_info, hashing_stream
                        )
                        assert hashing_stream.hash == response['contentSha1']
                        return FileVersionInfoFactory.from_api_response(response)

                except B2Error as e:
                    if not e.should_retry_upload():
                        raise
                    exception_info_list.append(e)
                    self.account_info.clear_bucket_upload_data(bucket_id)

        raise MaxRetriesExceeded(self.MAX_UPLOAD_ATTEMPTS, exception_info_list)

    def _upload_large_file(
        self, bucket_id, upload_source, file_name, content_type, file_info, progress_listener
    ):
        content_length = upload_source.get_content_length()
        if self.MAX_LARGE_FILE_SIZE < content_length:
            raise MaxFileSizeExceeded(content_length, self.MAX_LARGE_FILE_SIZE)

        # Set up the progress reporting for the parts
        progress_listener.set_total_bytes(content_length)

        # Select the part boundaries
        upload_source_parts = list(self.split_upload_source(upload_source))

        # Check for unfinished files with same name
        unfinished_file, finished_parts = self._find_unfinished_file_if_possible(
            bucket_id,
            file_name,
            file_info,
            upload_source_parts,
        )

        # Tell B2 we're going to upload a file if necessary
        if unfinished_file is None:
            unfinished_file = self.services.large_file.start_large_file(
                bucket_id, file_name, content_type, file_info
            )
        file_id = unfinished_file.file_id

        with progress_listener:
            large_file_upload_state = LargeFileUploadState(progress_listener)
            # Tell the executor to upload each of the parts
            part_futures = [
                self.get_thread_pool().submit(
                    self.upload_part,
                    bucket_id,
                    file_id,
                    upload_source_part,
                    large_file_upload_state,
                    finished_parts,
                ) for upload_source_part in upload_source_parts
            ]

            # Collect the sha1 checksums of the parts as the uploads finish.
            # If any of them raised an exception, that same exception will
            # be raised here by result()
            part_sha1_array = [interruptible_get_result(f)['contentSha1'] for f in part_futures]

        # Finish the large file
        response = self.session.finish_large_file(file_id, part_sha1_array)
        return FileVersionInfoFactory.from_api_response(response)

    def _find_unfinished_file_if_possible(
        self, bucket_id, file_name, file_info, upload_source_parts
    ):
        """
        Find an unfinished file that may be used to resume a large file upload.  The
        file is found using the filename and comparing the uploaded parts against
        the local file.

        This is only possible if the application key being used allows ``listFiles`` access.
        """
        upload_source_parts_dict = {
            upload_source_part.part_number: upload_source_part
            for upload_source_part in upload_source_parts
        }
        if 'listFiles' in self.account_info.get_allowed()['capabilities']:
            for file_ in self.services.large_file.list_unfinished_large_files(bucket_id):
                if file_.file_name == file_name and file_.file_info == file_info:
                    files_match = True
                    finished_parts = {}
                    for part in self.services.large_file.list_parts(file_.file_id):
                        # Compare part sizes
                        upload_source_part = upload_source_parts_dict[part.part_number]
                        if upload_source_part.part_length != part.content_length:
                            files_match = False
                            break

                        # Compare hash
                        with upload_source_part.upload_source.open() as f:
                            f.seek(upload_source_part.source_offset)
                            sha1_sum = hex_sha1_of_stream(f, upload_source_part.part_length)
                        if sha1_sum != part.content_sha1:
                            files_match = False
                            break

                        # Save part
                        finished_parts[part.part_number] = part

                    # Skip not matching files or unfinished files with no uploaded parts
                    if not files_match or not finished_parts:
                        continue

                    # Return first matched file
                    return file_, finished_parts
        return None, {}
