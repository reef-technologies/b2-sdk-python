import logging

import six

from b2sdk.file_version import FileVersionInfoFactory
from b2sdk.utils import B2TraceMetaAbstract, interruptible_get_result

from .outbound.large_file_upload_state import LargeFileUploadState

logger = logging.getLogger(__name__)


@six.add_metaclass(B2TraceMetaAbstract)
class Emerger(object):
    """
    Handle complex actions around multi source copy/uploads.

    This class can be used to build advanced copy workflows like incremental upload.
    """

    def __init__(self, session, services, download_manager, upload_manager, copy_manager):
        """
        Initialize the Emerger using the given session and transfer managers.

        :param session: an instance of :class:`~b2sdk.v1.B2Session`,
                      or any custom class derived from
                      :class:`~b2sdk.v1.B2Session`
        :param services: an instace of :class:`~b2sdk.v1.Services`
        :param b2sdk.v1.DownloadManager download_manager: an instace of :class:`~b2sdk.v1.DownloadManager`
        :param b2sdk.v1.UploadManager upload_manager: an instace of :class:`~b2sdk.v1.UploadManager`
        :param b2sdk.v1.CopyManager copy_manager: an instace of :class:`~b2sdk.v1.CopyManager`
        """
        self.session = session
        self.services = services
        self.download_manager = download_manager
        self.upload_manager = upload_manager
        self.copy_manager = copy_manager

    def emerge(
        self, bucket_id, emerge_ranges_iterator, file_name, content_type, file_info,
        progress_listener
    ):
        """
        Emerge (store multiple sources) of source range iterator.

        :param  str bucket_id: a bucket ID
        :param emerge_ranges_iterator: iterator of emerge ranges - range wrappers around emerge sources
                                       which are (not determined yet) polymorphism of
                                       :class:`~b2sdk.v1.CopySource` and :class:`~b2sdk.v1.UploadSource`
        :param str file_name: the file name of the new B2 file
        :param str content_type: the MIME type
        :param dict,None file_info: a file info to store with the file or ``None`` to not store anything
        :param b2sdk.v1.AbstractProgressListener progress_listener: a progress listener object to use

        Right now it is only a draft implementation that support concat interface only for files > 5mb.
        """
        # TODO: this is only a draft implementation that support concat interface only for files > 5mb

        # TODO: we assume that there is more than one emerge range on iterator
        unfinished_file = self.services.large_file.start_large_file(
            bucket_id, file_name, content_type, file_info
        )
        file_id = unfinished_file.file_id

        total_bytes = 0
        part_futures = []
        with progress_listener:
            large_file_upload_state = LargeFileUploadState(progress_listener)
            for emerge_range in emerge_ranges_iterator:
                if emerge_range.destination_offset != total_bytes:
                    raise NotImplementedError('only non overlapping ranges supported')

                emerge_source_type = emerge_range.emerge_source.get_type()

                # TODO: remeber - this is only a non working draft
                if emerge_source_type == 'upload':
                    # TODO: probably UploadSource and CopySource should inherit from EmergeSource
                    #   then `get_source()` wouldn't be required here
                    upload_source = emerge_range.emerge_source.get_source()
                    total_bytes += upload_source.get_content_length()

                    # FIXME: what we actually should do here???
                    progress_listener.set_total_bytes(total_bytes)

                    upload_source_parts = self.upload_manager.split_upload_source(upload_source)
                    part_futures.extend(
                        self.upload_manager.get_thread_pool().submit(
                            self.upload_manager.upload_part,
                            bucket_id,
                            file_id,
                            upload_source_part,
                            large_file_upload_state,
                        ) for upload_source_part in upload_source_parts
                    )
                elif emerge_source_type == 'copy':
                    copy_source = emerge_range.emerge_source.get_source()
                    if copy_source.content_length is None:
                        raise NotImplementedError('unknonwn length copy sources not supported')

                    # FIXME: what we actually should do here???
                    total_bytes += copy_source.content_length

                    copy_source_parts = self.copy_manager.split_copy_source(copy_source)
                    part_futures.extend(
                        self.get_thread_pool().submit(
                            self.copy_manager.copy_part,
                            file_id,
                            copy_source_part,
                            large_file_upload_state,
                        ) for copy_source_part in copy_source_parts
                    )
                else:
                    raise NotImplementedError(
                        'not implemented emerge source: {0}'.format(emerge_source_type)
                    )

            part_sha1_array = [interruptible_get_result(f)['contentSha1'] for f in part_futures]

        # Finish the large file
        response = self.session.finish_large_file(file_id, part_sha1_array)
        return FileVersionInfoFactory.from_api_response(response)

    def concat(
        self, bucket_id, emrege_sources_iterator, file_name, content_type, file_info,
        progress_listener
    ):
        """
        Concat multiple copy/upload sources.

        :param  str bucket_id: a bucket ID
        :param emrege_sources_iterator: iterator ofemerge sources which are (not determined yet) polymorphism of
                                       :class:`~b2sdk.v1.CopySource` and :class:`~b2sdk.v1.UploadSource`
        :param str file_name: the file name of the new B2 file
        :param str content_type: the MIME type
        :param dict,None file_info: a file info to store with the file or ``None`` to not store anything
        :param b2sdk.v1.AbstractProgressListener progress_listener: a progress listener object to use

        Thin wrapper around ``emerge`` function to show ``Emerger`` possible applications
        """

        def emerge_ranges_generator():
            current_position = 0
            for emerge_source in emrege_sources_iterator:
                current_position, upload_range = self._wrap_emerge_range(
                    current_position, emerge_source
                )
                yield upload_range

        return self.emerge(
            emerge_ranges_generator, file_name, content_type, file_info, progress_listener
        )

    def _wrap_emerge_range(self, current_position, emerge_source):
        pass
