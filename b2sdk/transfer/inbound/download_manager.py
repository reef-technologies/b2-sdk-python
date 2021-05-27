######################################################################
#
# File: b2sdk/transfer/inbound/download_manager.py
#
# Copyright 2020 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

import logging
from typing import Optional

from b2sdk.download_dest import DownloadDestProgressWrapper
from b2sdk.encryption.setting import EncryptionSetting
from b2sdk.progress import DoNothingProgressListener

from b2sdk.exception import (
    ChecksumMismatch,
    InvalidRange,
    TruncatedOutput,
)
from b2sdk.raw_api import SRC_LAST_MODIFIED_MILLIS
from b2sdk.utils import B2TraceMetaAbstract

from .downloaded_file import DownloadedFile
from .downloader.parallel import ParallelDownloader
from .downloader.simple import SimpleDownloader
from .file_metadata import FileMetadata

logger = logging.getLogger(__name__)


class DownloadManager(metaclass=B2TraceMetaAbstract):
    """
    Handle complex actions around downloads to free raw_api from that responsibility.
    """

    # how many chunks to break a downloaded file into
    DEFAULT_MAX_STREAMS = 8

    # minimum size of a download chunk
    DEFAULT_MIN_PART_SIZE = 100 * 1024 * 1024

    # block size used when downloading file. If it is set to a high value,
    # progress reporting will be jumpy, if it's too low, it impacts CPU
    MIN_CHUNK_SIZE = 8192  # ~1MB file will show ~1% progress increment
    MAX_CHUNK_SIZE = 1024**2

    def __init__(self, services):
        """
        Initialize the DownloadManager using the given services object.

        :param b2sdk.v1.Services services:
        """

        self.services = services
        self.strategies = [
            ParallelDownloader(
                max_streams=self.DEFAULT_MAX_STREAMS,
                min_part_size=self.DEFAULT_MIN_PART_SIZE,
                min_chunk_size=self.MIN_CHUNK_SIZE,
                max_chunk_size=self.MAX_CHUNK_SIZE,
            ),
            SimpleDownloader(
                min_chunk_size=self.MIN_CHUNK_SIZE,
                max_chunk_size=self.MAX_CHUNK_SIZE,
            ),
        ]

    def download_file_from_url(
        self,
        url,
        download_dest,
        progress_listener=None,
        range_=None,
        encryption: Optional[EncryptionSetting] = None,
        allow_seeking=True,
    ) -> DownloadedFile:
        """
        :param url: url from which the file should be downloaded
        :param download_dest: where to put the file when it is downloaded
        :param progress_listener: where to notify about progress downloading
        :param range_: 2-element tuple containing data of http Range header
        :param b2sdk.v1.EncryptionSetting encryption: encryption setting (``None`` if unknown)
        :param bool allow_seeking: if False, download strategies that rely on seeking to write data
                                   (parallel strategies) will be discarded.
        """
        progress_listener = progress_listener or DoNothingProgressListener()
        download_dest = DownloadDestProgressWrapper(download_dest, progress_listener)
        with self.services.session.download_file_from_url(
            url,
            range_=range_,
            encryption=encryption,
        ) as response:
            metadata = FileMetadata.from_response(response)
            if range_ is not None:
                # 2021-05-20: unfortunately for a read of a complete object server does not return the 'Content-Range' header
                if (range_[1] - range_[0] + 1) != metadata.content_length:
                    raise InvalidRange(metadata.content_length, range_)

            mod_time_millis = int(
                metadata.file_info.get(
                    SRC_LAST_MODIFIED_MILLIS,
                    response.headers['x-bz-upload-timestamp'],
                )
            )

            with download_dest.make_file_context(
                metadata.file_id,
                metadata.file_name,
                metadata.content_length,
                metadata.content_type,
                metadata.content_sha1,
                metadata.file_info,
                mod_time_millis,
                range_=range_,
            ) as file:

                for strategy in self.strategies:

                    if strategy.is_suitable(metadata, allow_seeking):
                        return DownloadedFile(file_version, strategy, range_, response, encryption,
                                              self.services.session, progress_listener)
                else:
                    assert False, 'no strategy suitable for download was found!'

