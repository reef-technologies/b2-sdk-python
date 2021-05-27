######################################################################
#
# File: b2sdk/transfer/inbound/downloaded_file.py
#
# Copyright 2021 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

import logging
from typing import Optional

from b2sdk.download_dest import DownloadDestProgressWrapper
from b2sdk.stream.progress import WritingStreamWithProgress
from b2sdk.encryption.setting import EncryptionSetting
from b2sdk.progress import DoNothingProgressListener

from b2sdk.exception import (
    ChecksumMismatch,
    InvalidRange,
    TruncatedOutput,
    UnexpectedCloudBehaviour,
)
from b2sdk.raw_api import SRC_LAST_MODIFIED_MILLIS
from b2sdk.utils import B2TraceMetaAbstract, set_file_mtime

from .downloader.parallel import ParallelDownloader
from .downloader.simple import SimpleDownloader
from .file_metadata import FileMetadata

logger = logging.getLogger(__name__)


class MtimeUpdatedFile:
    """
    Helper class that facilitates updating a files mod_time after closing.
    Usage:

    .. code-block: python

       downloaded_file = bucket.download_file_by_id('b2_file_id')
       with MtimeUpdatedFile('some_local_path') as file:
           downloaded_file.save(file, file.set_mod_time)
       #  'some_local_path' has the mod_time set according to metadata in B2
    """
    def __init__(self, path_, mode='wb+'):
        self.path_ = path_
        self.mode = mode
        self.mod_time_to_set = None
        self.file = None

    def set_mod_time(self, mod_time):
        self.mod_time_to_set = mod_time

    def __enter__(self):
        self.file = open(self.path_, self.mode)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.file.close()
        if self.mod_time_to_set is not None:
            set_file_mtime(self.path_, self.mod_time_to_set)


class DownloadedFile:
    def __init__(self, file_version, strategy, range_, response, encryption, session, progress_listener):
        self.file_version = file_version
        self.strategy = strategy
        self.range_ = range_
        self.progress_listener = progress_listener
        self.response = response
        self.encryption = encryption
        self.session = session

    def _validate_download(self, bytes_read, actual_sha1):
        if self.range_ is None:
            if bytes_read != self.file_version.content_length:
                raise TruncatedOutput(bytes_read, self.file_version.content_length)

            if self.file_version.content_sha1 != 'none' and actual_sha1 != self.file_version.content_sha1:
                raise ChecksumMismatch(
                    checksum_type='sha1',
                    expected=self.file_version.content_sha1,
                    actual=actual_sha1,
                )
        else:
            desired_length = self.range_[1] - self.range_[0] + 1
            if bytes_read != desired_length:
                raise TruncatedOutput(bytes_read, desired_length)

    def save(self, file, mod_time_callback=None):
        """
        Read data from B2 cloud and write it to a file-like object
        :param file: a file-like object
        :param mod_time_callback: a callable accepting a single argument: the mod time of the downloaded file
                                  in milliseconds
        """
        if self.progress_listener:
            file = WritingStreamWithProgress(file, self.progress_listener)
            if self.range_ is not None:
                total_bytes = self.range_[1] - self.range_[0] + 1
            else:
                total_bytes = self.file_version.size
            self.progress_listener.set_total_bytes(total_bytes)
        if mod_time_callback is not None:
            mod_time_callback(self.file_version.mod_time_millis())
        bytes_read, actual_sha1 = self.strategy.download(
            file,
            self.response,
            self.file_version,
            self.session,
            encryption=self.encryption,
        )
        self._validate_download(bytes_read, actual_sha1)

    def save_to(self, path_, mode='wb+'):
        """
        Open a local file and write data from B2 cloud to it, also update the mod_time.
        """
        with MtimeUpdatedFile(path_, mode) as file:
            self.save(file, file.set_mod_time)
