######################################################################
#
# File: b2sdk/transfer/inbound/downloader/simple.py
#
# Copyright 2020 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
from __future__ import annotations

import logging
from io import IOBase

from requests.models import Response

from b2sdk.encryption.setting import EncryptionSetting
from b2sdk.file_version import DownloadVersion
from b2sdk.session import B2Session
from b2sdk.utils.transfer import RetryCounter

from .abstract import AbstractDownloader

logger = logging.getLogger(__name__)


class SimpleDownloader(AbstractDownloader):

    REQUIRES_SEEKING = False

    def _download(
        self,
        file: IOBase,
        response: Response,
        download_version: DownloadVersion,
        session: B2Session,
        encryption: EncryptionSetting | None = None,
    ):
        actual_size = self._get_remote_range(response, download_version).size()
        chunk_size = self._get_chunk_size(actual_size)

        digest = self._get_hasher()

        bytes_read = 0
        for data in response.iter_content(chunk_size=chunk_size):
            file.write(data)
            digest.update(data)
            bytes_read += len(data)

        assert actual_size >= 1  # code below does `actual_size - 1`, but it should never reach that part with an empty file

        # now, normally bytes_read == download_version.content_length, but sometimes there is a timeout
        # or something and the server closes connection, while neither tcp or http have a problem
        # with the truncated output, so we detect it here and try to continue

        retry_counter = RetryCounter(self._retry_time)
        retry_counter.start()
        while retry_counter.count_and_check() and bytes_read < download_version.content_length:
            new_range = self._get_remote_range(
                response,
                download_version,
            ).subrange(bytes_read, actual_size - 1)
            # original response is not closed at this point yet, as another layer is responsible for closing it, so a new socket might be allocated,
            # but this is a very rare case and so it is not worth the optimization
            remaining_log_format = ' time: %is' if retry_counter.retry_time else ': %i'
            logger.debug(
                f're-download attempts remaining{remaining_log_format}, bytes read already: %i. Getting range %s now.',
                retry_counter.get_remaining_attempts(), bytes_read, new_range
            )
            with session.download_file_from_url(
                response.request.url,
                new_range.as_tuple(),
                encryption=encryption,
            ) as followup_response:
                for data in followup_response.iter_content(
                    chunk_size=self._get_chunk_size(actual_size)
                ):
                    file.write(data)
                    digest.update(data)
                    bytes_read += len(data)
        return bytes_read, digest.hexdigest()

    def download(
        self,
        file: IOBase,
        response: Response,
        download_version: DownloadVersion,
        session: B2Session,
        encryption: EncryptionSetting | None = None,
    ):
        future = self._thread_pool.submit(
            self._download, file, response, download_version, session, encryption
        )
        return future.result()
