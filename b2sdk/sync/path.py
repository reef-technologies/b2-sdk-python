######################################################################
#
# File: b2sdk/sync/path.py
#
# Copyright 2021 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

import enum
from abc import ABC, abstractmethod
from pathlib import PurePosixPath
from typing import List

from ..file_version import AbstractFileVersion, LocalFileVersion, FileVersionInfo


class AbstractSyncPath(ABC):
    """
    Represent a path in a source or destination folder - be it B2 or local
    """

    def __init__(self, relative_path: PurePosixPath, versions: List[AbstractFileVersion]):
        assert versions
        self.relative_path = relative_path
        self.versions = versions

    def latest_version(self) -> AbstractFileVersion:
        return self.versions[0]

    def __repr__(self):
        return '%s(%s, [%s])' % (
            self.__class__.__name__, self.relative_path, ', '.join(repr(v) for v in self.versions)
        )


class LocalSyncPath(AbstractSyncPath):
    __slots__ = ['relative_path', 'versions']

    def __init__(self, relative_path: PurePosixPath, versions: List[LocalFileVersion]):
        super().__init__(relative_path, versions)


class B2SyncPath(AbstractSyncPath):
    __slots__ = ['relative_path', 'versions']

    def __init__(self, relative_path: PurePosixPath, versions: List[FileVersionInfo]):
        super().__init__(relative_path, versions)
