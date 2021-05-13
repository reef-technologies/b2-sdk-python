######################################################################
#
# File: b2sdk/sync/path.py
#
# Copyright 2021 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

from abc import ABC, abstractmethod
from typing import List

from ..file_version import FileVersionInfo


class AbstractSyncPath(ABC):
    """
    Represent a path in a source or destination folder - be it B2 or local
    """

    def __init__(self, relative_path: str, mod_time: int, size: int):
        self.relative_path = relative_path
        self.mod_time = mod_time
        self.size = size

    @abstractmethod
    def is_visible(self) -> bool:
        """Is the path visible/not deleted on it's storage"""

    def __repr__(self):
        return '%s(%s, %s, %s)' % (
            self.__class__.__name__, repr(self.relative_path), repr(self.mod_time), repr(self.size)
        )


class LocalSyncPath(AbstractSyncPath):
    __slots__ = ['relative_path', 'mod_time', 'size']

    def is_visible(self) -> bool:
        return True


class B2SyncPath(AbstractSyncPath):
    __slots__ = ['relative_path', 'selected_version', 'all_versions']

    def __init__(
        self, relative_path: str, selected_version: FileVersionInfo,
        all_versions: List[FileVersionInfo]
    ):
        self.selected_version = selected_version
        self.all_versions = all_versions
        self.relative_path = relative_path

    def is_visible(self) -> bool:
        return self.selected_version.action != 'hide'

    @property
    def mod_time(self) -> int:
        return self.selected_version.mod_time_millis

    @property
    def size(self) -> int:
        return self.selected_version.size

    def __repr__(self):
        return '%s(%s, [%s])' % (
            self.__class__.__name__, self.relative_path, ', '.join(
                '(%s, %s, %s)' % (
                    repr(fv.id_),
                    repr(fv.mod_time_millis),
                    repr(fv.action),
                ) for fv in self.all_versions
            )
        )