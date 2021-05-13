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

from ..raw_api import SRC_LAST_MODIFIED_MILLIS


class PathType(enum.Enum):
    LOCAL = 'local'
    B2 = 'b2'


def mod_time_from_fv(file_version):
    if SRC_LAST_MODIFIED_MILLIS in file_version.file_info:
        return int(file_version.file_info[SRC_LAST_MODIFIED_MILLIS])
    return file_version.upload_timestamp


class AbstractSyncPath(ABC):
    """
    Represent a path in a source or destination folder - be it B2 or local
    """

    def __init__(self, relative_path, mod_time, size):
        self.relative_path = relative_path
        self.mod_time = mod_time
        self.size = size

    @abstractmethod
    def type_(self) -> PathType:
        pass

    def __repr__(self):
        return '%s(%s, %s, %s)' % (
            self.__class__.__name__, repr(self.relative_path), repr(self.mod_time), repr(self.size)
        )


class LocalSyncPath(AbstractSyncPath):
    __slots__ = ['relative_path', 'mod_time', 'size']

    def type_(self) -> PathType:
        return PathType.LOCAL


class B2SyncPath(AbstractSyncPath):
    __slots__ = ['relative_path', 'file_versions']

    def __init__(self, relative_path, file_versions):
        assert file_versions
        self.file_versions = file_versions
        self.relative_path = relative_path

    def type_(self) -> PathType:
        return PathType.B2

    @property
    def mod_time(self):
        return mod_time_from_fv(self.file_versions[0])

    @property
    def size(self):
        return self.file_versions[0].size

    def file_version(self):
        return self.file_versions[0]

    def file_id(self):
        return self.file_versions[0].id_

    def __repr__(self):
        return '%s(%s, [%s])' % (
            self.__class__.__name__, self.relative_path, ', '.join(
                '(%s, %s, %s)' % (
                    repr(fv.id_),
                    repr(mod_time_from_fv(fv)),
                    repr(fv.action),
                ) for fv in self.file_versions
            )
        )
