######################################################################
#
# File: test/unit/sync/fixtures.py
#
# Copyright 2020 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

import pytest

import apiver_deps
from apiver_deps import AbstractFolder, B2SyncPath, LocalSyncPath
from apiver_deps import CompareVersionMode, NewerFileSyncMode, KeepOrDeleteMode
from apiver_deps import DEFAULT_SCAN_MANAGER, Synchronizer

if apiver_deps.V <= 1:
    from apiver_deps import FileVersionInfo as VB2FileVersion
else:
    from apiver_deps import B2FileVersion as VB2FileVersion


class FakeFolder(AbstractFolder):
    def __init__(self, f_type, files=None):
        if files is None:
            files = []

        self.f_type = f_type
        self.files = files

    @property
    def bucket_name(self):
        if self.f_type != 'b2':
            raise ValueError('FakeFolder with type!=b2 does not have a bucket name')
        return 'fake_bucket_name'

    @property
    def bucket(self):
        if self.f_type != 'b2':
            raise ValueError('FakeFolder with type!=b2 does not have a bucket')
        return 'fake_bucket'  # WARNING: this is supposed to be a Bucket object, not a string

    def all_files(self, reporter, policies_manager=DEFAULT_SCAN_MANAGER):
        for single_file in self.files:
            if single_file.relative_path.endswith('/'):
                if policies_manager.should_exclude_directory(single_file.relative_path):
                    continue
            else:
                if policies_manager.should_exclude_file(single_file.relative_path):
                    continue
            yield single_file

    def folder_type(self):
        return self.f_type

    def make_full_path(self, name):
        if self.f_type == 'local':
            return '/dir/' + name
        else:
            return 'folder/' + name

    def __str__(self):
        return '%s(%s, %s)' % (self.__class__.__name__, self.f_type, self.make_full_path(''))


def local_file(name, mod_times, size=10):
    """
    Makes a File object for a local file, with one FileVersion for
    each modification time given in mod_times.
    """
    return LocalSyncPath(name, name, mod_times[0], size)


def b2_file(name, mod_times, size=10):
    """
    Makes a File object for a b2 file, with one FileVersion for
    each modification time given in mod_times.

    Positive modification times are uploads, and negative modification
    times are hides.  It's a hack, but it works.

    """
    versions = [
        VB2FileVersion(
            id_='id_%s_%d' % (name[0], abs(mod_time)),
            file_name='folder/' + name,
            upload_timestamp=abs(mod_time),
            action='upload' if 0 < mod_time else 'hide',
            size=size,
            file_info={'in_b2': 'yes'},
            content_type='text/plain',
            content_sha1='content_sha1',
        ) for mod_time in mod_times
    ]  # yapf disable
    return B2SyncPath(name, selected_version=versions[0], all_versions=versions)


@pytest.fixture(scope='session')
def folder_factory():
    def get_folder(f_type, *files):
        def get_files():
            nonlocal files
            for file in files:
                if f_type == 'local':
                    yield local_file(*file)
                else:
                    yield b2_file(*file)

        return FakeFolder(f_type, list(get_files()))

    return get_folder


@pytest.fixture(scope='session')
def synchronizer_factory():
    def get_synchronizer(
        policies_manager=DEFAULT_SCAN_MANAGER,
        dry_run=False,
        allow_empty_source=False,
        newer_file_mode=NewerFileSyncMode.RAISE_ERROR,
        keep_days_or_delete=KeepOrDeleteMode.NO_DELETE,
        keep_days=None,
        compare_version_mode=CompareVersionMode.MODTIME,
        compare_threshold=None,
    ):
        return Synchronizer(
            1,
            policies_manager=policies_manager,
            dry_run=dry_run,
            allow_empty_source=allow_empty_source,
            newer_file_mode=newer_file_mode,
            keep_days_or_delete=keep_days_or_delete,
            keep_days=keep_days,
            compare_version_mode=compare_version_mode,
            compare_threshold=compare_threshold,
        )

    return get_synchronizer


@pytest.fixture
def synchronizer(synchronizer_factory):
    return synchronizer_factory()
