######################################################################
#
# File: test/integration/test_listing.py
#
# Copyright 2021 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
from b2sdk.transfer.emerge.write_intent import WriteIntent
from b2sdk.transfer.outbound.upload_source import UploadSourceBytes
from b2sdk.utils.fs import WildcardStyle

from .base import IntegrationTestBase
from .fixtures import *  # pyflakes: disable


class TestListing(IntegrationTestBase):
    @pytest.fixture
    def full_bucket(self):
        bucket = self.create_bucket()
        upload_source = UploadSourceBytes(b'hello world')
        for path in ('a/z.txt', 'a/ba/z.txt', 'a/bb/z.txt', 'a/bc/z.txt', 'a/bd/cc/z.txt'):
            bucket.create_file(
                [WriteIntent(upload_source, destination_offset=0)], path, 'text/plain'
            )
        yield bucket

    def test_listing_wildcard_shell(self, full_bucket):
        for pattern, expected_result in (
            (
                'a/*.TXT',
                set(),
            ),
            (
                'a/\\*/z.txt',
                set(),
            ),
            (
                'a/*/z.txt',
                {
                    'a/ba/z.txt',
                    'a/bb/z.txt',
                    'a/bc/z.txt',
                },
            ),
            (
                'a/b[ab]/z.txt',
                {
                    'a/ba/z.txt',
                    'a/bb/z.txt',
                },
            ),
            (
                'a/{ba,bb}/z.txt',
                {
                    'a/ba/z.txt',
                    'a/bb/z.txt',
                },
            ),
            (
                'a/b{a..c}/z.txt',
                {
                    'a/ba/z.txt',
                    'a/bb/z.txt',
                    'a/bc/z.txt',
                },
            ),
            (
                'a/**/z.txt',
                {
                    'a/ba/z.txt',
                    'a/bb/z.txt',
                    'a/bc/z.txt',
                    'a/bd/cc/z.txt',
                    'a/z.txt',
                },
            ),
            ('a/b[!b]/z.txt', {
                'a/ba/z.txt',
                'a/bc/z.txt',
            }),
        ):
            res = full_bucket.ls(
                folder_to_list=pattern,
                recursive=True,
                with_wildcard=True,
                wildcard_style=WildcardStyle.SHELL,
            )
            assert {
                item.file_name
                for item, _ in res
            } == expected_result, f"pattern {pattern} failed"

    def test_listing_wildcard_glob(self, full_bucket):
        for pattern, expected_result in (
            (
                'a/*/z.txt',
                {
                    'a/bd/cc/z.txt',
                    'a/ba/z.txt',
                    'a/bb/z.txt',
                    'a/bc/z.txt',
                },
            ),
            (
                'a/b[ab]/z.txt',
                {
                    'a/ba/z.txt',
                    'a/bb/z.txt',
                },
            ),
            (
                'a/**/z.txt',
                {
                    'a/ba/z.txt',
                    'a/bb/z.txt',
                    'a/bc/z.txt',
                    'a/bd/cc/z.txt',
                },
            ),
            ('a/b[!b]/z.txt', {
                'a/ba/z.txt',
                'a/bc/z.txt',
            }),
            (
                'a/*.TXT',
                set(),
            ),
        ):
            res = full_bucket.ls(
                folder_to_list=pattern,
                recursive=True,
                with_wildcard=True,
                wildcard_style=WildcardStyle.GLOB,
            )
            assert {
                item.file_name
                for item, _ in res
            } == expected_result, f"pattern {pattern} failed"
