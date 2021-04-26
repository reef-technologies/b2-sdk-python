######################################################################
#
# File: test/unit/v2/test_account_info.py
#
# Copyright 2019 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

from abc import ABCMeta, abstractmethod
import json
import unittest.mock as mock
import os
import platform
import shutil
import tempfile

import pytest

from .test_base import TestBase


from .deps import B2_ACCOUNT_INFO_ENV_VAR, AbstractAccountInfo, InMemoryAccountInfo, UploadUrlPool, SqliteAccountInfo, TempDir
from .deps_exception import CorruptAccountInfo, MissingAccountData


class AccountInfoBase(metaclass=ABCMeta):
    # it is a mixin to avoid running the tests directly (without inheritance)
    PERSISTENCE = NotImplemented  # subclass should override this

    @abstractmethod
    def _make_info(self):
        """
        returns a new object of AccountInfo class which should be tested
        """

    def test_clear(self):
        account_info = self._make_info()
        account_info.set_auth_data(
            'account_id',
            'account_auth',
            'https://api.backblazeb2.com',
            'download_url',
            100,
            'app_key',
            'realm',
            s3_api_url='s3_api_url',
            application_key_id='key_id',
        )
        account_info.clear()

        with self.assertRaises(MissingAccountData):
            account_info.get_account_id()
        with self.assertRaises(MissingAccountData):
            account_info.get_account_auth_token()
        with self.assertRaises(MissingAccountData):
            account_info.get_api_url()
        with self.assertRaises(MissingAccountData):
            account_info.get_application_key()
        with self.assertRaises(MissingAccountData):
            account_info.get_download_url()
        with self.assertRaises(MissingAccountData):
            account_info.get_realm()
        with self.assertRaises(MissingAccountData):
            account_info.get_minimum_part_size()
        with self.assertRaises(MissingAccountData):
            account_info.get_application_key_id()
        self.assertFalse(account_info.is_same_key('key_id', 'realm'))

    def test_set_auth_data_compatibility(self):
        account_info = self._make_info()

        # The original set_auth_data
        account_info.set_auth_data(
            'account_id',
            'account_auth',
            'https://api.backblazeb2.com',
            'download_url',
            100,
            'app_key',
            'realm',
            s3_api_url='s3_api_url',
            application_key_id='key_id',
        )
        actual = account_info.get_allowed()
        self.assertEqual(AbstractAccountInfo.DEFAULT_ALLOWED, actual, 'default allowed')

        # allowed was added later
        allowed = dict(
            bucketId=None,
            bucketName=None,
            capabilities=['readFiles'],
            namePrefix=None,
        )
        account_info.set_auth_data(
            'account_id',
            'account_auth',
            'https://api.backblazeb2.com',
            'download_url',
            100,
            'app_key',
            'realm',
            s3_api_url='s3_api_url',
            allowed=allowed,
        )
        self.assertEqual(allowed, account_info.get_allowed())

    def test_clear_bucket_upload_data(self):
        account_info = self._make_info()
        account_info.put_bucket_upload_url('bucket-0', 'http://bucket-0', 'bucket-0_auth')
        account_info.clear_bucket_upload_data('bucket-0')
        self.assertEqual((None, None), account_info.take_bucket_upload_url('bucket-0'))

    def test_large_file_upload_urls(self):
        account_info = self._make_info()
        account_info.put_large_file_upload_url('file_0', 'http://file_0', 'auth_0')
        self.assertEqual(
            ('http://file_0', 'auth_0'), account_info.take_large_file_upload_url('file_0')
        )
        self.assertEqual((None, None), account_info.take_large_file_upload_url('file_0'))

    def test_clear_large_file_upload_urls(self):
        account_info = self._make_info()
        account_info.put_large_file_upload_url('file_0', 'http://file_0', 'auth_0')
        account_info.clear_large_file_upload_urls('file_0')
        self.assertEqual((None, None), account_info.take_large_file_upload_url('file_0'))

    def test_bucket(self):
        account_info = self._make_info()
        bucket = mock.MagicMock()
        bucket.name = 'my-bucket'
        bucket.id_ = 'bucket-0'
        self.assertEqual(None, account_info.get_bucket_id_or_none_from_bucket_name('my-bucket'))
        account_info.save_bucket(bucket)
        self.assertEqual(
            'bucket-0', account_info.get_bucket_id_or_none_from_bucket_name('my-bucket')
        )
        if self.PERSISTENCE:
            self.assertEqual(
                'bucket-0',
                self._make_info().get_bucket_id_or_none_from_bucket_name('my-bucket')
            )
        account_info.remove_bucket_name('my-bucket')
        self.assertEqual(None, account_info.get_bucket_id_or_none_from_bucket_name('my-bucket'))
        if self.PERSISTENCE:
            self.assertEqual(
                None,
                self._make_info().get_bucket_id_or_none_from_bucket_name('my-bucket')
            )

    def test_refresh_bucket(self):
        account_info = self._make_info()
        self.assertEqual(None, account_info.get_bucket_id_or_none_from_bucket_name('my-bucket'))
        bucket_names = {'a': 'bucket-0', 'b': 'bucket-1'}
        account_info.refresh_entire_bucket_name_cache(bucket_names.items())
        self.assertEqual('bucket-0', account_info.get_bucket_id_or_none_from_bucket_name('a'))
        if self.PERSISTENCE:
            self.assertEqual(
                'bucket-0',
                self._make_info().get_bucket_id_or_none_from_bucket_name('a')
            )

    def _test_account_info(self, check_persistence):
        account_info = self._make_info()
        account_info.set_auth_data(
            'account_id',
            'account_auth',
            'https://api.backblazeb2.com',
            'download_url',
            100,
            'app_key',
            'realm',
            s3_api_url='s3_api_url',
            application_key_id='key_id',
        )

        object_instances = [account_info]
        if check_persistence:
            object_instances.append(self._make_info())
        for info2 in object_instances:
            print(info2)
            self.assertEqual('account_id', info2.get_account_id())
            self.assertEqual('account_auth', info2.get_account_auth_token())
            self.assertEqual('https://api.backblazeb2.com', info2.get_api_url())
            self.assertEqual('app_key', info2.get_application_key())
            self.assertEqual('key_id', info2.get_application_key_id())
            self.assertEqual('realm', info2.get_realm())
            self.assertEqual(100, info2.get_minimum_part_size())
            self.assertTrue(info2.is_same_key('key_id', 'realm'))
            self.assertFalse(info2.is_same_key('key_id', 'another_realm'))
            self.assertFalse(info2.is_same_key('another_key_id', 'realm'))
            self.assertFalse(info2.is_same_key('another_key_id', 'another_realm'))

    def test_account_info_same_object(self):
        self._test_account_info(check_persistence=False)


class TestSqliteAccountInfo(AccountInfoBase, TestBase):
    PERSISTENCE = True

    def __init__(self, *args, **kwargs):
        super(TestSqliteAccountInfo, self).__init__(*args, **kwargs)
        self.db_path = tempfile.NamedTemporaryFile(
            prefix='tmp_b2_tests_%s__' % (self.id(),), delete=True
        ).name
        self.home = None

    def setUp(self):
        try:
            os.unlink(self.db_path)
        except OSError:
            pass
        print('using %s' % self.db_path)
        self.home = tempfile.mkdtemp()

    def tearDown(self):
        try:
            os.unlink(self.db_path)
        except OSError:
            pass
        shutil.rmtree(self.home)

    def test_corrupted(self):
        """
        Test that a corrupted file will be replaced with a blank file.
        """
        with open(self.db_path, 'wb') as f:
            f.write(b'not a valid database')

        with self.assertRaises(CorruptAccountInfo):
            self._make_info()

    @pytest.mark.skipif(
        platform.system() == 'Windows',
        reason='it fails to upgrade on Windows, not worth to fix it anymore'
    )
    def test_convert_from_json(self):
        """
        Tests converting from a JSON account info file, which is what version
        0.5.2 of the command-line tool used.
        """
        data = dict(
            account_auth_token='auth_token',
            account_id='account_id',
            api_url='api_url',
            application_key='application_key',
            download_url='download_url',
            minimum_part_size=5000,
            realm='production'
        )
        with open(self.db_path, 'wb') as f:
            f.write(json.dumps(data).encode('utf-8'))
        account_info = self._make_info()
        self.assertEqual('auth_token', account_info.get_account_auth_token())

    def _make_info(self):
        return self._make_sqlite_account_info()

    def _make_sqlite_account_info(self, env=None, last_upgrade_to_run=None):
        """
        Returns a new SqliteAccountInfo that has just read the data from the file.

        :param dict env: Override Environment variables.
        """
        # Override HOME to ensure hermetic tests
        with mock.patch('os.environ', env or {'HOME': self.home}):
            return SqliteAccountInfo(
                file_name=self.db_path if not env else None,
                last_upgrade_to_run=last_upgrade_to_run,
            )

    def test_account_info_persistence(self):
        self._test_account_info(check_persistence=True)

    def test_uses_xdg_config_home(self):
        with TempDir() as d:
            account_info = self._make_sqlite_account_info(
                env={
                    'HOME': self.home,
                    'XDG_CONFIG_HOME': d,
                }
            )
            expected_path = os.path.abspath(os.path.join(d, 'b2', 'account_info'))
            actual_path = os.path.abspath(account_info.filename)
            self.assertEqual(
                expected_path, actual_path,
                'Actual path %s is not equal to $XDG_CONFIG_HOME/b2/account_info' % (actual_path,)
            )
            assert os.path.exists(
                os.path.join(d, 'b2')
            ), 'Config folder $XDG_CONFIG_HOME/b2 was not created!'

    def test_account_info_env_var_overrides_xdg_config_home(self):
        with TempDir() as d:
            account_info = self._make_sqlite_account_info(
                env={
                    'HOME': self.home,
                    'XDG_CONFIG_HOME': d,
                    B2_ACCOUNT_INFO_ENV_VAR: os.path.join(d, 'b2_account_info'),
                }
            )
            expected_path = os.path.abspath(os.path.join(d, 'b2_account_info'))
            actual_path = os.path.abspath(account_info.filename)
            self.assertEqual(
                expected_path, actual_path, 'Actual path %s is not equal to %s' % (
                    actual_path,
                    B2_ACCOUNT_INFO_ENV_VAR,
                )
            )