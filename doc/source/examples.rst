=================
Quick start guide
=================

Initialize API:

.. code-block:: python

    >>> from b2sdk.account_info.sqlite_account_info import InMemoryAccountInfo
    >>> from b2sdk.api import B2Api
    >>> from b2sdk.cache import AuthInfoCache

    >>> info = InMemoryAccountInfo()

    >>> b2_api = B2Api(info, AuthInfoCache(info))


Account authorization
=====================

.. code-block:: python

    >>> realm = 'production'  # a realm to authorize account in

    >>> b2_api.authorize_account(realm, account_id_or_key_id, application_key)


Synchronization
===============

.. code-block:: python

    >>> from b2sdk.sync.scan_policies import ScanPoliciesManager
    >>> from b2sdk.sync import parse_sync_folder, sync_folders
    >>> import time
    >>> import sys

    >>> source = '/home/user1/b2_example'
    >>> destination = 'b2://example-mybucket-b2'

    >>> source = parse_sync_folder(source, b2_api)
    >>> destination = parse_sync_folder(destination, b2_api)

    >>> policies_manager = ScanPoliciesManager(exclude_all_symlinks=True)

    >>> sync_folders(
            source_folder=source,
            dest_folder=destination,
            args=args,
            now_millis=int(round(time.time() * 1000)),
            stdout=sys.stdout,
            no_progress=False,
            max_workers=10,
            policies_manager=policies_manager,
            dry_run=False,
            allow_empty_source=True,
        )
    upload some.pdf
    upload som2.pdf

Bucket actions
==============

Create a bucket
---------------

.. code-block:: python

    >>> bucket_name = 'example-mybucket-b2-1'
    >>> bucket_type = 'allPublic'

    >>> b2_api.create_bucket(
            bucket_name,  # bucket name (str)
            bucket_type,  # a bucket type, could be one of the following values: "allPublic", "allPrivate" (str)
        )
    Bucket<346501784642eb3e60980d10,example-mybucket-b2-1,allPublic>

You can optionally stores bucket info, CORS rules and lifecycle rules with the bucket. See `Python <b2sdk/bucket.py>`_.

Remove a bucket
---------------

.. code-block:: python

    >>> bucket_name = 'example-mybucket-b2-to-delete'
    >>> bucket = b2_api.get_bucket_by_name(bucket_name)
    >>> b2_api.delete_bucket(bucket)
    {'accountId': '451862be08d0',
     'bucketId': '346501784642eb3e60980d10',
     'bucketInfo': {},
     'bucketName': 'example-mybucket-b2-to-delete',
     'bucketType': 'allPublic',
     'corsRules': [],
     'lifecycleRules': [],
     'revision': 3}


List buckets
-------------

.. code-block:: python

    >>> for b in b2_api.list_buckets():
            print('%s  %-10s  %s' % (b.id_, b.type_, b.name))
    5485a1682662eb3e60980d10  allPublic   example-mybucket-b2

Update bucket info
------------------

.. code-block:: python

    >>> new_bucket_type = 'allPrivate'
    >>> bucket_name = 'example-mybucket-b2'

    >>> bucket = b2_api.get_bucket_by_name(bucket_name)
    >>> bucket.update(bucket_type=new_bucket_type)
    {'accountId': '451862be08d0',
     'bucketId': '5485a1682662eb3e60980d10',
     'bucketInfo': {},
     'bucketName': 'example-mybucket-b2',
     'bucketType': 'allPrivate',
     'corsRules': [],
     'lifecycleRules': [],
     'revision': 3}

File actions
============

Upload file
-----------

.. code-block:: python

    >>> from b2sdk.progress import make_progress_listener

    >>> local_file_path = '/home/user1/b2_example/new.pdf'
    >>> b2_file_name = 'dummy_new.pdf'
    >>> file_info = {'how': 'good-file'}

    >>> bucket = b2_api.get_bucket_by_name(bucket_name)
    >>> response = bucket.upload_local_file(
            local_file=local_file_path,
            file_name=b2_file_name,
            file_infos=file_info,
            progress_listener=make_progress_listener(local_file_path, True),  # to enable progress reporting
        )
    >>> response  # this return file version info
    <b2sdk.file_version.FileVersionInfo at 0x7fc8cd560550>


List files
----------

.. code-block:: python

    >>> bucket_name = 'example-mybucket-b2'
    >>> bucket = b2_api.get_bucket_by_name(bucket_name)
    >>> max_to_show = 1  # max files to show, default=100, optional parameter
    >>> start_file_name = 'som'  # default is '', optional parameter
    >>> bucket.list_file_names(start_file_name, max_to_show)
    {'files': [{'accountId': '451862be08d0',
       'action': 'upload',
       'bucketId': '5485a1682662eb3e60980d10',
       'contentLength': 1870579,
       'contentSha1': 'd821849a70922e87c2b0786c0be7266b89d87df0',
       'contentType': 'application/pdf',
       'fileId': '4_z5485a1682662eb3e60980d10_f1195145f42952533_d20190403_m130258_c002_v0001111_t0002',
       'fileInfo': {'src_last_modified_millis': '1550988084299'},
       'fileName': 'som2.pdf',
       'uploadTimestamp': 1554296578000}],
     'nextFileName': 'som2.pdf '}

    # list file versions
    >>> bucket.list_file_versions()
    {'files': [{'accountId': '451862be08d0',
       'action': 'upload',
       'bucketId': '5485a1682662eb3e60980d10',
       'contentLength': 1870579,
       'contentSha1': 'd821849a70922e87c2b0786c0be7266b89d87df0',
       'contentType': 'application/pdf',
       'fileId': '4_z5485a1682662eb3e60980d10_f1195145f42952533_d20190403_m130258_c002_v0001111_t0002',
       'fileInfo': {'src_last_modified_millis': '1550988084299'},
       'fileName': 'som2.pdf',
       'uploadTimestamp': 1554296578000}

Download file
-------------

By Id:

.. code-block:: python

    >>> from b2sdk.progress import make_progress_listener
    >>> from b2sdk.download_dest import DownloadDestLocalFile

    >>> local_file_path = '/home/user1/b2_example/new2.pdf'
    >>> file_id = '4_z5485a1682662eb3e60980d10_f1195145f42952533_d20190403_m130258_c002_v0001111_t0002'
    >>> progress_listener = make_progress_listener(local_file_path, True)
    >>> download_dest = DownloadDestLocalFile(local_file_path)
    >>> b2_api.download_file_by_id(file_id, download_dest, progress_listener)
    {'fileId': '4_z5485a1682662eb3e60980d10_f1195145f42952533_d20190403_m130258_c002_v0001111_t0002',
     'fileName': 'som2.pdf',
     'contentType': 'application/pdf',
     'contentLength': 1870579,
     'contentSha1': 'd821849a70922e87c2b0786c0be7266b89d87df0',
     'fileInfo': {'src_last_modified_millis': '1550988084299'}}

    >>> print('File name:   ', download_dest.file_name)
    File name:    som2.pdf
    >>> print('File id:     ', download_dest.file_id)
    File id:      4_z5485a1682662eb3e60980d10_f1195145f42952533_d20190403_m130258_c002_v0001111_t0002
    >>> print('File size:   ', download_dest.content_length)
    File size:    1870579
    >>> print('Content type:', download_dest.content_type)
    Content type: application/pdf
    >>> print('Content sha1:', download_dest.content_sha1)
    Content sha1: d821849a70922e87c2b0786c0be7266b89d87df0

By Name:

.. code-block:: python

    >>> bucket = b2_api.get_bucket_by_name(bucket_name)
    >>> b2_file_name = 'dummy_new.pdf'
    >>> local_file_name = '/home/user1/b2_example/new3.pdf'
    >>> download_dest = DownloadDestLocalFile(local_file_name)
    >>> progress_listener = make_progress_listener(local_file_path, True)
    >>> bucket.download_file_by_name(b2_file_name, download_dest, progress_listener)
    {'fileId': '4_z5485a1682662eb3e60980d10_f113f963288e711a6_d20190404_m065910_c002_v0001095_t0044',
     'fileName': 'dummy_new.pdf',
     'contentType': 'application/pdf',
     'contentLength': 1870579,
     'contentSha1': 'd821849a70922e87c2b0786c0be7266b89d87df0',
     'fileInfo': {'how': 'good-file'}}


Get file meta information
-------------------------

.. code-block:: python

    >>> file_id = '4_z5485a1682662eb3e60980d10_f113f963288e711a6_d20190404_m065910_c002_v0001095_t0044'
    >>> b2_api.get_file_info(file_id)
    {'accountId': '451862be08d0',
     'action': 'upload',
     'bucketId': '5485a1682662eb3e60980d10',
     'contentLength': 1870579,
     'contentSha1': 'd821849a70922e87c2b0786c0be7266b89d87df0',
     'contentType': 'application/pdf',
     'fileId': '4_z5485a1682662eb3e60980d10_f113f963288e711a6_d20190404_m065910_c002_v0001095_t0044',
     'fileInfo': {'how': 'good-file'},
     'fileName': 'dummy_new.pdf',
     'uploadTimestamp': 1554361150000}


Delete file
-----------

.. code-block:: python

    >>> file_id = '4_z5485a1682662eb3e60980d10_f113f963288e711a6_d20190404_m065910_c002_v0001095_t0044'
    >>> file_info = b2_api.delete_file_version(file_id, 'dummy_new.pdf')


Cancel file operations
----------------------

.. code-block:: python

    >>> bucket = b2_api.get_bucket_by_name(bucket_name)
    >>> for file_version in bucket.list_unfinished_large_files():
            bucket.cancel_large_file(file_version.file_id)


Account information
===================

.. code-block:: python

    account_info = b2_api.account_info

    # Get Account ID
    accountId = account_info.get_account_id()

    # Allowed Permissions
    allowed = account_info.get_allowed()

    # Get Application Key
    applicationKey = account_info.get_application_key()

    # Get Application Key
    accountAuthToken = account_info.get_account_auth_token()

    # Get Application Key
    apiUrl = account_info.get_api_url()

    # Get Application Key
    downloadUrl = account_info.get_download_url()

