.. hint:: Use :doc:`quick_start` to quickly jump to examples

########################
API Reference
########################

Interface types
=======================

**b2sdk** API is divided into two parts, :ref:`public <api_public>` and :ref:`internal <api_internal>`. Please pay attention to which interface type you use.


.. tip::
   :ref:`Pinning versions <semantic_versioning>` properly ensures the stability of your application.


.. _api_public:

Public API
========================

.. todo::
   Public API doc list

.. toctree::
   api/account_info
   api/api
   api/exception
   api/bucket
   api/data_classes
   api/enums
   api/progress
   api/sync
   api/utils

.. _api_internal:

Internal API
========================

.. note:: See :ref:`Internal interface <internal_interface>` chapter to learn when and how to safely use the Internal API

.. todo::
   Private API doc list

.. toctree::
   api/internal/session
   api/internal/raw_api
   api/internal/b2http
   api/internal/utils
   api/internal/cache
   api/internal/download_dest
   api/internal/sync/action
   api/internal/sync/exception
   api/internal/sync/file
   api/internal/sync/folder
   api/internal/sync/folder_parser
   api/internal/sync/policy
   api/internal/sync/policy_manager
   api/internal/sync/scan_policies
   api/internal/sync/sync
   api/internal/transfer/inbound/downloader/abstract
   api/internal/transfer/inbound/downloader/parallel
   api/internal/transfer/inbound/downloader/range
   api/internal/transfer/inbound/downloader/simple
   api/internal/transfer/inbound/file_metadata
   api/internal/transfer/inbound/download_manager
   api/internal/transfer/outbound/copy_manager
   api/internal/transfer/outbound/copy_source
   api/internal/transfer/outbound/large_file_upload_state
   api/internal/transfer/outbound/progress_reporter
   api/internal/transfer/outbound/upload_manager
   api/internal/transfer/outbound/upload_source_part
   api/internal/transfer/emerger
   api/internal/upload_source
   api/internal/raw_simulator

