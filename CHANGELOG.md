# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This project uses [*towncrier*](https://towncrier.readthedocs.io/) and the changes for the 
upcoming release can be found in [changelog.d](changelog.d).

<!-- towncrier release notes start -->

## [2.9.4](https://github.com/Backblaze/b2-sdk-python/releases/tag/v2.9.4) - 2025-06-11


### Fixed

- Fix broken `StubAccountInfo.list_bucket_names_ids()`.
- Fix bucket name mapping in `RawSimulator.authorize_account()`.
- Fix incorrect path check in `LocalFolder.make_full_path`.


## [2.9.3](https://github.com/Backblaze/b2-sdk-python/releases/tag/v2.9.3) - 2025-05-29


### Fixed

- Fix `B2HttpApiConfig` and `Services` references in exposed `v2` API.


## [2.9.2](https://github.com/Backblaze/b2-sdk-python/releases/tag/v2.9.2) - 2025-05-29


### Fixed

- Fix incorrect reliance on v3 abstractions in apiver v2. ([#540](https://github.com/Backblaze/b2-sdk-python/issues/540))


## [2.9.1](https://github.com/Backblaze/b2-sdk-python/releases/tag/v2.9.1) - 2025-05-28


### Changed

- Adapt authorize_account flow to multi-bucket keys.
- Migrate to b2 native api v4.
- Move url_for_api func to an internal classmethod in B2Api class.
- Release apiver v3 interface. `from b2sdk.v3 import ...` is now the recommended import, but previous versions are still supported.
- Update application key classes to support multiple bucket ids.
- Update create_key flow to multi-bucket keys.

### Infrastructure

- Migrate integration tests to apiver v3.


## [2.8.1](https://github.com/Backblaze/b2-sdk-python/releases/tag/v2.8.1) - 2025-04-24


### Fixed

- Fix TimeoutError handling in `b2http`.

### Doc

- Document params in FileRetentionSetting class. ([#532](https://github.com/Backblaze/b2-sdk-python/issues/532))


## [2.8.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v2.8.0) - 2025-01-23


### Changed

- Migrate to B2 Native API v3.

### Fixed

- Fix continuation for started large files with no fully finished parts.
- Perform re-authentication for empty 401 responses returned for `HEAD` requests.

### Infrastructure

- Remove yapf in favor of ruff.


## [2.7.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v2.7.0) - 2024-12-12


### Changed

- Make Event Notifications generally available. ([#518](https://github.com/Backblaze/b2-sdk-python/issues/518))
- Switch a pytest hook from path to collection_path.

### Fixed

- Add upload token reset after upload timeout.
- Fix file/directory permission handling for Windows during the B2 sync.

### Infrastructure

- Fix event notification tests when introducing new keys in API outputs.


## [2.6.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v2.6.0) - 2024-10-28


### Removed

- Remove Python 3.7 support in new releases.
  Under Python 3.7 `pip` will keep resolving the latest version of the package that supports active interpreter.
  Python 3.8 is now the minimum supported version, [until it reaches EOL in October 2024](https://devguide.python.org/versions/).
  We encourage use of the latest stable Python release.

### Fixed

- Fixed datetime.utcnow() deprecation warnings under Python 3.12.

### Added

- Declare official support for Python 3.13 in b2sdk.
  Test b2sdk against Python 3.13 in CI.

### Infrastructure

- Upgraded to pytest 8 (#484).


## [2.5.1](https://github.com/Backblaze/b2-sdk-python/releases/tag/v2.5.1) - 2024-08-15


### Fixed

- Fix LocalFolder.all_files(..) erroring out if one of the non-excluded directories is not readable by the user running the scan.
  Warning is added to ProgressReport instead as other file access errors are.


## [2.5.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v2.5.0) - 2024-07-30


### Fixed

- Fix TruncatedOutput errors when downloading files over congested network (fixes [B2_Command_Line_Tool#554](https://github.com/Backblaze/B2_Command_Line_Tool/issues/554)).
- Ensure `FileSimulator.as_download_headers` returns `dict[str, str]` mapping.

### Added

- Add `unhide_file` method to Bucket class.

### Doc

- Improve `download_file_from_url` methods type hints.

### Infrastructure

- Limit max CI (Github Actions) duration to 90 minutes.


## [2.4.1](https://github.com/Backblaze/b2-sdk-python/releases/tag/v2.4.1) - 2024-06-19


### Fixed

- Fix `LocalFolder` regression (introduced in 2.4.0) which caused `LocalFolder` to not list files by path lexicographical order.
  This is also a fix for `synchronizer` re-uploading files on every run in some cases. ([#502](https://github.com/Backblaze/b2-sdk-python/issues/502))


## [2.4.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v2.4.0) - 2024-06-17


### Changed

- In `b2sdk.v3` the `B2Api` will always create `cache` from `AccountInfo` object, unless `cache` is provided explicitly.
  The current stable `b2sdk.v2` remains unchanged, i.e. `DummyCache` is created by default if `account_info` was provided, but not `cache`.
  Documentation for `b2sdk.v2` was updated with the new recommended usage, e.g. `B2Api(info, cache=AuthInfoCache(info))`, to achieve the same behavior as `b2sdk.v3`. ([#497](https://github.com/Backblaze/b2-sdk-python/issues/497))

### Fixed

- Move scan filters before a read on filesystem access attempt. This will prevent unnecessary warnings and IO operations on paths that are not relevant to the operation. ([#456](https://github.com/Backblaze/b2-sdk-python/issues/456))
- Fix bucket caching erroring out when using `StubAccountInfo`.

### Added

- Add `annotated_types` dependency for type annotations that include basic value validation.
- Add `daysFromStartingToCancelingUnfinishedLargeFiles` option to `lifecycle_rules` type annotation.
- Add non-retryable `NoPaymentHistory` exception.
  API returns this exception when action (e.g. bucket creation or replication rules) is not allowed due to lack of payment history.


## [2.3.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v2.3.0) - 2024-05-15


### Added

- Add `folder_to_list_can_be_a_file` parameter to `b2sdk.v2.Bucket.ls`, that if set to `True` will allow listing a file versions if path is an exact match.
  This parameter won't be included in `b2sdk.v3.Bucket.ls` and unless supplied `path` ends with `/`, the possibility of path pointing to file will be considered first.


## [2.2.1](https://github.com/Backblaze/b2-sdk-python/releases/tag/v2.2.1) - 2024-05-09


### Fixed

- Fix `__str__` of `b2sdk.v2.BucketIdNotFound` to return full error message and not just missing bucket ID value.


## [2.2.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v2.2.0) - 2024-05-08

### Added

- Add `has_errors_or_warnings` method to `ProgressReport` class.

### Fixed

- Ensure `b2sdk.v2.b2http` emits `b2sdk.v2.BucketIdNotFound` exception instead of `b2sdk._v3.BucketIdNotFound`. ([#437](https://github.com/Backblaze/b2-sdk-python/issues/437))
- Ensure `unprintable_to_hex` and `unprintable_to_hex` return empty string (instead of `None`) if empty string was supplied as argument.
- Skip files with invalid filenames when scanning directories (for `sync`, ...) instead of raising an exception.


## [2.1.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v2.1.0) - 2024-04-15


### Changed

- Use ParallelDownloader for small files instead of SimpleDownloader to avoid blocking on I/O.

### Fixed

- Fix `decode_content=True` causing an error when downloading tiny and large files.
- Prevent errors due to the use of "seekable" download strategies for seekable, but not readable files.

### Added

- Add set&get Event Notification rules methods to Bucket API as part of Event Notifications feature Private Preview.
  See https://www.backblaze.com/blog/announcing-event-notifications/ for details.


## [2.0.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v2.0.0) - 2024-04-02


### Removed

- Remove `tqdm` dependency. Now `tqdm` has to be explicitly installed to use `TqdmProgressListener` class.
- Remove `[doc]` extras dependency group - moved to dev dependencies.
- Remove unnecessary `packaging` package dependency. It's functionality was never explicitly exposed.

### Changed

- Move non-apiver packages (e.g. packages other than `b2sdk.v1`, `b2sdk.v2`, ...) to `b2sdk._internal` to further discourage use of non-public internals.
  If you accidentally used non-public internals, most likely only thing you will need to do, is import from `b2sdk.v2` instead of `b2sdk`.
- Move logging setup and `UrllibWarningFilter` class from `b2sdk.__init__.py` to `b2sdk._v3` (and thus `b2sdk.v2` & `b2sdk.v1`).
  This will allow us to remove/change it in new apiver releases without the need to change the major semver version.

### Added

- Add `SqliteAccountInfo.get_user_account_info_path` to public API.

### Infrastructure

- Update to [GitHub Actions using Node 20](https://github.blog/changelog/2023-09-22-github-actions-transitioning-from-node-16-to-node-20/).


## [1.33.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.33.0) - 2024-03-15


### Fixed

- Escape control characters whenever printing object and bucket names to improve security.
- Remove unused `setuptools` from default dependency list.

### Added

- Added control character escaping methods.


## [1.32.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.32.0) - 2024-02-26


### Added

- Add `set_thread_pool_size`, `get_thread_pool_size` to *Manger classes.

### Infrastructure

- Fix schema graph rendering in readthedocs documentation.


## [1.31.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.31.0) - 2024-02-19


### Fixed

- Remove obsolete test scripts from b2sdk package: `test_upload_url_concurrency`, `b2sdk.b2http:test_http`. ([#471](https://github.com/Backblaze/b2-sdk-python/issues/471))

### Added

- Allow for `min_part_size` that is greater than default `recommended_part_size` value, without having to explicitly set `recommended_part_size` value.
- Add `GET` method support to `B2Http`.
- Add `JSON` type annotation and fix type hints in `B2Http` methods.
- Add more type hints to API methods.


## [1.30.1](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.30.1) - 2024-02-02


### Fixed

- Fix package author metadata.


## [1.30.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.30.0) - 2024-02-02


### Fixed

- Fix escape sequence warnings present in python 3.12. ([#458](https://github.com/Backblaze/b2-sdk-python/issues/458))
- Handle json encoded, invalid B2 error responses, preventing exceptions such as `invalid literal for int() with base 10: 'service_unavailable'`.

### Added

- Add support for filters to `Bucket.ls()`.

### Infrastructure

- Package the library using [pdm](https://pdm-project.org), use locked dependencies in CI.
- Update `ruff` linter and apply it to all files.


## [1.29.1](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.29.1) - 2024-01-23


### Fixed

- Handle non-json encoded B2 error responses, i.e. retry on 502 and 504 errors.

### Doc

- Add missing import in Synchronizer docs example.


## [1.29.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.29.0) - 2023-12-13


### Changed

- Change v3.B2Api.authorize_account signature to make `realm` optional and `"production"` by default.

### Added

- Progress listener instances can now change their descriptions during run. This allows for e.g.: changing description after file headers are downloaded but before the content is fetched.

### Infrastructure

- Add `-v` to pytest in CI.
- Run windows pypy3.9 tests on nightly builds.


## [1.28.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.28.0) - 2023-12-06


### Changed

- On XDG compatible OSes (Linux, BSD), the profile file is now created in `$XDG_CONFIG_HOME` (with a fallback to `~/.config/` in absence of given env. variable).
- Replace blank `assert` with exception when size values for parts upload are misaligned.

### Fixed

- Streaming from empty stream no longer ends with "Empty emerge parts iterator" error.

### Infrastructure

- Changelog entries are now validated as a part of CI pipeline.
- Disable dependabot requests for updates unrelated to security issues.
- Fixed tests failing because of changes made to `locale.normalize` in Python 3.12.


## [1.27.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.27.0) - 2023-11-26


### Changed

- Add dependency on `setuptools` and `packaging` as they are not shipped by cpython 3.12 and are used in production code.

### Fixed

- Fix closing of passed progress listeners in `Bucket.upload` and `Bucket.copy`


## [1.26.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.26.0) - 2023-11-20


### Added

- Add `expires`, `content_disposition`, `content_encoding`, `content_language` arguments to various `Bucket` methods ([#357](https://github.com/Backblaze/b2-sdk-python/issues/357))

### Infrastructure

- Towncrier changelog generation - to avoid conflicts when simultaneously working on PRs
- Fix towncrier generated changelog to work with mindsers/changelog-reader-action


## [1.25.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.25.0) - 2023-11-15

### Added
- Add `*_PART_SIZE`, `BUCKET_NAME_*`, `STDOUT_FILEPATH` constants
- Add `points_to_fifo`, `points_to_stdout` functions

### Changed
- Mark `TempDir` as deprecated in favor of `tempfile.TemporaryDirectory`

### Fixed
- Fix downloading to a non-seekable file, such as /dev/stdout
- Fix ScanPoliciesManager support for compiled regexes

### Infrastructure
- Fix readthedocs build by updating to v2 configuration schema
- Fix spellcheck erroring out on LICENSE file
- Fix snyk reporting vulnerability due to tornado package use in docs generation
- Deduplicate test_base files in test suite
- Refactor integration tests for better pytest compatibility & eager bucket cleanup

## [1.24.1](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.24.1) - 2023-09-27

### Fixed
- Fix missing key ID for large file encrypted with SSE-C
- Fix concatenating error message when message is None

## [1.24.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.24.0) - 2023-08-31

### Added
- 'bypass_governance' flag to delete_file_version

## [1.23.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.23.0) - 2023-08-10

### Added
- Add `get_file_info_by_name` to the B2Api class

### Fixed
- Require `typing_extensions` on Python 3.11 (already required on earlier versions) for better compatibility with pydantic v2
- Fix `RawSimulator` handling of `cache_control` parameter during tests.

## [1.22.1](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.22.1) - 2023-07-24

### Fixed
- Fix regression in dir exclusion patterns introduced in 1.22.0

## [1.22.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.22.0) - 2023-07-21

### Added
- Declare official support of Python 3.12
- Improved `lifecycle_rules` argument type annotations

### Deprecated
- Deprecate `file_infos` argument. Use `file_info` instead. Old argument name won't be supported in v3.

### Changed
- `version_utils` decorators now ignore `current_version` parameter to better fit `apiver` needs

### Fixed
- Circular symlinks no longer cause infinite loops when syncing a folder
- Fix crash on upload retry with unbound data source

### Infrastructure
- Remove unsupported PyPy versions (3.7, 3.8) from tests matrix and add PyPy 3.9 & 3.10 instead
- Replaced `pyflakes` with `ruff` for linting
- Refactored logic for resuming large file uploads to unify code paths, correct inconsistencies, and enhance configurability (#381)
- Automatically set copyright date when generating the docs
- Use modern type hints in documentation (achieved through combination of PEP 563 & 585 and `sphinx-autodoc-typehints`)

## [1.21.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.21.0) - 2023-04-17

### Added
- Add support for custom upload timestamp
- Add support for cache control header while uploading

### Infrastructure
- Remove dependency from `arrow`
- Build Python wheels for distribution

## [1.20.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.20.0) - 2023-03-23

### Added
- Add `use_cache` parameter to `B2Api.list_buckets`

### Changed
- Connection timeout is now being set explicitly

### Fixed
- Small files downloaded twice

### Infrastructure
- Disable changelog verification for dependabot PRs

## [1.19.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.19.0) - 2023-01-24

### Added
- Authorizing a key for a single bucket ensures that this bucket is cached
- `Bucket.ls` operation supports wildcard matching strings
- Documentation for `AbstractUploadSource` and its children
- `InvalidJsonResponse` when the received error is not a proper JSON document
- Raising `PotentialS3EndpointPassedAsRealm` when a specific misconfiguration is suspected
- Add `large_file_sha1` support
- Add support for incremental upload and sync
- Ability to stream data from an unbound source to B2 (for example stdin)

### Fixed
- Removed information about replication being in closed beta
- Don't throw raw `OSError` exceptions when using `DownloadedFile.save_to` to a path that doesn't exist, is a directory or the user doesn't have permissions to write to

### Infrastructure
- Additional tests for listing files/versions
- Ensured that changelog validation only happens on pull requests
- Upgraded GitHub actions checkout to v3, python-setup to v4
- Additional tests for `IncrementalHexDigester`

## [1.18.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.18.0) - 2022-09-20

### Added
- Logging performance summary of parallel download threads
- Add `max_download_streams_per_file` parameter to B2Api class and underlying structures
- Add `is_file_lock_enabled` parameter to `Bucket.update()` and related methods

### Fixed
- Replace `ReplicationScanResult.source_has_sse_c_enabled` with `source_encryption_mode`
- Fix `B2Api.get_key()` and `RawSimulator.delete_key()`
- Fix calling `CopySizeTooBig` exception

### Infrastructure
- Fix nox's deprecated `session.install()` calls
- Re-enable changelog validation in CI
- StatsCollector contains context managers for gathering performance statistics

## [1.17.3](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.17.3) - 2022-07-15

### Fixed
- Fix `FileVersion._get_upload_headers` when encryption key is `None`

### Infrastructure
- Fix download integration tests on non-production environments
- Add `B2_DEBUG_HTTP` env variable to enable network-level test debugging
- Disable changelog validation temporarily

## [1.17.2](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.17.2) - 2022-06-24

### Fixed
- Fix a race in progress reporter
- Fix import of replication

## [1.17.1](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.17.1) - 2022-06-23 [YANKED]

### Fixed
- Fix importing scan module

## [1.17.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.17.0) - 2022-06-23 [YANKED]

As in version 1.16.0, the replication API may still be unstable, however
no backward-incompatible changes are planned at this point.

### Added
- Add `included_sources` module for keeping track of included modified third-party libraries
- Add `include_existing_files` parameter to `ReplicationSetupHelper`
- Add `get_b2sdk_doc_urls` function for extraction of external documentation URLs during runtime

### Changed
- Downloading compressed files with `Content-Encoding` header set no longer causes them to be decompressed on the fly - it's an option
- Change the per part retry limit from 5 to 20 for data transfer operations. Please note that the retry system is not considered to be a part of the public interface and is subject to be adjusted
- Do not wait more than 64 seconds between retry attempts (unless server asks for it)
- On longer failures wait an additional (random, up to 1s) amount of time to prevent client synchronization
- Flatten `ReplicationConfiguration` interface
- Reorder actions of `ReplicationSetupHelper` to avoid zombie rules

### Fixed
- Fix: downloading compressed files and decompressing them on the fly now does not cause a TruncatedOutput error
- Fix `AccountInfo.is_master_key()`
- Fix docstring of `SqliteAccountInfo`
- Fix lifecycle rule type in the docs

### Infrastructure
- Add 3.11.0-beta.1 to CI
- Change Sphinx major version from 5 to 6
- Extract folder/bucket scanning into a new `scan` module
- Enable pip cache in CI

## [1.16.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.16.0) - 2022-04-27

This release contains a preview of replication support. It allows for basic
usage of B2 replication feature (currently in closed beta).

As the interface of the sdk (and the server api) may change, the replication
support shall be considered PRIVATE interface and should be used with caution.
Please consult the documentation on how to safely use the private api interface.

Expect substantial amount of work on sdk interface:
- The interface of `ReplicationConfiguration` WILL change
- The interface of `FileVersion.replication_status` MIGHT change
- The interface of `FileVersionDownload` MIGHT change

### Added
- Add basic replication support to `Bucket` and `FileVersion`
- Add `is_master_key()` method to `AbstractAccountInfo`
- Add `readBucketReplications` and `writeBucketReplications` to `ALL_CAPABILITIES`
- Add log tracing of `interpret_b2_error`
- Add `ReplicationSetupHelper`

### Fixed
- Fix license test on Windows
- Fix cryptic errors when running integration tests with a non-full key

## [1.15.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.15.0) - 2022-04-12

### Changed
- Don't run coverage in pypy in CI
- Introduce a common thread worker pool for all downloads
- Increase http timeout to 20min (for copy using 5GB parts)
- Remove inheritance from object (leftover from python2)
- Run unit tests on all CPUs

### Added
- Add pypy-3.8 to test matrix
- Add support for unverified checksum upload mode
- Add dedicated exception for unverified email
- Add a parameter to customize `sync_policy_manager`
- Add parameters to set the min/max part size for large file upload/copy methods
- Add CopySourceTooBig exception
- Add an option to set a custom file version class to `FileVersionFactory`
- Add an option for B2Api to turn off hash checking for downloaded files
- Add an option for B2Api to set write buffer size for `DownloadedFile.save_to` method
- Add support for multiple profile files for SqliteAccountInfo

### Fixed
- Fix copying objects larger than 1TB
- Fix uploading objects larger than 1TB
- Fix downloading files with unverified checksum
- Fix decoding in filename and file info of `DownloadVersion`
- Fix an off-by-one bug and other bugs in the Simulator copy functionality

### Removed
- Drop support for Python 3.5 and Python 3.6

## [1.14.1](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.14.1) - 2022-02-23

### Security
- Fix setting permissions for local sqlite database (thanks to Jan Schejbal for responsible disclosure!)

## [1.14.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.14.0) - 2021-12-23

### Fixed
- Relax constraint on arrow to allow for versions >= 1.0.2

## [1.13.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.13.0) - 2021-10-24

### Added
- Add support for Python 3.10

### Changed
- Update a list with all capabilities

### Fixed
- Fix pypy selector in CI

## [1.12.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.12.0) - 2021-08-06

### Changed
- The `importlib-metadata` requirement is less strictly bound now (just >=3.3.0 for python > 3.5).
- `B2Api` `update_file_legal_hold` and `update_file_retention_setting` now return the set values

### Added
- `BucketIdNotFound` thrown based on B2 cloud response
- `_clone` method to `FileVersion` and `DownloadVersion`
- `delete`, `update_legal_hold`, `update_retention` and `download` methods added to `FileVersion`

### Fixed
- FileSimulator returns special file info headers properly

### Removed
- One unused import.

## [1.11.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.11.0) - 2021-06-24

### Changed
- apiver `v2` interface released. `from b2sdk.v2 import ...` is now the recommended import,
  but `from b2sdk.v1 import ...` works as before

## [1.10.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.10.0) - 2021-06-23

### Added
- `get_fresh_state` method added to `FileVersion` and `Bucket`

### Changed
- `download_file_*` methods refactored to allow for inspecting DownloadVersion before downloading the whole file
- `B2Api.get_file_info` returns a `FileVersion` object in v2
- `B2RawApi` renamed to `B2RawHTTPApi`
- `B2HTTP` tests are now common
- `B2HttpApiConfig` class introduced to provide parameters like `user_agent_append` to `B2Api` without using internal classes in v2
- `Bucket.update` returns a `Bucket` object in v2
- `Bucket.ls` argument `show_versions` renamed to `latest_only` in v2
- `B2Api` application key methods refactored to operate with dataclasses instead of dicts in v2
- `B2Api.list_keys` is a generator lazily fetching all keys in v2
- `account_id` and `bucket_id` added to FileVersion

### Fixed
- Fix EncryptionSetting.from_response_headers
- Fix FileVersion.size and FileVersion.mod_time_millis type ambiguity
- Old buckets (from past tests) are cleaned up before running integration tests in a single thread

### Removed
- Remove deprecated `SyncReport` methods

## [1.9.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.9.0) - 2021-06-07

### Added
- `ScanPoliciesManager` is able to filter b2 files by upload timestamp

### Changed
- `Synchronizer.make_file_sync_actions` and `Synchronizer.make_folder_sync_actions` were made private in v2 interface
- Refactored `sync.file.*File` and `sync.file.*FileVersion` to `sync.path.*SyncPath` in v2
- Refactored `FileVersionInfo` to `FileVersion` in v2
- `ScanPoliciesManager` exclusion interface changed in v2
- `B2Api` unittests for v0, v1 and v2 are now common
- `B2Api.cancel_large_file` returns a `FileIdAndName` object instead of a `FileVersion` object in v2
- `FileVersion` has a mandatory `api` parameter in v2
- `B2Folder` holds a handle to B2Api
- `Bucket` unit tests for v1 and v2 are now common

### Fixed
- Fix call to incorrect internal api in `B2Api.get_download_url_for_file_name`

## [1.8.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.8.0) - 2021-05-21

### Added
- Add `get_bucket_name_or_none_from_bucket_id` to `AccountInfo` and `Cache`
- Add possibility to change realm during integration tests
- Add support for "file locks": file retention, legal hold and default bucket retention

### Fixed
- Cleanup sync errors related to directories
- Use proper error handling in `ScanPoliciesManager`
- Application key restriction message reverted to previous form
- Added missing apiver wrappers for FileVersionInfo
- Fix crash when Content-Range header is missing
- Pin dependency versions appropriately

### Changed
- `b2sdk.v1.sync` refactored to reflect `b2sdk.sync` structure
- Make `B2Api.get_bucket_by_id` return populated bucket objects in v2
- Add proper support of `recommended_part_size` and `absolute_minimum_part_size` in `AccountInfo`
- Refactored `minimum_part_size` to `recommended_part_size` (the value used stays the same)
- Encryption settings, types and providers are now part of the public API

### Removed
- Remove `Bucket.copy_file` and `Bucket.start_large_file`
- Remove `FileVersionInfo.format_ls_entry` and `FileVersionInfo.format_folder_ls_entry`

## [1.7.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.7.0) - 2021-04-22

### Added
- Add `__slots__` and `__eq__` to `FileVersionInfo` for memory usage optimization and ease of testing
- Add support for SSE-C server-side encryption mode
- Add support for `XDG_CONFIG_HOME` for determining the location of `SqliteAccountInfo` db file

### Changed
- `BasicSyncEncryptionSettingsProvider` supports different settings sets for reading and writing
- Refactored AccountInfo tests to a single file using pytest

### Fixed
- Fix clearing cache during `authorize_account`
- Fix `ChainedStream` (needed in `Bucket.create_file` etc.)
- Make tqdm-based progress reporters less jumpy and easier to read
- Fix emerger examples in docs

## [1.6.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.6.0) - 2021-04-08

### Added
- Fetch S3-compatible API URL from `authorize_account`

### Fixed
- Exclude packages inside the test package when installing
- Fix for server response change regarding SSE

## [1.5.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.5.0) - 2021-03-25

### Added
- Add `dependabot.yml`
- Add support for SSE-B2 server-side encryption mode

### Changed
- Add upper version limit for the requirements

### Fixed
- Pin `setuptools-scm<6.0` as `>=6.0` doesn't support Python 3.5

## [1.4.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.4.0) - 2021-03-03

### Changed
- Add an ability to provide `bucket_id` filter parameter for `list_buckets`
- Add `is_same_key` method to `AccountInfo`
- Add upper version limit for arrow dependency, because of a breaking change

### Fixed
- Fix docs autogen

## [1.3.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.3.0) - 2021-01-13

### Added
- Add custom exception for `403 transaction_cap_exceeded`
- Add `get_file_info_by_id` and `get_file_info_by_name` to `Bucket`
- `FileNotPresent` and `NonExistentBucket` now subclass new exceptions `FileOrBucketNotFound` and `ResourceNotFound`

### Changed
- Fix missing import in the synchronization example
- Use `setuptools-scm` for versioning
- Clean up CI steps

## [1.2.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.2.0) - 2020-11-03

### Added
- Add support for Python 3.9
- Support for bucket to bucket sync
- Add a possibility to append a string to the User-Agent in `B2Http`

### Changed
- Change default fetch count for `ls` to 10000

### Removed
- Drop Python 2 and Python 3.4 support :tada:
- Remove `--prefix` from `ls` (it didn't really work, use `folderName` argument)

### Fixed
- Allow to set an empty bucket info during the update
- Fix docs generation in CI

## [1.1.4](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.1.4) - 2020-07-15

### Added
- Allow specifying custom realm in B2Session.authorize_account

## [1.1.2](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.1.2) - 2020-07-06

### Fixed
- Fix upload part for file range on Python 2.7

## [1.1.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.1.0) - 2020-06-24

### Added
- Add `list_file_versions` method to buckets.
- Add server-side copy support for large files
- Add ability to synthesize objects from local and remote sources
- Add AuthInfoCache, InMemoryCache and AbstractCache to public interface
- Add ability to filter in ScanPoliciesManager based on modification time
- Add ScanPoliciesManager and SyncReport to public interface
- Add md5 checksum to FileVersionInfo
- Add more keys to dicts returned by as_dict() methods

### Changed
- Make sync treat hidden files as deleted
- Ignore urllib3 "connection pool is full" warning

### Removed
- Remove arrow warnings caused by https://github.com/crsmithdev/arrow/issues/612

### Fixed
- Fix handling of modification time of files

## [1.0.2](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.0.2) - 2019-10-15

### Changed
- Remove upper version limit for arrow dependency

## [1.0.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.0.0) - 2019-10-03

### Fixed
- Minor bug fix.

## [1.0.0](https://github.com/Backblaze/b2-sdk-python/releases/tag/v1.0.0)-rc1 - 2019-07-09

### Deprecated
- Deprecate some transitional method names to v0 in preparation for v1.0.0.

## [0.1.10](https://github.com/Backblaze/b2-sdk-python/releases/tag/v0.1.10) - 2019-07-09

### Removed
- Remove a parameter (which did nothing, really) from `b2sdk.v1.Bucket.copy_file` signature

## [0.1.8](https://github.com/Backblaze/b2-sdk-python/releases/tag/v0.1.8) - 2019-06-28

### Added
- Add support for b2_copy_file
- Add support for `prefix` parameter on ls-like calls

## [0.1.6](https://github.com/Backblaze/b2-sdk-python/releases/tag/v0.1.6) - 2019-04-24

### Changed
- Rename account ID for authentication to application key ID.
Account ID is still backwards compatible, only the terminology
has changed.

### Fixed
- Fix transferer crashing on empty file download attempt

## [0.1.4](https://github.com/Backblaze/b2-sdk-python/releases/tag/v0.1.4) - 2019-04-04

### Added
Initial official release of SDK as a separate package (until now it was a part of B2 CLI)
