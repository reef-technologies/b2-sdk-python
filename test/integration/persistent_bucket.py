######################################################################
#
# File: test/integration/persistent_bucket.py
#
# Copyright 2024 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
import hashlib
import os
import uuid
from dataclasses import dataclass
from functools import cached_property
from test.integration.helpers import BUCKET_NAME_LENGTH

from b2sdk._internal.bucket import Bucket
from b2sdk.v2 import B2Api
from b2sdk.v2.exception import NonExistentBucket

PERSISTENT_BUCKET_NAME_PREFIX = "constst"


@dataclass
class PersistentBucketAggregate:
    bucket: Bucket

    def __post_init__(self):
        self.subfolder = self.new_subfolder()

    @property
    def bucket_name(self) -> str:
        return self.bucket.name

    def new_subfolder(self) -> str:
        return f"test-{uuid.uuid4().hex[:8]}"

    @property
    def bucket_id(self):
        return self.bucket.id_

    @cached_property
    def b2_uri(self):
        return f"b2://{self.bucket_name}/{self.subfolder}"


def hash_dict_sha256(d):
    """
    Create a sha256 hash of the given dictionary.
    """
    dict_repr = repr(sorted((k, repr(v)) for k, v in d.items()))
    hash_obj = hashlib.sha256()
    hash_obj.update(dict_repr.encode('utf-8'))
    return hash_obj.hexdigest()


def get_persistent_bucket_name(b2_api: B2Api, create_options: dict) -> str:
    """
    Create a hash of the `create_options` dictionary, include it in the bucket name
    so that we can easily reuse buckets with the same options across (parallel) test runs.
    """
    # Exclude sensitive options from the hash
    unsafe_options = {"authorizationToken", "accountId", "default_server_side_encryption"}
    create_options_hashable = {k: v for k, v in create_options.items() if k not in unsafe_options}
    hashed_options = hash_dict_sha256(create_options_hashable)
    bucket_owner = os.environ.get("GITHUB_REPOSITORY_ID", b2_api.get_account_id())
    bucket_base = f"{bucket_owner}:{hashed_options}"
    bucket_hash = hashlib.sha256(bucket_base.encode()).hexdigest()
    return f"{PERSISTENT_BUCKET_NAME_PREFIX}-{bucket_hash}" [:BUCKET_NAME_LENGTH]


def get_or_create_persistent_bucket(b2_api: B2Api, **create_options) -> Bucket:
    bucket_name = get_persistent_bucket_name(b2_api, create_options.copy())
    try:
        bucket = b2_api.get_bucket_by_name(bucket_name)
    except NonExistentBucket:
        bucket = b2_api.create_bucket(
            bucket_name,
            bucket_type="allPublic",
            lifecycle_rules=[
                {
                    "daysFromHidingToDeleting": 1,
                    "daysFromUploadingToHiding": 1,
                    "fileNamePrefix": "",
                }
            ],
            **create_options,
        )
    return bucket
