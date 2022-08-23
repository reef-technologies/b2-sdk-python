######################################################################
#
# File: b2sdk/v0/bucket.py
#
# Copyright 2019 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################

from b2sdk import v1


class Bucket(v1.Bucket):
    def list_file_names(self, start_filename=None, max_entries=None, prefix=None):
        """
        Legacy interface which just returns whatever remote API returns.
        """
        return self.api.session.list_file_names(self.id_, start_filename, max_entries, prefix)

    def list_file_versions(self, start_filename=None, start_file_id=None, max_entries=None, prefix=None):
        """
        Legacy interface which just returns whatever remote API returns.
        """
        return self.api.session.list_file_versions(self.id_, start_filename, start_file_id, max_entries, prefix)


class BucketFactory(v1.BucketFactory):
    BUCKET_CLASS = staticmethod(Bucket)
