from b2sdk.v2 import Bucket


class BucketTrackingMixin:
    """
    Mixin class for B2Api, which enables bucket tracking.
    This mixin will add a `buckets` member to the B2Api instance and will use it track created and
    deleted buckets.  The main purpose of this are tests -- the `buckets` member can be used in test
    teardown to ensure proper bucket cleanup.
    """

    def __init__(self, *args, **kwargs):
        self.buckets = []
        super().__init__(*args, **kwargs)

    def create_bucket(self, name: str, *args, **kwargs) -> Bucket:
        bucket = super().create_bucket(name, *args, **kwargs)
        self.buckets.append(bucket)
        return bucket

    def delete_bucket(self, bucket: Bucket):
        super().delete_bucket(bucket)
        self.buckets = [b for b in self.buckets if b.id_ != bucket.id_]
