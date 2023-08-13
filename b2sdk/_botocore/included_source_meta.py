######################################################################
#
# File: b2sdk/requests/included_source_meta.py
#
# Copyright 2022 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
from b2sdk.included_sources import IncludedSourceMeta, add_included_source

included_source_meta = IncludedSourceMeta(
    'botocore', 'Included in a revised form', {
        'NOTICE':
            """botocore
Copyright 2012-2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.

b2sdk includes vendorized parts of the botocore python library for 100-continue functionality.

Copyright 2023 Backblaze Inc.
Changes made to the original source:
* Updated botocore.awsrequest.request method to work with str/byte header values (urllib 1.x vs 2.x)
* Updated botocore.awsrequest._handle_expect_response method to work with b2 responses
* Updated botocore.awsrequest._send_output method to change 100 response timeout"""
    }
)
add_included_source(included_source_meta)
