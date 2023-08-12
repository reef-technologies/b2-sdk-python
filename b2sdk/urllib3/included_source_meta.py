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
    'urllib3', 'Included in a revised form', {
        'NOTICE':
            """Urllib3
Copyright 2008-2011 Andrey Petrov and contributors.

Copyright 2023 Backblaze Inc.
Changes made to the original source:
The following classes have been overriden for support HTTP 100-continue:
urllib3.connection.HTTPConnection, urllib3.connection.VerifiedHTTPSConnection,
urllib3.connectionpool.HTTPConnectionPool, urllib3.connectionpool.HTTPSConnectionPool"""
    }
)
add_included_source(included_source_meta)
