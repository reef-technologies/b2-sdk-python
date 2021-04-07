########################
Server-Side Encryption
########################

***********************
Cloud
***********************
B2 cloud supports `Server-Side Encryption <https://www.backblaze.com/b2/docs/server_side_encryption.html>`_. All read
and write operations provided by **b2sdk** accept encyrption settings as an optional argument. Not supplying this
argument means relying on bucket defaults - for **SSE-B2** and for no encryption. In case of **SSE-C**, providing an
encryption key is crucial for succesfull donwloading and copying. This is especially apparent in ca se of sync, for more
information take a look at `imma need to put a link here`_.

