# http-dumper

A simple HTTP server that dumps incoming requests to the console.
It is useful for debugging HTTP clients.

It can run either HTTP 1.1 or HTTP/2 in clear or TLS mode.

For TLS mode a certificate needs to be provided. The justfile
has a recipe for generating the certificate.


