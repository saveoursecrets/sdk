#!/usr/bin/env bash

set -e

# macOS rejects certificates in the chain whose validity exceeds
# 825 days (errSecCertificateValidityPeriodTooLong, -67901).
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout root.key -out root.crt \
  -days 825 \
  -config root.conf

openssl req -new -nodes -newkey rsa:2048 \
  -keyout server.key \
  -out server.csr \
  -config server.conf

openssl x509 -req \
  -in server.csr \
  -CA root.crt -CAkey root.key -CAcreateserial \
  -out server.crt \
  -days 365 \
  -extfile server_ext.conf
