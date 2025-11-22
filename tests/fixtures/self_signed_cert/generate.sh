#!/usr/bin/env bash

set -e

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout root.key -out root.crt \
  -days 36500 \
  -config root.conf

openssl req -new -nodes -newkey rsa:2048 \
  -keyout server.key \
  -out server.csr \
  -config server.conf

openssl x509 -req \
  -in server.csr \
  -CA root.crt -CAkey root.key -CAcreateserial \
  -out server.crt \
  -days 36500 \
  -extfile server_ext.conf
