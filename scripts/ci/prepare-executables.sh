#/usr/bin/env bash

set -e

EXES="$@"
BIN_DIR=${BIN_DIR:-target/bin}

echo "$EXES"

mkdir -p $BIN_DIR
cp -f $EXES $BIN_DIR
cp LICENSE-APACHE LICENSE-MIT COPYRIGHT $BIN_DIR
ls -la $BIN_DIR
