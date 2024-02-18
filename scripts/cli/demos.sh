#!/bin/sh

set -e

export SOS_DATA_DIR="target/accounts"
export ACCOUNT_PASSWORD="demo-test-password-case"
export ACCOUNT_BACKUP="target/demo-backup.zip"

scripts=tests/command_line/scripts/demos
anticipate \
  record \
  --parallel \
  --overwrite \
  --print-comments \
  --logs target \
  --setup $scripts/accounts-basic.sh \
  demos \
  $scripts/version.sh \
  $scripts/help.sh \
  $scripts/server.sh \
  $scripts/secrets-basic.sh
