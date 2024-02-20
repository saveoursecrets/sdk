#!/bin/sh

set -e

export SOS_DATA_DIR="target/accounts"
export ACCOUNT_PASSWORD="demo-test-password-case"
export ACCOUNT_BACKUP="target/demo-backup.zip"
export NO_COLOR=1

anticipate \
  run \
  --setup tests/command_line/scripts/setup/account.sh \
  tests/command_line/scripts/specs/*.sh
