#!/bin/sh

set -e

source scripts/cli/env.sh

scripts=tests/command_line/scripts/demos
anticipate \
  record \
  --overwrite \
  --parallel \
  --print-comments \
  --setup $scripts/setup/account-basic.sh \
  demos \
  $scripts/shell-basic.sh
