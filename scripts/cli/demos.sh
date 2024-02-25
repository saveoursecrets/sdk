#!/bin/sh

set -e

source scripts/cli/env.sh

scripts=tests/command_line/scripts/demos
anticipate \
  record \
  --overwrite \
  --parallel \
  --print-comments \
  --setup $scripts/setup/accounts-basic.sh \
  demos \
  $scripts/*.sh
