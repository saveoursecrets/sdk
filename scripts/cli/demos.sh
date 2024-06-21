#!/bin/sh

set -e

source scripts/cli/env.sh

scripts=crates/integration_tests/tests/command_line/scripts
SPECS=($scripts/demos/*.sh)
SPEC=${SPEC:-${SPECS[@]}}

anticipate \
  record \
  --overwrite \
  --parallel \
  --print-comments \
  --setup $scripts/demos/setup/account-basic.sh \
  demos \
  $SPEC
