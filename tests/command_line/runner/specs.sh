#!/bin/sh

set -e

source tests/command_line/runner/env.sh
export NO_COLOR=1
export PATH="target/debug:$PATH"

command -v sos

if [ -n "$SOS_TEST_CLIENT_DB" ]; then
  # env has already exported SOS_DATA_DIR so this
  # will create the database file and run migrations
  sos tool db migrate
fi

scripts=tests/command_line/scripts
SPECS=($scripts/specs/*.sh)
SPEC=${SPEC:-${SPECS[@]}}

anticipate \
  run \
  --setup $scripts/setup.sh \
  --teardown $scripts/teardown.sh \
  --timeout 15000 \
  $SPEC
