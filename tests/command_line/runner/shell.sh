#!/bin/sh

set -e

source tests/command_line/runner/env.sh
export NO_COLOR=1
export PATH="target/debug:$PATH"

command -v sos

if [ -z "$SOS_TEST_CLIENT_FS" ]; then
  # env has already exported SOS_DATA_DIR so this
  # will create the database file and run migrations
  sos tool db migrate
fi

anticipate \
  run \
  --setup tests/command_line/scripts/setup.sh \
  --teardown tests/command_line/scripts/teardown.sh \
  --timeout 15000 \
  tests/command_line/scripts/specs/shell.sh
