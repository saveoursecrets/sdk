#!/bin/sh

set -e

source scripts/cli/env.sh
export NO_COLOR=1
export SOS_TEST=1

if [ -n "$SOS_CLI_DEBUG" ]; then
  export PATH="target/debug:$PATH"
fi

command -v sos

sos env paths

scripts=tests/command_line/scripts
SPECS=($scripts/specs/*.sh)
SPEC=${SPEC:-${SPECS[@]}}

anticipate \
  run \
  --setup $scripts/setup.sh \
  --teardown $scripts/teardown.sh \
  $SPEC
