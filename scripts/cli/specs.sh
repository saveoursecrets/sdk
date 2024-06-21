#!/bin/sh

set -e

source scripts/cli/env.sh
export NO_COLOR=1

if [ -n "$DEBUG" ]; then
  export PATH="target/debug:$PATH"
fi

command -v sos

scripts=crates/integration_tests/tests/command_line/scripts
SPECS=($scripts/specs/*.sh)
SPEC=${SPEC:-${SPECS[@]}}

anticipate \
  run \
  --setup $scripts/setup.sh \
  --teardown $scripts/teardown.sh \
  $SPEC
