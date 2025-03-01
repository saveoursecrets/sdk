#!/bin/sh

set -e

source scripts/cli/env.sh
export NO_COLOR=1
export PATH="target/debug:$PATH"

command -v sos

scripts=tests/command_line/scripts
SPECS=($scripts/specs/*.sh)
SPEC=${SPEC:-${SPECS[@]}}

anticipate \
  run \
  --setup $scripts/setup.sh \
  --teardown $scripts/teardown.sh \
  --timeout 15000 \
  $SPEC
