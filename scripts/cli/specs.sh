#!/bin/sh

set -e

source scripts/cli/env.sh
export NO_COLOR=1
export SOS_PROMPT='➜ '

if [ -n "$DEBUG" ]; then
  export PATH="target/debug:$PATH"
fi

command -v sos

anticipate \
  run \
  --setup tests/command_line/scripts/setup.sh \
  --teardown tests/command_line/scripts/teardown.sh \
  tests/command_line/scripts/specs/*.sh
