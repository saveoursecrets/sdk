#!/bin/sh

set -e

source scripts/cli/env.sh
export NO_COLOR=1

rm target/*.zip

if [ -n "$DEBUG" ]; then
  export PATH="target/debug:$PATH"
fi

command -v sos

anticipate \
  run \
  --setup tests/command_line/scripts/setup/account.sh \
  tests/command_line/scripts/specs/*.sh
