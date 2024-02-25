#!/bin/sh

set -e

source scripts/cli/env.sh

  #$scripts/version.sh \
  #$scripts/help.sh \
  #$scripts/server.sh \
  #$scripts/servers-basic.sh \
  #$scripts/secrets-basic.sh

scripts=tests/command_line/scripts/demos
anticipate \
  record \
  --overwrite \
  --parallel \
  --print-comments \
  --setup $scripts/setup/accounts-basic.sh \
  demos \
  $scripts/*.sh
