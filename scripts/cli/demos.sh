#!/bin/sh

set -e

source scripts/cli/env.sh

rm target/*.{zip,vcf,heic}

scripts=tests/command_line/scripts/demos
anticipate \
  record \
  --parallel \
  --overwrite \
  --print-comments \
  --setup $scripts/accounts-basic.sh \
  demos \
  $scripts/version.sh \
  $scripts/help.sh \
  $scripts/server.sh \
  $scripts/secrets-basic.sh
