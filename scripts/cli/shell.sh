#!/bin/sh

set -e

source scripts/cli/env.sh
export NO_COLOR=1
export PATH="target/debug:$PATH"

command -v sos

anticipate \
	run \
	--setup tests/command_line/scripts/setup.sh \
	--teardown tests/command_line/scripts/teardown.sh \
	--timeout 15000 \
	tests/command_line/scripts/specs/shell.sh
