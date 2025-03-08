#!/bin/bash

set -e

num=$(expr "${1:-10}" + 0 2>/dev/null)

# Test N times to ensure a test spec is not flaky
for ((i = 1; i <= $num; i++)); do
	echo "Test $i..."
	# cargo make clean-tests && cargo nextest run
	cargo nextest run file_integrity_cancel
done

echo "Tests completed ($num)"
