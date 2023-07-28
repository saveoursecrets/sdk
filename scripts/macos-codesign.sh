#/usr/bin/env bash

set -e

DIR="$1"
EXES=$(./scripts/find-executables.sh $DIR)
ID=${MACOS_CERTIFICATE_NAME:-$SOS_MACOS_SIGN_CERTIFICATE_ID}

for EXE in $EXES; do
  codesign -s "$ID" --timestamp -o runtime -v "$EXE" --force
done
