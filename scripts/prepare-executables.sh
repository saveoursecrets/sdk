#/usr/bin/env bash

set -e

EXES="$@"
BIN_DIR=${BIN_DIR:-target/bin}

echo "$EXES"

mkdir -p $BIN_DIR
cp -f $EXES $BIN_DIR
cp LICENSE-APACHE LICENSE-MIT COPYRIGHT $BIN_DIR
ls -la $BIN_DIR

#OS="$(uname -s)"
#case "${OS}" in
  #Darwin*)
    #./scripts/macos-codesign.sh $BIN_DIR
    
    ## zip each executable for notarization
    #for EXE in $EXES; do
      #EXE_NAME=$(basename "$EXE")
      #EXE_DIR=$(dirname "$EXE")
      #DIR="$EXE_DIR" EXE="$EXE_NAME" ./scripts/macos-notarize.sh
    #done
  #;;
#esac
