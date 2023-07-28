#!/usr/bin/env bash

set -e

DIR=${DIR:-target/release}
EXE=${EXE:-sos}
KEYCHAIN_PROFILE="$SOS_INSTALLER_KEYCHAIN_PROFILE"

(cd $DIR && zip "$EXE.zip" "$EXE")
ZIP=${ZIP:-$DIR/$EXE.zip}

xcrun notarytool submit $ZIP \
  --keychain-profile "$KEYCHAIN_PROFILE" \
  --wait

cd $DIR
unzip -o "$EXE.zip"
spctl --assess -vvv --type install $EXE
