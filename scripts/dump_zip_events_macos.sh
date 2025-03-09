#!/usr/bin/env bash

set -e

command -v sos || "install sos(1)" 

# replace this with your account ID
ID="0x88d2bf1c2262ac826f25a0ddd2df7af1cd4f3e9f"
DIR="$HOME/Library/Application Support/SaveOurSecrets"
OUT="target/$ID"

mkdir -p $OUT

sos tool events folder "$DIR/identity/$ID.events" > "${OUT}/$ID.events"
sos tool events account "$DIR/local/$ID/account.events" > "${OUT}/account.events"
sos tool events file "$DIR/local/$ID/files.events" > "${OUT}/files.events"
sos tool events device "$DIR/local/$ID/devices.events" > "${OUT}/devices.events"

while IFS= read -r -d '' file; do
  case "$file" in
    *.events)
      echo "$file"
      name=$(basename "$file")
      sos tool events folder "$file" > "${OUT}/$name"
      ;;
  esac
done < <(find "$DIR/local/$ID/vaults" -type f -print0)

cd target && zip -r "${ID}.zip" "$ID" 
