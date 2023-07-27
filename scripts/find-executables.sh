#!/usr/bin/env bash

set -e

DIR="$1"
GITHUB_ENV=${GITHUB_ENV:-/dev/null}

OS="$(uname -s)"
case "${OS}" in
  Darwin*) exes=$(find $DIR -maxdepth 1 -type f -perm +111 -print | xargs);;
  *) exes=$(find $DIR -maxdepth 1 -type f -executable -print | xargs)
esac

echo "EXES='${exes}'" >> $GITHUB_ENV

#find $DIR -maxdepth 1 -type f -executable -print | xargs
#find $DIR -maxdepth 1 -type f -perm +111 -print | xargs
