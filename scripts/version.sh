#!/usr/bin/env bash

set -e

# should be called from the repo root
cd crates/sos && cargo pkgid | cut -f2 -d '#'
