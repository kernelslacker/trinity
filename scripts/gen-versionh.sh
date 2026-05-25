#!/bin/bash

HEADER="include/version.h"
SCRIPT_DIR="${0%/*}"
ROOT="${SCRIPT_DIR}/.."

GIT=$(which git 2>/dev/null)
DEVEL=$(grep -c '^VERSION.*pre' "$ROOT/Makefile")

# VERSION: git describe in DEVEL mode if available, else the Makefile constant.
VER=""
if [ "$DEVEL" == "1" ] && [ -n "${GIT}" ] && [ -d "${ROOT}/.git" ]; then
  VER=$(${GIT} -C "${ROOT}" describe --always)
fi
if [ -z "$VER" ]; then
  VER=$(grep VERSION= "$ROOT/Makefile" | sed -re '1 s/.*=.*"(.*)".*/\1/')
fi

# GIT_HASH: short SHA with -dirty suffix when the tree has uncommitted
# changes.  Falls back to "unknown" for tarball builds without .git.
GIT_HASH="unknown"
if [ -n "${GIT}" ] && [ -d "${ROOT}/.git" ]; then
  GIT_HASH=$(${GIT} -C "${ROOT}" rev-parse --short=12 HEAD 2>/dev/null || echo "unknown")
  if ! ${GIT} -C "${ROOT}" diff --quiet HEAD 2>/dev/null; then
    GIT_HASH="${GIT_HASH}-dirty"
  fi
fi

# Compose into a temp file and only overwrite the header on content
# change, to avoid spurious rebuilds of every .c file that includes
# version.h.
NEW=$(mktemp)
{
  echo "#pragma once"
  echo "/* This file is auto-generated */"
  printf '#define VERSION "%s"\n' "$VER"
  printf '#define GIT_HASH "%s"\n' "$GIT_HASH"
} > "$NEW"

if ! cmp -s "$NEW" "$HEADER" 2>/dev/null; then
  mv "$NEW" "$HEADER"
else
  rm -f "$NEW"
fi
