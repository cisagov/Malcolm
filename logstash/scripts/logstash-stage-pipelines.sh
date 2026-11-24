#!/usr/bin/env bash
# Copyright (c) 2026 Battelle Energy Alliance, LLC. All rights reserved.

# Overlay administrator-supplied pipeline files and assets onto the runtime tree.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 SOURCE_DIRECTORY RUNTIME_DIRECTORY" >&2
  exit 1
fi

# The optional bind mount need not be present in ordinary deployments.
[[ -e "$1" || -L "$1" ]] || exit 0
if [[ ! -d "$1" || -L "$1" ]]; then
  echo "Pipeline source must be a real directory: $1" >&2
  exit 1
fi
SOURCE_DIR="$(cd -- "$1" && pwd -P)"
mkdir -p -- "$2"
RUNTIME_DIR="$(cd -- "$2" && pwd -P)"
if [[ "$RUNTIME_DIR/" == "$SOURCE_DIR/"* || "$SOURCE_DIR/" == "$RUNTIME_DIR/"* ]]; then
  echo "Pipeline source and runtime directories must not overlap" >&2
  exit 1
fi

shopt -s nullglob
for PIPELINE_SOURCE in "$SOURCE_DIR"/*; do
  [[ -d "$PIPELINE_SOURCE" && ! -L "$PIPELINE_SOURCE" ]] || continue
  PIPELINE_NAME="${PIPELINE_SOURCE##*/}"
  if [[ ! "$PIPELINE_NAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]]; then
    echo "Invalid pipeline directory name: $PIPELINE_NAME" >&2
    exit 1
  fi
  # Do not create empty pipelines. Symlinks are not followed or staged.
  [[ -n "$(find "$PIPELINE_SOURCE" -type f -print -quit)" ]] || continue
  PIPELINE_DEST="$RUNTIME_DIR/$PIPELINE_NAME"
  if [[ -L "$PIPELINE_DEST" ]]; then
    echo "Runtime pipeline directory must not be a symlink: $PIPELINE_DEST" >&2
    exit 1
  fi
  mkdir -p -- "$PIPELINE_DEST"
  # No --delete: custom additions must leave bundled filters intact.
  # Do not preserve host ownership or read-only modes: startup edits runtime files.
  rsync -r -- "$PIPELINE_SOURCE/" "$PIPELINE_DEST/"
  find "$PIPELINE_DEST" -type d -exec chmod u+rwx '{}' +
  find "$PIPELINE_DEST" -type f -exec chmod u+rw '{}' +
done
