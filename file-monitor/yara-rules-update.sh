#!/usr/bin/env bash

set -e
set -u
set -o pipefail

ENCODING="utf-8"

[[ "${EXTRACTED_FILE_UPDATE_RULES:-"false"}" == "true" ]] || exit 0

SRC_DIR=${YARA_RULES_SRC_DIR:-"/usr/local/src/signature-base"}
LINK_DIR=${YARA_RULES_DIR:-"/yara-rules"}

if type git >/dev/null 2>&1 && [[ -d "$SRC_DIR" ]] && [[ -d "$LINK_DIR" ]]; then
  pushd "$SRC_DIR" >/dev/null 2>&1
  git remote update
  git fetch --depth 1 origin
  git reset --hard origin
  popd >/dev/null 2>&1
  rm -f "$LINK_DIR"/*.yar
  ln -v -f -s -r "$YARA_RULES_SRC_DIR"/yara/*.yar "$YARA_RULES_SRC_DIR"/vendor/yara/*.yar "$LINK_DIR"/
else
  exit 1
fi
