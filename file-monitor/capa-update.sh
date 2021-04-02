#!/usr/bin/env bash

set -e
set -u
set -o pipefail

ENCODING="utf-8"

[[ "${EXTRACTED_FILE_UPDATE_RULES:-"false"}" == "true" ]] || exit 0

CAPA=${CAPA_BIN:-"/usr/local/bin/capa"}

BASE_DIR="$(mktemp -d -t capa-XXXXXX)"

function git_latest_release () {
  if [ "$1" ]; then
    (set -o pipefail && curl -sL -f "https://api.github.com/repos/$1/releases/latest" | jq '.tag_name' | sed -e 's/^"//' -e 's/"$//' ) || \
      (set -o pipefail && curl -sL -f "https://api.github.com/repos/$1/releases" | jq '.[0].tag_name' | sed -e 's/^"//' -e 's/"$//' ) || \
      echo unknown
  else
    echo "unknown">&2
  fi
}

function finish {
  rm -rf "$BASE_DIR"
}

if type git >/dev/null 2>&1; then
  trap finish EXIT
  if [[ -f "$CAPA" ]]; then
    CAPA_PREVIOUS_VERSION="$("$CAPA" --version 2>&1 | awk '{print $2}' | cut -d'-' -f1)"
  else
    CAPA_PREVIOUS_VERSION="none"
  fi
  CAPA_LATEST_VERSION="$(git_latest_release fireeye/capa)"
  if [[ -n $CAPA_LATEST_VERSION ]] && [[ "$CAPA_PREVIOUS_VERSION" != "$CAPA_LATEST_VERSION" ]]; then
    pushd "$BASE_DIR" >/dev/null 2>&1
    curl -fsSL -o ./capa.zip "https://github.com/fireeye/capa/releases/download/${CAPA_LATEST_VERSION}/capa-${CAPA_LATEST_VERSION}-linux.zip"
    unzip ./capa.zip
    chmod 755 ./capa
    mkdir -p "$(dirname "$CAPA")"
    rm -f "$CAPA".old 2>/dev/null || true
    mv -f "$CAPA" "$CAPA".old 2>/dev/null || true
    mv -f ./capa "$CAPA"
    popd >/dev/null 2>&1
  fi
else
  exit 1
fi
