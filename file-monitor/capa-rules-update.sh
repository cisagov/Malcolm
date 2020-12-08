#!/usr/bin/env bash

set -e
set -u
set -o pipefail

ENCODING="utf-8"

[[ "${EXTRACTED_FILE_UPDATE_RULES:-"false"}" == "true" ]] || exit 0

BASE_URL=${CAPA_URL:-"https://github.com/fireeye/capa"}
RULE_URL=${CAPA_RULES_URL:-"https://github.com/fireeye/capa-rules"}
RULES_DIR=${CAPA_RULES_DIR:-"/capa-rules"}
CAPA=${CAPA_BIN:-"/usr/local/bin/capa"}

BASE_DIR="$(mktemp -d -t capa-base-XXXXXX)"

function finish {
  rm -rf "$BASE_DIR"
}

if type git >/dev/null 2>&1 && [[ -f "$CAPA" ]] && [[ -d "$RULES_DIR" ]]; then
  trap finish EXIT
  CAPA_RELEASE="v$("$CAPA" --version 2>&1 | awk '{print $2}')"
  git clone --depth 1 --single-branch --branch "$CAPA_RELEASE" "$BASE_URL" "$BASE_DIR"/capa
  pushd "$BASE_DIR"/capa >/dev/null 2>&1
  git submodule init rules
  CAPA_RULE_RELEASE="$(git rev-parse @:./rules)"
  popd >/dev/null 2>&1
  if [[ -n $CAPA_RULE_RELEASE ]]; then
    pushd "$RULES_DIR" >/dev/null 2>&1
    CAPA_RULE_CURRENT_RELEASE="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
    if [[ "$CAPA_RULE_CURRENT_RELEASE" != "$CAPA_RULE_RELEASE" ]]; then
      rm -rf ./*
      git init
      git remote add origin "$RULE_URL"
      git fetch --depth 1 origin "$CAPA_RULE_RELEASE"
      git reset --hard FETCH_HEAD
    else
      echo "capa-rules is up-to-date"
    fi
    popd >/dev/null 2>&1
  else
    exit 1
  fi
else
  exit 1
fi
