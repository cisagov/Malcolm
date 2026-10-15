#!/bin/bash

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

if [ -z "$BASH_VERSION" ]; then
  echo "Wrong interpreter, please run \"$0\" with bash"
  exit 1
fi

ZEEK_DIR=${ZEEK_DIR:-/usr/local/zeek}

# Packages are installed at the commits pinned in zeek-packages.lock (generated from
#   zeek/zeek-packages.list by scripts/zeek_packages_lock_refresh.sh). git verifies each checkout
#   against its commit hash, so the build gets exactly the reviewed code.
ZEEK_PACKAGES_LOCK=${ZEEK_PACKAGES_LOCK:-/usr/local/share/zeek-packages.lock}

#
# zkg_install_pinned URL COMMIT ENV_LIST
#
# zkg install a package at a specific commit, with optional semicolon-separated environment
#   variables (e.g., CMAKE_BUILD_TYPE=Debug;HILTI_CXX_FLAGS=-fno-var-tracking-assignments)
function zkg_install_pinned() {
  local REPO_URL="$1" COMMIT="$2" ENV_LIST="$3"
  local ENVS=()
  [[ -n "$ENV_LIST" ]] && IFS=';' read -ra ENVS <<< "${ENV_LIST}"
  local EXTRA_ZKG_PARAMS=()
  if [[ "$REPO_URL" =~ "zeek-kafka" ]]; then
    EXTRA_ZKG_PARAMS+=( --user-var )
    EXTRA_ZKG_PARAMS+=( LIBRDKAFKA_ROOT=/usr/include/librdkafka )
  fi
  env "${ENVS[@]}" zkg install --nodeps --force --skiptests "${EXTRA_ZKG_PARAMS[@]}" --version "$COMMIT" "$REPO_URL"
}

#
# git_clone_pinned URL COMMIT DESTINATION
#
# check out a repository (and its submodules) at a specific commit, for packages zkg doesn't handle
function git_clone_pinned() {
  local REPO_URL="$1" COMMIT="$2" DEST="$3"
  mkdir -p "$DEST"
  git -C "$DEST" init -q
  git -C "$DEST" remote add origin "$REPO_URL"
  git -C "$DEST" fetch -q --depth 1 origin "$COMMIT"
  git -C "$DEST" checkout -q FETCH_HEAD
  git -C "$DEST" submodule update -q --init --recursive --depth 1
}

# don't consume as many resources when building spicy analyzers, even if it's slower.
# https://docs.zeek.org/projects/spicy/en/latest/toolchain.html
TOTAL_CPUS="$(nproc --all 2>/dev/null || echo '1')"
TOTAL_CPUS=$(( TOTAL_CPUS / 2 ))
(( $TOTAL_CPUS <= 0 )) && TOTAL_CPUS=1
export HILTI_JIT_PARALLELISM=${BUILD_JOBS:-$TOTAL_CPUS}

# TODO: some that might be worth looking at in the future:
# * ARP (off by default) https://packages.zeek.org/packages/view/593a976c-c3b1-11ed-9c2f-0a598146b5c6
# * Detect gateway IP: https://github.com/stratosphereips/zeek-package-log-gateway-IP
# * Different IRC detections: https://packages.zeek.org/packages/view/5943b1ed-c3b1-11ed-9c2f-0a598146b5c6

if [[ ! -r "$ZEEK_PACKAGES_LOCK" ]]; then
  echo "Zeek package lock file not found: $ZEEK_PACKAGES_LOCK" >&2
  exit 1
fi

# read the whole lock file first so nothing run during an install can consume its lines from stdin
mapfile -t LOCK_ENTRIES < <(grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$ZEEK_PACKAGES_LOCK")

for ENTRY in "${LOCK_ENTRIES[@]}"; do
  IFS='|' read -r REPO_URL COMMIT RESOLVED_REF ENV_LIST METHOD <<< "$ENTRY"
  if [[ -z "$REPO_URL" ]] || [[ ! "$COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
    echo "Invalid entry in $ZEEK_PACKAGES_LOCK: $ENTRY" >&2
    exit 1
  fi
  echo "Installing $REPO_URL at $COMMIT ($RESOLVED_REF)"
  case "$METHOD" in
    ""|zkg)
      zkg_install_pinned "$REPO_URL" "$COMMIT" "$ENV_LIST"
      ;;
    clone:*)
      git_clone_pinned "$REPO_URL" "$COMMIT" "${ZEEK_DIR}/${METHOD#clone:}"
      ;;
    *)
      echo "Unknown install method '$METHOD' for $REPO_URL" >&2
      exit 1
      ;;
  esac
done

find "${ZEEK_DIR}"/lib/zeek/plugins/packages -type f -name "*.hlto" -exec chmod 755 "{}" \;

# one-off packages from local build
if [[ -d "$ZEEK_DIR"/custom-pkg ]]; then
  while IFS= read -r -d '' PKGDIR; do
    pushd "$PKGDIR" >/dev/null 2>&1
    if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      git init
      git add .
      git config --global user.email "nobody@example.com"
      git config --global user.name "nobody"
      git commit -m "initial commit"
    fi
    zkg install --nodeps --force --skiptests .
    popd >/dev/null 2>&1
  done < <(find "$ZEEK_DIR"/custom-pkg -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)
fi