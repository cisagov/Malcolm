#!/bin/sh
# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

# Install Tini only after verifying its versioned upstream checksum.
set -eu

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <amd64|arm64> <checksum-manifest> <destination>" >&2
  exit 2
fi

arch="$1"
manifest="$2"
destination="$3"

case "$arch" in
  amd64|arm64) ;;
  *) echo "Unsupported Tini architecture: $arch" >&2; exit 1 ;;
esac

asset="tini-$arch"
if [ ! -f "$manifest" ]; then
  echo "Missing Tini checksum manifest: $manifest" >&2
  exit 1
fi

expected=""
matches=0
while read -r digest filename rest; do
  if [ "$filename" = "$asset" ]; then
    expected="$digest"
    matches=$((matches + 1))
  fi
done < "$manifest"
if [ "$matches" -ne 1 ]; then
  echo "Missing or duplicate checksum for $asset" >&2
  exit 1
fi
case "$expected" in
  ""|*[!0123456789abcdefABCDEF]*)
    echo "Missing, duplicate or invalid Tini checksum for $asset" >&2
    exit 1
    ;;
esac
if [ "${#expected}" -ne 64 ]; then
  echo "Invalid Tini checksum length for $asset" >&2
  exit 1
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

base_url="${TINI_URL:-https://github.com/krallin/tini/releases/download/v0.19.0/tini}"
curl -fsSL --retry 3 -o "$workdir/$asset" "${base_url}-$arch"
(
  cd "$workdir"
  printf '%s  %s\n' "$expected" "$asset" | sha256sum -c -
)

# Preserve the installed executable if download or verification fails.
install -m 0755 "$workdir/$asset" "$destination"
