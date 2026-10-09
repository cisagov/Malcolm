#!/bin/sh
# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

# Install a pinned Tini executable after validating its Linux SHA-256 digest.
# Used by the Filebeat, Logstash and OpenSearch runtime Docker images.
set -eu

if [ "$#" -ne 4 ]; then
  echo "Usage: $0 <amd64|arm64> <manifest> <url> <destination>" >&2
  exit 2
fi

architecture="$1"
manifest="$2"
url="$3"
destination="$4"

case "$architecture" in
  amd64|arm64) ;;
  *) echo "Unsupported Tini architecture: $architecture" >&2; exit 1 ;;
esac

asset="tini-$architecture"
if [ ! -f "$manifest" ]; then
  echo "Missing Tini checksum manifest: $manifest" >&2
  exit 1
fi

matches=0
expected=""
while read -r checksum filename extra; do
  if [ "$filename" = "$asset" ]; then
    matches=$((matches + 1))
    expected="$checksum"
    if [ -n "$extra" ]; then
      echo "Malformed Tini checksum entry for $asset" >&2
      exit 1
    fi
  fi
done < "$manifest"

case "$expected" in
  ""|*[!0123456789abcdefABCDEF]*)
    echo "Invalid or absent Tini checksum for $asset" >&2
    exit 1
    ;;
esac
if [ "$matches" -ne 1 ] || [ "${#expected}" -ne 64 ]; then
  echo "Missing, duplicated or malformed Tini checksum for $asset" >&2
  exit 1
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

curl -fsSL --retry 3 -o "$workdir/$asset" "$url"
(
  cd "$workdir"
  printf '%s  %s\n' "$expected" "$asset" | sha256sum -c -
)
# Do not modify the existing executable until the download is verified.
install -m 0755 "$workdir/$asset" "$destination"
