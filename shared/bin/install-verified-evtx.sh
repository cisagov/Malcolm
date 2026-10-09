#!/bin/sh
# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

# Install a pinned evtx_dump release only after verifying its SHA-256 digest.
set -eu

if [ "$#" -ne 4 ]; then
  echo "Usage: $0 <x86_64|aarch64> <sha256-manifest> <url> <destination>" >&2
  exit 2
fi

arch="$1"
manifest="$2"
url="$3"
destination="$4"

case "$arch" in
  x86_64|aarch64) ;;
  *)
    echo "Unsupported evtx_dump architecture: $arch" >&2
    exit 1
    ;;
esac

asset="evtx_dump-v0.12.3-${arch}-unknown-linux-gnu"
if [ ! -f "$manifest" ]; then
  echo "Missing evtx_dump checksum manifest: $manifest" >&2
  exit 1
fi

matches=0
expected=""
while read -r checksum filename _extra; do
  if [ "$filename" = "$asset" ]; then
    matches=$((matches + 1))
    expected="$checksum"
  fi
done < "$manifest"

case "$expected" in
  ""|*[!0123456789abcdefABCDEF]*)
    echo "Invalid or absent evtx_dump checksum for $asset" >&2
    exit 1
    ;;
esac
if [ "$matches" -ne 1 ] || [ "${#expected}" -ne 64 ]; then
  echo "Missing or duplicate evtx_dump checksum for $asset" >&2
  exit 1
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

curl -fsSL --retry 3 -o "$workdir/$asset" "$url"
(
  cd "$workdir"
  printf '%s  %s\n' "$expected" "$asset" | sha256sum -c -
)

# Do not replace an existing working executable until verification succeeds.
install -m 0755 "$workdir/$asset" "$destination"
