#!/bin/sh
# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.
#
# Fallback yq for the documentation build: pin the release and verify SHA256.
# The optional manifest and base URL arguments support offline test fixtures.
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
  echo "Usage: $0 <destination> [manifest] [release-download-base-url]" >&2
  exit 2
fi

destination="$1"
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
manifest="${2:-$script_dir/checksums/yq-v4.54.1.sha256}"
release_url="${3:-https://github.com/mikefarah/yq/releases/download/v4.54.1}"

case "$(uname -s)" in
  Linux) platform=linux ;;
  Darwin) platform=darwin ;;
  *) echo "Unsupported yq platform" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "Unsupported yq CPU architecture" >&2; exit 1 ;;
esac

asset="yq_${platform}_${arch}"
if [ ! -f "$manifest" ]; then
  echo "Missing yq checksum manifest: $manifest" >&2
  exit 1
fi

matches=0
expected=""
while read -r digest name _extra; do
  if [ "$name" = "$asset" ]; then
    expected="$digest"
    matches=$((matches + 1))
  fi
done < "$manifest"

case "$expected" in
  ""|*[!0123456789abcdefABCDEF]*)
    echo "Invalid or absent yq checksum for $asset" >&2
    exit 1
    ;;
esac
if [ "$matches" -ne 1 ] || [ "${#expected}" -ne 64 ]; then
  echo "Duplicate or malformed yq checksum for $asset" >&2
  exit 1
fi

mkdir -p "$(dirname -- "$destination")"
temporary="$(mktemp "${destination}.tmp.XXXXXXXX")"
trap 'rm -f "$temporary"' EXIT HUP INT TERM

curl -fsSL --retry 3 -o "$temporary" "${release_url%/}/$asset"

if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$temporary" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$temporary" | awk '{print $1}')"
else
  echo "Cannot verify yq: neither sha256sum nor shasum is installed" >&2
  exit 1
fi

if [ "$actual" != "$expected" ]; then
  echo "SHA256 verification failed for $asset" >&2
  exit 1
fi

chmod 755 "$temporary"
mv -f "$temporary" "$destination"
echo "Verified and installed $asset" >&2
