#!/usr/bin/env bash
# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

# Install Supercronic only after verifying an in-repository checksum.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <amd64|arm64> <checksum-file> <output-binary>" >&2
  exit 2
fi

arch="$1"
checksum_file="$2"
output_binary="$3"

case "$arch" in
  amd64|arm64) ;;
  *)
    echo "Unsupported Supercronic architecture: $arch" >&2
    exit 1
    ;;
esac

binary="supercronic-linux-${arch}"
if [[ ! -f "$checksum_file" ]]; then
  echo "Missing Supercronic checksum file: $checksum_file" >&2
  exit 1
fi

# Duplicate and missing entries fail validation before downloading.
expected="$(awk -v filename="$binary" '$2 == filename { print $1 }' "$checksum_file")"
if [[ ! "$expected" =~ ^[[:xdigit:]]{64}$ ]]; then
  echo "Missing, duplicate or invalid checksum for $binary" >&2
  exit 1
fi

version="${SUPERCRONIC_VERSION:-0.2.49}"
release_url="${SUPERCRONIC_URL:-https://github.com/aptible/supercronic/releases/download/v${version}/supercronic-linux-}"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

curl -fsSL --retry 3 -o "$workdir/$binary" "${release_url}${arch}"
(
  cd "$workdir"
  printf '%s  %s\n' "$expected" "$binary" | sha256sum -c -
)

# Do not overwrite an installed executable on failed download/verification.
install -m 0755 "$workdir/$binary" "$output_binary"
