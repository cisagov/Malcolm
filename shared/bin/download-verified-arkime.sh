#!/bin/sh
# Copyright (c) 2026 Battelle Energy Alliance, LLC. All rights reserved.

# Download the paired Arkime package and JA4 plugin; publish neither until both verify.
set -eu

if [ "$#" -ne 4 ]; then
  echo "Usage: $0 VERSION ARCH OUTPUT_DIRECTORY CHECKSUM_FILE" >&2
  exit 1
fi
VERSION="$1"
ARCH="$2"
OUTPUT_DIR="$3"
CHECKSUM_FILE="$4"
case "$ARCH" in
  amd64|arm64) ;;
  *) echo "Unsupported Arkime architecture: $ARCH" >&2; exit 1 ;;
esac
case "$VERSION" in
  ''|*[!0-9A-Za-z._-]*) echo "Invalid Arkime version: $VERSION" >&2; exit 1 ;;
esac
[ -r "$CHECKSUM_FILE" ] || { echo "Cannot read Arkime checksums: $CHECKSUM_FILE" >&2; exit 1; }

PACKAGE="arkime_${VERSION}-1.debian13_${ARCH}.deb"
PLUGIN="ja4plus.${ARCH}.so"
mkdir -p -- "$OUTPUT_DIR"
DOWNLOAD_DIR="$(mktemp -d "$OUTPUT_DIR/.arkime-download.XXXXXX")"
trap 'rm -rf -- "$DOWNLOAD_DIR"' 0
trap 'exit 1' HUP INT TERM

for ARTIFACT in "$PACKAGE" "$PLUGIN"; do
  EXPECTED="$(awk -v name="$ARTIFACT" '$2 == name { print $1 }' "$CHECKSUM_FILE")"
  case "$EXPECTED" in
    ''|*[!0-9a-fA-F]*) echo "Missing or invalid checksum for $ARTIFACT" >&2; exit 1 ;;
  esac
  if [ "${#EXPECTED}" -ne 64 ]; then
    echo "Missing or ambiguous checksum for $ARTIFACT" >&2
    exit 1
  fi
  curl -fsSL --retry 3 -o "$DOWNLOAD_DIR/$ARTIFACT" \
    "https://github.com/arkime/arkime/releases/download/v${VERSION}/${ARTIFACT}"
  (
    cd -- "$DOWNLOAD_DIR"
    printf '%s  %s\n' "$EXPECTED" "$ARTIFACT" | sha256sum -c -
  )
done

# The caller can install the package only after the entire pair has passed verification.
mv -- "$DOWNLOAD_DIR/$PACKAGE" "$OUTPUT_DIR/$PACKAGE"
mv -- "$DOWNLOAD_DIR/$PLUGIN" "$OUTPUT_DIR/$PLUGIN"
