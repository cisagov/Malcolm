#!/bin/sh
# Verify a versioned release asset against Malcolm's repo-managed manifest.
# The URL and manifest key accept a {arch} placeholder for Linux amd64/arm64.
set -eu

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <destination> <download-url> <artifact-name>" >&2
    exit 2
fi

destination=$1
url_template=$2
artifact_template=$3

case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo "Unsupported binary architecture" >&2; exit 1 ;;
esac

url=$(printf '%s' "$url_template" | sed "s/{arch}/$arch/g")
artifact=$(printf '%s' "$artifact_template" | sed "s/{arch}/$arch/g")
manifest=${VERIFIED_BINARY_MANIFEST:-/usr/local/share/binaries.sha256}

case "$url" in
    https://*) ;;
    *) echo "Expected an HTTPS binary download URL" >&2; exit 1 ;;
esac
case "$artifact" in
    ''|*[!a-zA-Z0-9._+-]*) echo "Invalid artifact name" >&2; exit 1 ;;
esac
if [ ! -r "$manifest" ]; then
    echo "Binary checksum manifest not found: $manifest" >&2
    exit 1
fi

# A duplicate key yields a multiline string and therefore also fails closed.
expected=$(awk -v target="$artifact" '$2 == target {print $1}' "$manifest")
if [ "${#expected}" -ne 64 ]; then
    echo "Missing or duplicate SHA-256 for $artifact" >&2
    exit 1
fi
case "$expected" in
    *[!0123456789abcdefABCDEF]*) echo "Invalid SHA-256 for $artifact" >&2; exit 1 ;;
esac

download=$(mktemp)
trap 'rm -f "$download"' 0
trap 'exit 1' 1 2 3 15

# Never install a binary before the entire downloaded file verifies.
curl -fsSL --retry 3 -o "$download" "$url"
printf '%s  %s\n' "$expected" "$download" | sha256sum -c -
install -m 0755 "$download" "$destination"
