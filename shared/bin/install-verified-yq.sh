#!/bin/sh

# Install a pinned yq release only after checking the locally maintained
# SHA-256 manifest. Do not obtain checksums from the artifact's download site
# during the container build.
set -eu

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <destination> <versioned-yq-url-prefix> <checksum-manifest>" >&2
    exit 2
fi

destination=$1
url_prefix=$2
manifest=$3

case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *)
        echo "Unsupported yq download architecture" >&2
        exit 1
        ;;
esac

checksum=$(awk -v name="yq_linux_$arch" '$2 == name {print $1}' "$manifest")
if [ "${#checksum}" -ne 64 ]; then
    echo "Missing or invalid expected SHA-256 for yq_linux_$arch" >&2
    exit 1
fi

download=$(mktemp)
trap 'rm -f "$download"' 0
trap 'exit 1' 1 2 3 15

# Download to a temporary location; never replace the existing executable on
# a failed download or checksum mismatch.
curl -fsSL -o "$download" "${url_prefix}${arch}"
printf '%s  %s\n' "$checksum" "$download" | sha256sum -c -
install -m 0755 "$download" "$destination"
