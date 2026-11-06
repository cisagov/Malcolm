#!/bin/sh
# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

# Publish Arkime's MaxMind databases into the shared Logstash read-only volume.
# A temporary file and rename ensure readers never see partially copied MMDBs.
set -eu

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <arkime-etc-directory> <shared-geoip-directory>" >&2
  exit 2
fi

source_dir="$1"
shared_dir="$2"

if [ ! -d "$shared_dir" ]; then
  echo "GeoIP shared directory does not exist: $shared_dir" >&2
  exit 1
fi

for edition in ASN City Country; do
  filename="GeoLite2-${edition}.mmdb"
  original="$source_dir/$filename"
  if [ ! -s "$original" ]; then
    continue
  fi

  staging="$(mktemp "$shared_dir/.$filename.XXXXXXXX")"
  if cp "$original" "$staging" &&
     chmod 644 "$staging" &&
     mv -f "$staging" "$shared_dir/$filename"; then
    :
  else
    rm -f "$staging"
    echo "Unable to publish $filename to shared GeoIP directory" >&2
    exit 1
  fi
done
