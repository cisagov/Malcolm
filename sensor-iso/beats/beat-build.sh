#!/bin/bash

# Copyright (c) 2018 Battelle Energy Alliance, LLC.  All rights reserved.

VERSION="7.5.0"
while getopts b:v: opts; do
   case ${opts} in
      b) BEAT=${OPTARG} ;;
      v) VERSION=${OPTARG} ;;
   esac
done

if [[ -z $BEAT || -z $VERSION ]] ; then
  echo "usage:" >&2
  echo "  beat-build.sh -b <BEAT> [-v <BEAT_VERSION]" >&2
  echo "" >&2
  echo "example:" >&2
  echo "  beat-build.sh -b metricbeat -v $VERSION" >&2
  exit 1
fi

BEAT_DIR="$(pwd)/$(echo "$BEAT" | sed "s@^https*://@@" | sed 's@/@_@g')"
mkdir -p "$BEAT_DIR"
docker run --rm -v "$BEAT_DIR":/build -e "BEATS-VERSION=$VERSION" -e "BEATS=$BEAT" beats-build:latest
