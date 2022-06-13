#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

VERSION="7.10.2"
THIRD_PARTY_BRANCH="master"
while getopts b:v:t: opts; do
   case ${opts} in
      b) BEAT=${OPTARG} ;;
      v) VERSION=${OPTARG} ;;
      t) THIRD_PARTY_BRANCH=${OPTARG} ;;
   esac
done

if [[ -z $BEAT || -z $VERSION || -z $THIRD_PARTY_BRANCH ]] ; then
  echo "usage:" >&2
  echo "  beat-build.sh -b <BEAT> [-v <BEAT_VERSION>] [-v <THIRD_PARTY_BEAT_BRANCH>]" >&2
  echo "" >&2
  echo "example:" >&2
  echo "  beat-build.sh -b filebeat -v $VERSION" >&2
  exit 1
fi

BEAT_DIR="$(pwd)/$(echo "$BEAT" | sed "s@^https*://@@" | sed 's@/@_@g')"
mkdir -p "$BEAT_DIR"
docker run --rm -v "$BEAT_DIR":/build -e "BEATS_VERSION=$VERSION" -e "THIRD_PARTY_BRANCH=$THIRD_PARTY_BRANCH" -e "BEATS=$BEAT" beats-build:latest
