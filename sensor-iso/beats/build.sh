#!/bin/bash

# Copyright (c) 2018 Battelle Energy Alliance, LLC.  All rights reserved.

echo Target version: $BEATS_VERSION

BRANCH=$(echo $BEATS_VERSION | awk -F \. {'print $1 "." $2'})
echo Target branch: $BRANCH

if [ ! -d "$GOPATH/src/github.com/elastic/beats" ]; then go get -v github.com/elastic/beats; fi

cd $GOPATH/src/github.com/elastic/beats
git checkout $BRANCH

IFS=","
BEATS_ARRAY=($BEATS)

for BEAT in "${BEATS_ARRAY[@]}"
do

    if [[ -d "$GOPATH/src/github.com/elastic/beats/$BEAT" ]] ; then
      # an official beat
      cd "$GOPATH/src/github.com/elastic/beats/$BEAT"
      make
      cp "$BEAT" /build

      # package
      DOWNLOAD="$BEAT-$BEATS_VERSION-linux-x86.tar.gz"
      if [ ! -e $DOWNLOAD ]; then curl -s -O -J "https://artifacts.elastic.co/downloads/beats/$BEAT/$DOWNLOAD"; fi
      tar xf "$DOWNLOAD"

      cp "$BEAT" "$BEAT-$BEATS_VERSION-linux-x86"
      tar zcf "$BEAT-$BEATS_VERSION-linux-amd64.tar.gz" "$BEAT-$BEATS_VERSION-linux-x86"
      cp "$BEAT-$BEATS_VERSION-linux-amd64.tar.gz" /build

    elif [[ "$BEAT" =~ ^https*://(gogs\..*|github\.com) ]] ; then
      BRANCH=${THIRD_PARTY_BRANCH:-"master"}

      # clone from git manually rather than do a "go get"
      mkdir -p "$GOPATH/src/$(dirname "$(echo "$BEAT" | sed "s@^https*://@@")")"
      cd "$GOPATH/src/$(dirname "$(echo "$BEAT" | sed "s@^https*://@@")")"
      git clone --depth=1 --single-branch --branch "$BRANCH" "$BEAT"
      BEAT_EXE_NAME="$(basename "$BEAT" | sed "s/\.git$//")"
      cd "$BEAT_EXE_NAME"
      go get
      go install
      if [[ -f "$GOBIN/$BEAT_EXE_NAME" ]] ; then
        cp "$GOBIN/$BEAT_EXE_NAME" /build
        strip "/build/$BEAT_EXE_NAME"
      fi

    else
      # a community beat?
      if [[ "$BEAT" =~ gogs\..* ]]; then
        INSECURE_FLAG="--insecure"
      else
        INSECURE_FLAG=""
      fi
      go get $INSECURE_FLAG "$BEAT"
      BEAT_EXE_NAME="$(basename "$BEAT")"
      if [[ -f "$GOBIN/$BEAT_EXE_NAME" ]] ; then
        cp "$GOBIN/$BEAT_EXE_NAME" /build
        strip "/build/$BEAT_EXE_NAME"
      fi
    fi

    ls -lh /build

done
