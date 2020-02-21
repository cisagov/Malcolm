#!/bin/bash

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

OUTPUT_DIR="/tmp"
unset VERBOSE

while getopts o:v opts; do
   case ${opts} in
      o) OUTPUT_DIR=${OPTARG} ;;
      v) VERBOSE=1 ;;
   esac
done

set -e
if [[ -n $VERBOSE ]]; then
  set -x
fi

apt-get -y -q update

mkdir -p /tmp/vbox-guest-deb

cd /tmp/vbox-guest-deb

dget http://deb.debian.org/debian/pool/contrib/v/virtualbox/$(curl -fsL 'http://deb.debian.org/debian/pool/contrib/v/virtualbox/' | grep -P 'href="virtualbox_[^"]*?\.dsc' | tail -n 1 | grep -Po '"virtualbox_.+?"' | tr -d '"')

cd virtualbox*dfsg/

mkdir -p /usr/share/man/man1

mk-build-deps -t "apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends -y" -ir

VBOX_PKG_VERSION=$(export $(grep -P '^VBOX_VERSION_(MAJOR|MINOR|BUILD)' Version.kmk | tr -d ' ') && echo "$VBOX_VERSION_MAJOR.$VBOX_VERSION_MINOR.$VBOX_VERSION_BUILD")

DEBFULLNAME='Seth Grover' DEBEMAIL='malcolm.netsec@gmail.com' dch -bv $VBOX_PKG_VERSION-dfsg-2~~bpo10+1 --distribution buster-backports --force-distribution 'Unofficial backport'

dpkg-buildpackage -b

cd /tmp/vbox-guest-deb

ls -l *.deb && mv -v *.deb "$OUTPUT_DIR"/

cd /tmp

if [[ -n $VERBOSE ]]; then
  set +x
fi
set +e
