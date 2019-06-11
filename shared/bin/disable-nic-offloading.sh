#!/bin/bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

if [[ -n "$1" ]]; then
  for OPT in rx tx sg tso ufo gso gro lro ; do
    /sbin/ethtool -K "$1" $OPT off
  done
fi
