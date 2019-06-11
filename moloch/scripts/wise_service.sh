#!/bin/bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.


while true; do
  if [[ ("$WISE" == "on") && (-f $MOLOCHDIR/runwise) && (-f $MOLOCHDIR/etc/wise.ini) ]]; then
    echo "Launch wise..."
    pushd $MOLOCHDIR/wiseService >/dev/null 2>&1
    $MOLOCHDIR/bin/node wiseService.js -c $MOLOCHDIR/etc/wise.ini
    popd >/dev/null 2>&1
  fi
  sleep 5
done
