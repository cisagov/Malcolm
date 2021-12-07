#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.


while true; do
  if [[ ("$WISE" == "on") && (-f /var/run/arkime/runwise) && (-f $ARKIMEDIR/etc/wise.ini) ]]; then
    echo "Launch wise..."
    pushd $ARKIMEDIR/wiseService >/dev/null 2>&1
    $ARKIMEDIR/bin/node wiseService.js -c $ARKIMEDIR/etc/wise.ini
    popd >/dev/null 2>&1
  fi
  sleep 5
done
