#!/bin/bash

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.


while true; do
  if [[ -f /var/run/moloch/initialized && "$VIEWER" == "on" ]]; then
    echo "Launch viewer..."
    cd $ARKIMEDIR/viewer
    $ARKIMEDIR/bin/node viewer.js -c $ARKIMEDIR/etc/config.ini | tee -a $ARKIMEDIR/logs/viewer.log 2>&1
  fi
  sleep 5
done
