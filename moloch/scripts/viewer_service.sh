#!/bin/bash

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.


while true; do
  if [[ -e /var/run/moloch/configured && -f /var/run/moloch/initialized && "$VIEWER" == "on" ]]; then
    echo "Launch viewer..."
    cd $MOLOCHDIR/viewer
    $MOLOCHDIR/bin/node viewer.js -c $MOLOCHDIR/etc/config.ini | tee -a $MOLOCHDIR/logs/viewer.log 2>&1
  fi
  sleep 5
done
