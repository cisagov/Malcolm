#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.


while true; do
  if [[ -f /var/run/arkime/initialized && "$VIEWER" == "on" ]]; then
    echo "Launch viewer..."
    cd $ARKIME_DIR/viewer
    $ARKIME_DIR/bin/node viewer.js --insecure -c $ARKIME_DIR/etc/config.ini | tee -a $ARKIME_DIR/logs/viewer.log 2>&1
  fi
  sleep 5
done
