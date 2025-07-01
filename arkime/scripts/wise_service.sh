#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

while true; do
  if [[ (("$WISE" == "on") || ("$ARKIME_LIVE_CAPTURE" == "true")) && (-f /var/run/arkime/runwise) && (-f $ARKIME_DIR/wiseini/wise.ini) ]]; then
    echo "Launch wise..."
    rm -f $ARKIME_DIR/logs/wise*
    pushd $ARKIME_DIR/wiseService >/dev/null 2>&1
    $ARKIME_DIR/bin/node wiseService.js --insecure -c $ARKIME_DIR/wiseini/wise.ini
    popd >/dev/null 2>&1
  fi
  sleep 5
done
