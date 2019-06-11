#!/bin/bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.


while true; do
  if [[ -e $MOLOCHDIR/configured && -f $MOLOCHDIR/initialized && "$CAPTURE" == "on" ]]; then
    echo "Launch capture..."
    $MOLOCHDIR/bin/moloch-capture
  fi
  sleep 5
done
