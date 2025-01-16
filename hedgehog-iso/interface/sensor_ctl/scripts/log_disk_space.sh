#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

SPACE_STRING="$(/bin/df -lh --output=source,target,avail,size,pcent | tail -n +2 | grep '^/dev' |  tr -s ' ' ',' | cut -d, -f2,3,4,5 | sed 's/^/\[/' | sed 's/$/\]/' | tr '\n' '.')"
logger "${SPACE_STRING}"
