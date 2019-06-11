#!/bin/bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

set -e

if [[ -z "$EXT_USERNAME" ]] || [[ -z "$EXT_PASSWORD" ]]; then
  echo "Please set \$EXT_USERNAME and \$EXT_PASSWORD and re-run this script" >&2
  exit 1
fi

logstash-keystore create 2>/dev/null
echo -n -e "${EXT_USERNAME}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | logstash-keystore add ES_EXTERNAL_USER --stdin --force 2>/dev/null
echo -n -e "${EXT_PASSWORD}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | logstash-keystore add ES_EXTERNAL_PASSWORD --stdin --force 2>/dev/null
logstash-keystore list 2>/dev/null
