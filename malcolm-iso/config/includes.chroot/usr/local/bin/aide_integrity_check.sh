#!/bin/bash

set -euo pipefail

aide \
    --config=/etc/aide/aide.conf \
    --log-level=error \
    --after="report_format=json" \
    --check \
  | jq -c -M
