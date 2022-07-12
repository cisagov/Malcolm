#!/bin/bash

set -euo pipefail

# 1. df
# 1-1. --exclude-type=tmpfs --exclude-type=devtmpfs - exclude "tmpfs" and "devtmpfs" filesystems
# 1-2. --block-size=1                               - get byte sizes (not blocks)
# 1-3. --local                                      - only show local filesystems
# 1-4. --no-sync                                    - don't perform sync operation before getting results
# 1-5. --output=target,size,used,avail              - select mountpoint, total size, used size, available size
# 2. pipe through JQ (-R (read raw strings), -c (compact), -M (no colors), -s (slurp))
# 2-1. create hash with 'df' hash object and 'details' array sub-object
# 2-2. split df output on newlines
# 2-3. for each mountpoint (beginning with '/'), split on whitespace and assign to keys

df --exclude-type=tmpfs --exclude-type=devtmpfs --block-size=1 --local --no-sync --output=target,size,used,avail 2>/dev/null | \
  jq -R -c -M -s '
    {df: { details: [
      split("\n") |
      .[] |
      if test("^/") then
        gsub(" +"; " ") | split(" ") | {target: .[0], size: .[1]|tonumber, used: .[2]|tonumber, avail: .[3]|tonumber}
      else
        empty
      end
    ]}}'
