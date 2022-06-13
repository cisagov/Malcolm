#!/bin/sh

df --exclude-type=tmpfs --exclude-type=devtmpfs --block-size=1 --local --no-sync --output=target,size,used,avail 2>/dev/null | \
  jq -R -c -M -s '
    {df: { details: [
      split("\n") |
      .[] |
      if test("^/") then
        gsub(" +"; " ") | split(" ") | {target: .[0], size: .[1], used: .[2], avail: .[3]}
      else
        empty
      end
    ]}}'
