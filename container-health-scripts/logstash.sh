#!/usr/bin/env bash

set -euo pipefail

STRICT=0
while getopts 'vs' OPTION; do
  case "$OPTION" in
    v)
      set -x
      ;;

    s)
      STRICT=1
      ;;

    ?)
      echo "script usage: $(basename $0) [-v (verbose)] [-s (strict)]" >&2
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"

if [[ $STRICT == 1 ]]; then
    JQ_EVAL=$(
        curl --fail --silent -XGET http://localhost:9600/_health_report | \
            jq '(.status | test("green|yellow")) and
                (.indicators.pipelines.status | test("green|yellow")) and
                (all(.indicators.pipelines.indicators[]; .status | test("green|yellow")))' 2>/dev/null
    )
    [[ "$JQ_EVAL" == "true" ]] && exit 0 && exit 1
else
    curl --fail --silent --output /dev/null -XGET http://localhost:9600/_health_report
fi


