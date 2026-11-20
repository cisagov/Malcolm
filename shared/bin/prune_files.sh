#!/usr/bin/env bash

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

function UsagePercentagePwd {
  df -k . 2>/dev/null | awk '{gsub("%",""); capacity=$5}; END {print capacity}'
}

function UsageBytesPwd {
  du -sb . 2>/dev/null | awk '{print $1}'
}

# recursion depth (1 = not recursive)
DEPTH=1

# THRESHOLD_PCT and MAXSIZE_BYTES define pruning triggers; either or both may trigger pruning.
#   A value of 0 means that trigger is unused
#   If either trigger condition matches, the script will prune until disk usage drops **below** the thresholds

# THRESHOLD_PCT is an integer percentage between 1-100 ("prune when disk usage >= THRESHOLD_PCT%")
THRESHOLD_PCT=0
# MAXSIZE_GB is an integer representing gigabytes ("prune when path contents >= MAXSIZE_GB"), although
#   it can be specified as a human-readable data size (e.g., 10G) if humanfriendly is available
MAXSIZE_GB=0
MAXSIZE_BYTES=0

# if specified, this script will check and prune every $INTERVAL seconds
INTERVAL=0 # defaults to "run once then exit"

VERBOSE=0 # defaults to "not verbose"
while getopts i:m:p:rt:v opts; do
   case ${opts} in
      i) INTERVAL=${OPTARG} ;;
      m) MAXSIZE_GB=${OPTARG} ;;
      p) PRUNE_PATH=${OPTARG} ;;
      r) DEPTH=999 ;;
      t) THRESHOLD_PCT="${OPTARG//%}" ;;
      v) VERBOSE=1 ;;
   esac
done

INT_RE='^[0-9]+$'

if [[ -z "$PRUNE_PATH" ]] || [[ ! -e "$PRUNE_PATH" ]] || ! pushd >/dev/null 2>&1 "$PRUNE_PATH" ; then
  echo "Please specify prune path with -p" >&2
  exit 1
fi

if [[ ! "$INTERVAL" =~ $INT_RE ]] || ! (( "$INTERVAL" >= 0 && "$INTERVAL" <= 86400 )) ; then
  echo "Please specify prune check interval (seconds, 0-86400) with -i (0 = run once)" >&2
  exit 1
fi

# Integer -m values are decimal gigabytes. Human-readable values are parsed
# directly to bytes, without rounding either the limit or current usage.
if [[ "$MAXSIZE_GB" =~ $INT_RE ]]; then
  MAXSIZE_BYTES="${MAXSIZE_GB}000000000"
elif command -v humanfriendly >/dev/null 2>&1; then
  MAXSIZE_BYTES="$(humanfriendly --parse-size "$MAXSIZE_GB" 2>/dev/null)"
fi
if [[ "$MAXSIZE_BYTES" =~ ^0*([1-9][0-9]*|0)$ ]]; then
  # Normalize leading zeroes and reject overflow before Bash arithmetic can
  # turn an oversized limit into a smaller, destructive pruning threshold.
  MAXSIZE_BYTES="${BASH_REMATCH[1]}"
  # Equal-length decimal strings must be compared without converting to integers.
  # shellcheck disable=SC2071
  if (( ${#MAXSIZE_BYTES} > 19 )) ||
     { (( ${#MAXSIZE_BYTES} == 19 )) && [[ "$MAXSIZE_BYTES" > "9223372036854775807" ]]; }; then
    echo "Maxsize exceeds the supported byte range" >&2
    exit 1
  fi
else
  MAXSIZE_BYTES=0
fi

if ( [[ -z "$THRESHOLD_PCT" ]] || [[ ! "$THRESHOLD_PCT" =~ $INT_RE ]] || ! (( "$THRESHOLD_PCT" >= 1 && "$THRESHOLD_PCT" <= 100)) ) &&
   ( [[ -z "$MAXSIZE_BYTES" ]] || ! (( "$MAXSIZE_BYTES" >= 1 )) ); then
  echo "No prune trigger specified (threshold -t or maxsize -m); running in no-op mode." >&2
  THRESHOLD_PCT=0
  MAXSIZE_BYTES=0
fi

while true ; do

  if (( THRESHOLD_PCT > 0 )) || (( MAXSIZE_BYTES > 0 )) || [[ "$VERBOSE" == "1" ]]; then
    # check initial disk capacity
    USAGE_PCT=$(UsagePercentagePwd)
    USAGE_BYTES=$(UsageBytesPwd)
  fi

  if ( (( $THRESHOLD_PCT > 0 )) && (( $USAGE_PCT >= $THRESHOLD_PCT )) ) || ( (( $MAXSIZE_BYTES > 0 )) && (( $USAGE_BYTES >= $MAXSIZE_BYTES )) ); then

    # we have exceeded the threshold, see if there is something to prune
    [[ "$VERBOSE" == "1" ]] && echo "\"$PRUNE_PATH\" is at $USAGE_PCT% of capacity ($USAGE_BYTES bytes), pruning..." >&2

    # read files by modification time, oldest first, deleting until we've dropped below the threshold
    DELETED_FILES=0
    DELETED_BYTES=0
    while IFS='' read -r -d ' ' FILE_TIME && IFS='' read -r -d ' ' FILE_SIZE && IFS='' read -r -d '' FILE_TO_DELETE; do

      FILE_SIZE_HUMAN=$(numfmt --to=iec-i --suffix=B $FILE_SIZE)
      FILE_TIME_HUMAN=$(date -u -d @$FILE_TIME)

      if [[ -f "$FILE_TO_DELETE" ]]; then
        if rm -f "$FILE_TO_DELETE" ; then
          DELETED_FILES=$((DELETED_FILES+1))
          DELETED_BYTES=$((DELETED_BYTES+FILE_SIZE))

          [[ "$VERBOSE" == "1" ]] && echo "Pruned \"$FILE_TO_DELETE\" ($FILE_SIZE_HUMAN, $FILE_TIME_HUMAN)" >&2

          # re-check disk capacity
          USAGE_PCT=$(UsagePercentagePwd)
          if ( (( THRESHOLD_PCT > 0 )) && (( USAGE_PCT >= THRESHOLD_PCT )) ) ; then
            # we still exceed the percent threshold, continue to loop
            [[ "$VERBOSE" == "1" ]] && echo "\"$PRUNE_PATH\" is at $USAGE_PCT% of capacity, pruning..." >&2
            exceeds_pct=true
          else
            # we're below the percent limit, now check the byte limit.
            [[ "$VERBOSE" == "1" ]] && echo "\"$PRUNE_PATH\" is at $USAGE_PCT% of capacity" >&2
            exceeds_pct=false
          fi

          if ! $exceeds_pct; then
              # Perform this expensive check only if needed.
              USAGE_BYTES=$(UsageBytesPwd)
              if ( (( MAXSIZE_BYTES > 0 )) && (( USAGE_BYTES >= MAXSIZE_BYTES )) ); then
                # we still exceed the threshold, continue to loop
                [[ "$VERBOSE" == "1" ]] && echo "\"$PRUNE_PATH\" is at $USAGE_PCT% of capacity ($USAGE_BYTES bytes), pruning..." >&2
              else
                # we're below the byte limit as well, break
                [[ "$VERBOSE" == "1" ]] && echo "\"$PRUNE_PATH\" is at $USAGE_PCT% of capacity ($USAGE_BYTES bytes)" >&2
                break
              fi
          fi

        fi # file was rm'ed
      fi # file exists
                                                                                               # exclude files in our Zeek live capture directory
    done < <(find . -xdev -mindepth 1 -maxdepth $DEPTH -ignore_readdir_race -type f \( ! -path '*/spool/*' -o -path '*/spool/tmp*' \) -printf '%T@ %s %p\0' 2>/dev/null | sort -zn 2>/dev/null)

    if (( $DELETED_FILES > 0 )) ; then
      echo "Pruned $DELETED_FILES files ($(numfmt --to=iec-i --suffix=B $DELETED_BYTES)) in \"$PRUNE_PATH\""
    else
      [[ "$VERBOSE" == "1" ]] && echo "Nothing was pruned in \"$PRUNE_PATH\"!" >&2
    fi

  else
    [[ "$VERBOSE" == "1" ]] && echo "\"$PRUNE_PATH\" is at $USAGE_PCT% of capacity ($USAGE_BYTES bytes)" >&2
  fi

  if (( $INTERVAL > 0 )) ; then
    for i in $(seq 1 $INTERVAL); do sleep 1; done
  else
    break
  fi

done

popd >/dev/null 2>&1
