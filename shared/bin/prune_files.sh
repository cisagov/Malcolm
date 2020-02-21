#!/bin/bash

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

# recursion depth (1 = not recursive)
DEPTH=1

# threshold is an integer percentage between 1-100; the script will prune until disk usage drops below the threshold
THRESHOLD=90 # defaults to "prune when usage >= 90%";

# if specified, this script will check and prune every $INTERVAL seconds
INTERVAL=0 # defaults to "run once then exit"

VERBOSE=0 # defaults to "not verbose"

while getopts t:p:i:rv opts; do
   case ${opts} in
      p) PRUNE_PATH=${OPTARG} ;;
      t) THRESHOLD=${OPTARG} ;;
      i) INTERVAL=${OPTARG} ;;
      r) DEPTH=999 ;;
      v) VERBOSE=1 ;;
   esac
done

INT_RE='^[0-9]+$'

if [ -z $PRUNE_PATH ] || [ ! -e "$PRUNE_PATH" ] || ! pushd >/dev/null 2>&1 $PRUNE_PATH ; then
  echo "Please specify prune path with -p"
  exit 1
fi

if [ -z $THRESHOLD ] || [[ ! "$THRESHOLD" =~ $INT_RE ]] || ! [ "$THRESHOLD" -ge 1 -a "$THRESHOLD" -le 100 ] ; then
  echo "Please specify prune threshold (percentage, 1-100) with -t"
  exit 1
fi

if [[ ! "$INTERVAL" =~ $INT_RE ]] || ! [ "$INTERVAL" -ge 0 -a "$INTERVAL" -le 86400 ] ; then
  echo "Please specify prune check interval (seconds, 0-86400) with -i (0 = run once)"
  exit 1
fi

while true ; do

  # check initial disk capacity
  USAGE=$(df -k . | awk '{gsub("%",""); capacity=$5}; END {print capacity}')
  if [ $USAGE -gt $THRESHOLD ] ; then

    # we have exceeded the threshold, see if there is something to prune
    [[ "$VERBOSE" == "1" ]] && echo "\"$PRUNE_PATH\" is at $USAGE% of capacity, pruning..."

    # read files by modification time, oldest first, deleting until we've dropped below the threshold
    DELETED=0
    while IFS='' read -r -d ' ' FILE_TIME && IFS='' read -r -d ' ' FILE_SIZE && IFS='' read -r -d '' FILE_TO_DELETE; do

      FILE_SIZE_HUMAN=$(numfmt --to=iec-i --suffix=B $FILE_SIZE)
      FILE_TIME_HUMAN=$(date -u -d @$FILE_TIME)

      if [ -f "$FILE_TO_DELETE" ]; then
        if rm -f "$FILE_TO_DELETE" ; then
          DELETED=$((DELETED+1))

          echo "Pruned \"$FILE_TO_DELETE\" ($FILE_SIZE_HUMAN, $FILE_TIME_HUMAN)"

          # re-check disk capacity
          USAGE=$(df -k . | awk '{gsub("%",""); capacity=$5}; END {print capacity}')
          if [ $USAGE -gt $THRESHOLD ] ; then
            # we still exceed the threshold, continue to loop
            [[ "$VERBOSE" == "1" ]] && echo "\"$PRUNE_PATH\" is at $USAGE% of capacity, pruning..."
          else
            # we're below the limit, break
            [[ "$VERBOSE" == "1" ]] && echo "\"$PRUNE_PATH\" is at $USAGE% of capacity"
            break
          fi

        fi # file was rm'ed
      fi # file exists

    done < <(find . -xdev -mindepth 1 -maxdepth $DEPTH -ignore_readdir_race -type f \( ! -path '*/spool/*' -o -path '*/spool/tmp*' \) -printf '%T@ %s %p\0' 2>/dev/null | sort -zn 2>/dev/null)

    if [ $DELETED -gt 0 ] ; then
      [[ "$VERBOSE" == "1" ]] && echo "Pruned $DELETED files in \"$PRUNE_PATH\""
    else
      echo "Nothing was pruned in \"$PRUNE_PATH\"!"
    fi

  else
    [[ "$VERBOSE" == "1" ]] && echo "\"$PRUNE_PATH\" is at $USAGE% of capacity"
  fi

  if [ $INTERVAL -gt 0 ] ; then
    sleep $INTERVAL
  else
    break
  fi

done

popd >/dev/null 2>&1
