#!/bin/bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

lastmod(){
  expr $(date +%s) - $(stat -c %X "$1")
}

shopt -s nullglob

PCAP_ROTATE_MINUTES=${PCAP_ROTATE_MINUTES:-15}
PCAP_ROTATE_SECONDS=$(echo "$PCAP_ROTATE_MINUTES*60" | bc)

# we want to HUP any netsniff-ng process that has been writing to the
# same file for >= PCAP_ROTATE_SECONDS. netsniff-ng itself takes care
# of rolling the file based on filesize, this way we won't interfere
# with that because we'll be looking at the actual file time itself

while true; do
  sleep 5

  NETSNIFF_PIDS=$(pidof netsniff-ng)
  for NETSNIFF_PID in $NETSNIFF_PIDS; do

    unset OUTPUT_DIR
    unset PCAP_PREFIX

    # see what arguments this netsniff-ng was started with
    NETSNIFF_ARGS=($(cat /proc/$NETSNIFF_PID/cmdline | tr '\000' ' ' | python -c 'import shlex; print shlex.split(None)' | tr -d '[],'))
    NETSNIFF_ARGS_LEN=${#NETSNIFF_ARGS[@]}

    # extract the --out directory and --prefix prefix for the file(s) being written to by this netsniff-ng
    # (we would just use /proc/$NETSNIFF_PID/fd/ but in docker we can't resolve the symlink)
    CURR_IDX=0
    for ARG in ${NETSNIFF_ARGS[@]}; do
      if (( CURR_IDX > 0 )) && (( CURR_IDX < NETSNIFF_ARGS_LEN - 1 )); then
        if [[ "$ARG" = "'-o'" ]] || [[ "$ARG" = "'--out'" ]]; then
          OUTPUT_DIR=$(sed -e "s/^'//" -e "s/'$//" <<< "${NETSNIFF_ARGS[(( CURR_IDX + 1 ))]}")
        elif [[ "$ARG" = "'-P'" ]] || [[ "$ARG" = "'--prefix'" ]]; then
          PCAP_PREFIX=$(sed -e "s/^'//" -e "s/'$//" <<< "${NETSNIFF_ARGS[(( CURR_IDX + 1 ))]}")
        fi
      fi
      CURR_IDX=$((CURR_IDX+1))
    done

    if [[ -n $OUTPUT_DIR ]] && [[ -n $PCAP_PREFIX ]]; then
      # for the file(s) being written to by this netsniff-ng, if the creation time (okay,
      # access time, but nobody's "accessed" it since it was created) is longer ago than
      # PCAP_ROTATE_SECONDS then we're gonna HUP it
      NEEDS_HUP=0
      MAX_SEC_SINCE_MOD=0
      for PCAP_FILE in "$OUTPUT_DIR/$PCAP_PREFIX"*; do
        SEC_SINCE_MOD=$(lastmod "$PCAP_FILE")
        if (( $SEC_SINCE_MOD >= $PCAP_ROTATE_SECONDS )); then
          NEEDS_HUP=$((NEEDS_HUP+1))
          (( $SEC_SINCE_MOD > $MAX_SEC_SINCE_MOD )) && MAX_SEC_SINCE_MOD=$SEC_SINCE_MOD
        fi
      done
      if (( $NEEDS_HUP > 0 )); then
        kill -s HUP $NETSNIFF_PID && echo "Rolling netsniff-ng ($PCAP_PREFIX...) at $MAX_SEC_SINCE_MOD"
      fi
    fi # $OUTPUT_DIR and $PCAP_PREFIX

  done # for NETSNIFF_PID in $NETSNIFF_PIDS

done # while true
