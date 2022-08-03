#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

set -e

CONFIG_DIR="supervisor.d"
CONFIG_FILE="supervisord.conf"
CONTROL_VARS_FILE="control_vars.conf"
CAPTURE_GROUPS_FILE="capture-groups.conf"

function join_by { local IFS="$1"; shift; echo "$*"; }

# Create config files for each capture interface for the various capture programs (tcpdump, netsniff)
# so that supervisord can manage instances of each of these programs for each interface.
# zeek is now managed by zeekctl (via zeekdeploy.sh) rather than individually by supervisord so that
# we can use load balancing
function CreateCaptureConfigs() {

  declare -a CAPTURE_PROGS=("tcpdump" "netsniff")

  if [[ -d ./"$CONFIG_DIR" ]]; then
    rm -f ./"$CONFIG_DIR"/"$CAPTURE_GROUPS_FILE"

    for PROG in "${CAPTURE_PROGS[@]}"; do
      declare -a PROG_GROUP=()

      # remove any old .conf files for this capture program, we'll create them all fresh
      rm -f ./"$CONFIG_DIR"/$PROG*.conf
      if [[ -n $CAPTURE_INTERFACE ]]; then

        # for each capture interface, expand the capture program's template and substitute for the $IFACE variable
        for IFACE in ${CAPTURE_INTERFACE//,/ }; do
          if [[ -r ./"$CONFIG_DIR"/$PROG.template ]]; then

            # expand $IFACE into interface name in a new configuration file
            export $IFACE
            sed -e "s/[$]IFACE/${IFACE}/g" ./"$CONFIG_DIR"/$PROG.template > ./"$CONFIG_DIR"/$PROG-"$IFACE".conf

            # if there needs to be a working directory for supervisord to manage this program, create it now
            WORK_DIR=$(eval echo "$(grep ^directory= ./"$CONFIG_DIR"/$PROG-"$IFACE".conf | sed "s/^directory=//" | sed  "s/%(ENV_\(\w*\))s/$\1/")")
            mkdir -p "$WORK_DIR" 2>/dev/null || true

            # get new program name for group inclusion
            INSTANCE_NAME="$(grep '^\[program:' ./"$CONFIG_DIR"/$PROG-"$IFACE".conf | sed "s/^\[program://" | sed "s/\]$//")"
            PROG_GROUP+=($INSTANCE_NAME)

          fi # capture program template exists
        done # loop over capture interfaces

      fi # capture interface(s) defined

      if (( ${#PROG_GROUP[@]} )); then
        GROUP_PROGS="$(join_by , "${PROG_GROUP[@]}")"
        # define group config file
        echo "[group:$PROG]" >> ./"$CONFIG_DIR"/"$CAPTURE_GROUPS_FILE"
        echo "programs=$GROUP_PROGS" >> ./"$CONFIG_DIR"/"$CAPTURE_GROUPS_FILE"
        echo "" >> ./"$CONFIG_DIR"/"$CAPTURE_GROUPS_FILE"
      fi

    done # loop over capture programs
  fi # config dir exists
}

# force-navigate to script directory (containing config file)
[[ "$(uname -s)" = 'Darwin' ]] && REALPATH=grealpath || REALPATH=realpath
[[ "$(uname -s)" = 'Darwin' ]] && DIRNAME=gdirname || DIRNAME=dirname
if ! (type "$REALPATH" && type "$DIRNAME") > /dev/null; then
  echo "$(basename "${BASH_SOURCE[0]}") requires $REALPATH and $DIRNAME"
  exit 1
fi
# SUPERVISOR_PATH is exported to be referenced in supervisord.conf
export SUPERVISOR_PATH="$($DIRNAME $($REALPATH -e "${BASH_SOURCE[0]}"))"
pushd "$SUPERVISOR_PATH" >/dev/null 2>&1

source "$CONTROL_VARS_FILE"

CreateCaptureConfigs

mkdir -p "$SUPERVISOR_PATH/"{log,run}
rm -f "$SUPERVISOR_PATH/"/log/*

rm -rf /opt/sensor/sensor_ctl/zeek/intel/lock || true
mkdir -p "$SUPERVISOR_PATH"/suricata/rules "$ZEEK_LOG_PATH"/suricata 2>/dev/null || true
mkdir -p "$PCAP_PATH"/ 2>/dev/null || true
mkdir -p "$SUPERVISOR_PATH"/supercronic 2>/dev/null && touch "$SUPERVISOR_PATH"/supercronic/crontab || true

if [ -d "$SUPERVISOR_PATH/"/supervisor.init ]; then
  popd >/dev/null 2>&1
  set +e
  for INIT_FILE in "$SUPERVISOR_PATH/"/supervisor.init/*; do
    source "${INIT_FILE}" >/dev/null 2>&1
  done
  set -e
  pushd "$SUPERVISOR_PATH" >/dev/null 2>&1
fi

ulimit -l unlimited || true
supervisord -c "$CONFIG_FILE"

popd >/dev/null 2>&1
