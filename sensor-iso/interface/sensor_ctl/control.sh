#!/bin/bash

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

set -e

CONFIG_DIR="supervisor.d"
CONFIG_FILE="supervisord.conf"
CONTROL_VARS_FILE="control_vars.conf"

# create symlinks to this script named start, stop, restart, etc.
CONTROL_COMMAND="$(basename "${BASH_SOURCE[0]}")"

if [[ ($# -eq 0) || (($# -eq 1) && ("$1" = "all")) ]]; then
  if [[ "$CONTROL_COMMAND" = "shutdown" ]]; then
    CONTROL_PROCESS=()
  else
    # no arguments, defaults to all managed processes
    CONTROL_PROCESS="all"
  fi
else
  # eg., tcpdump, zeek
  CONTROL_PROCESS="$@"
fi

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

if [[ -d ./"$CONFIG_DIR" && ("$CONTROL_COMMAND" = "start" || "$CONTROL_COMMAND" = "restart") && "$CONTROL_PROCESS" = "all" ]]; then
  # if it's simply a bare "start" or "restart", we only really want it to restart the programs for which
  # autostart=true, instead of ALL possible programs. So look in $CONFIG_FILE for autostart=true processes
  # and execute the $CONTROL_COMMAND only on those programs
  CONTROL_PROGS=()
  while read LINE; do
    PROCESS_NAME=$(echo $LINE | cut -f1 -d=)
    PROCESS_AUTOSTART_VAR=$(echo $LINE | cut -f2 -d=)
    PROCESS_AUTOSTART="$(eval echo "\$$PROCESS_AUTOSTART_VAR")"
    if [ "${PROCESS_AUTOSTART,,}" = "true" ]; then
      #
      CONTROL_PROGS+=("$PROCESS_NAME")
    fi
  done <<< "$(grep -Pih "^(\[program:|autostart\s*=)" ./"$CONFIG_DIR"/*.conf | sed -e "s/\[program:\(.*\)\]/\1/" | sed -e "s/.*ENV_\(.*\))s/\1/" | paste -s -d'=\n')"

  # because we're using group names now, we need to use the full group name in our start/restart command rather than just the command name
  # get it from the "status" command
  CONTROL_PROGS_WITH_GROUP=()
  while read LINE; do
    for PROG in "${CONTROL_PROGS[@]}"; do
      if [[ $LINE =~ ^[a-zA-Z0-9_-]+:${PROG}$ ]]; then
        CONTROL_PROGS_WITH_GROUP+=("$LINE")
        break
      fi
    done
  done <<< "$(supervisorctl -c "$CONFIG_FILE" status all | awk '{print $1}')"

  # issue the command with the full, group-included names
  if [ ${#CONTROL_PROGS_WITH_GROUP[@]} -gt 0 ]; then
    supervisorctl -c "$CONFIG_FILE" "$CONTROL_COMMAND" "${CONTROL_PROGS_WITH_GROUP[@]}"
  fi

else
  # simply pass the command through to supervisorctl
  supervisorctl -c "$CONFIG_FILE" "$CONTROL_COMMAND" "${CONTROL_PROCESS[@]}"

  # if zeek doesn't want to go down in a timely manner (or at all), make it an offer it can't refuse
  if [[ ("$CONTROL_COMMAND" = "stop" || "$CONTROL_COMMAND" = "shutdown") && ("$CONTROL_PROCESS" = "all" || "$CONTROL_PROCESS" = "zeek"*) ]]; then
    for i in {1..60}; do
      sleep 1
      pidof zeek >/dev/null 2>&1 || break
    done
    pidof zeek >/dev/null 2>&1 && killall -9 zeek
  fi
fi

popd >/dev/null 2>&1
