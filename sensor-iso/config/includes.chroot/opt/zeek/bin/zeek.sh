#!/bin/bash

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

# configuration variables may be specified in control_vars.conf rather than on the command line
CONTROL_VARS_FILE="control_vars.conf"

# script usd for file extraction
EXTRACTOR_ZEEK_SCRIPT="extractor.zeek"

# get utilities for finding default zeek path and executable
[[ "$(uname -s)" = 'Darwin' ]] && REALPATH=grealpath || REALPATH=realpath
[[ "$(uname -s)" = 'Darwin' ]] && DIRNAME=gdirname || DIRNAME=dirname
if ! (type "$REALPATH" && type "$DIRNAME") > /dev/null; then
  echo "$(basename "${BASH_SOURCE[0]}") requires $REALPATH and $DIRNAME"
  exit 1
fi
export SCRIPT_PATH="$($DIRNAME $($REALPATH -e "${BASH_SOURCE[0]}"))"

# source configuration variables file if found (precedence: pwd, script directory, /opt/sensor/sensor_ctl)
if [[ -r ./"$CONTROL_VARS_FILE" ]]; then
  source ./"$CONTROL_VARS_FILE"
elif [[ -r "$SCRIPT_PATH"/"$CONTROL_VARS_FILE" ]]; then
  source "$SCRIPT_PATH"/"$CONTROL_VARS_FILE"
elif [[ -r /opt/sensor/sensor_ctl/"$CONTROL_VARS_FILE" ]]; then
  source /opt/sensor/sensor_ctl/"$CONTROL_VARS_FILE"
fi

# determine location of zeek executable and relative installation path
ZEEK_EXE="$(which zeek)"
[[ ! -x "$ZEEK_EXE" ]] && ZEEK_EXE="/opt/zeek/bin/zeek"
[[ ! -x "$ZEEK_EXE" ]] && ZEEK_EXE="/usr/bin/zeek"
[[ ! -x "$ZEEK_EXE" ]] && ZEEK_EXE="/usr/local/bin/zeek"
if [[ ! -x "$ZEEK_EXE" ]]; then
  echo "zeek executable not found or not executable"
  exit 1
fi
ZEEK_INSTALL_PATH="$(realpath "$(dirname "$(realpath "$ZEEK_EXE")")"/..)"
if [[ ! -d "$ZEEK_INSTALL_PATH" ]]; then
  echo "zeek root path \"$ZEEK_INSTALL_PATH\" does not exist"
  exit 1
fi

# allow user-specified overrides for interface, file extraction mode, and destination log path
while getopts i:p:f:d:o: opts; do
   case ${opts} in
      i) CAPTURE_INTERFACE=${OPTARG} ;;
      p) PCAP_FILE=${OPTARG} ;;
      f) ZEEK_EXTRACTOR_MODE=${OPTARG} ;;
      d) ZEEK_LOG_PATH=${OPTARG} ;;
      o) ZEEK_EXTRACTOR_OVERRIDE_FILE=${OPTARG} ;;
   esac
done

# capture interface or PCAP file *must* be specified
if [[ -n $PCAP_FILE ]] && [[ -r $PCAP_FILE ]] ; then
  ZEEK_INPUT_FLAG="-r"
  ZEEK_INPUT_OBJECT=$PCAP_FILE
elif [[ -n $CAPTURE_INTERFACE ]] ; then
  ZEEK_INPUT_FLAG="-i"
  ZEEK_INPUT_OBJECT=$CAPTURE_INTERFACE
else
  echo "Zeek capture interface (via \$CAPTURE_INTERFACE or -i <name>) or PCAP file (via -p <filename>) not specified"
  exit 1
fi

# default file extraction mode is "do not extract files"
[[ -z $ZEEK_EXTRACTOR_MODE ]] && ZEEK_EXTRACTOR_MODE="none"
export ZEEK_EXTRACTOR_MODE

# if zeek log path is unspecified, write logs to pwd
[[ -z $ZEEK_LOG_PATH ]] && ZEEK_LOG_PATH=.
ZEEK_LOG_PATH="$($REALPATH "$ZEEK_LOG_PATH")"

# if file extraction is enabled and file extraction script exists, set up the argument for zeek to use it
ZEEK_EXTRACTOR_SCRIPT="$ZEEK_INSTALL_PATH"/share/zeek/site/"$EXTRACTOR_ZEEK_SCRIPT"
([[ ! -r "$ZEEK_EXTRACTOR_SCRIPT" ]] || [[ "$ZEEK_EXTRACTOR_MODE" = "none" ]]) && ZEEK_EXTRACTOR_SCRIPT=""
([[ ! -r "$ZEEK_EXTRACTOR_OVERRIDE_FILE" ]] || [[ -z "$ZEEK_EXTRACTOR_SCRIPT" ]] || [[ ! "$ZEEK_EXTRACTOR_MODE" = "mapped" ]]) && ZEEK_EXTRACTOR_OVERRIDE_FILE=""

# zeek ruleset is loaded from control_vars.conf if it existed, or "local" if not
[[ -z $ZEEK_RULESET ]] && ZEEK_RULESET="local"

ARCHIVE_PATH="$ZEEK_LOG_PATH/archived/$(date +"%Y-%m-%d-%H-%M-%S")"
mkdir -p "$ZEEK_LOG_PATH"/extract_files "$ARCHIVE_PATH"
pushd "$ZEEK_LOG_PATH" >/dev/null 2>&1

function finish {
  echo "\"$ZEEK_EXE\" exited" >&2
  pushd "$ZEEK_LOG_PATH" >/dev/null 2>&1

  ####################################################################################
  # rename/move current zeek log files to an archive directory
  ####################################################################################

  # we don't want to interfere with files being used by other processes (except filebeat, screw that guy)
  mapfile -t OPEN_FILES < <( lsof -u "$USER" -a +D "$(pwd)" -a -d 0-65535 2>/dev/null | grep -Pv "^[\w-]+beat" | tail -n +2 | awk '{print $9}' | sed "s@^$ZEEK_LOG_PATH/@@" )
  declare -A OPEN_FILES_MAP
  for OPEN_FILE in ${OPEN_FILES[@]}; do
    OPEN_FILES_MAP["$OPEN_FILE"]=1
  done

  shopt -s nullglob
  for LOG_FILE in *; do
    # process only files, and don't mess with open files (see OPEN_FILES declaration above)
    if [[ ! -d "$LOG_FILE" ]] && [[ -z ${OPEN_FILES_MAP[$LOG_FILE]} ]]; then
      mv -v "$LOG_FILE" "$ARCHIVE_PATH"/
    fi
  done
  popd >/dev/null 2>&1

  # we don't need to hang on to the persistent .state directory
  [[ -d "$ZEEK_LOG_PATH"/.state ]] && sleep 1 && (pidof zeek >/dev/null 2>&1 || rm -rf "$ZEEK_LOG_PATH"/.state)
}
trap finish EXIT

# execute zeek
echo "Running \"$ZEEK_EXE\"..." >&2
if [[ -n "$ZEEK_EXTRACTOR_SCRIPT" ]] && [[ -n "$ZEEK_EXTRACTOR_OVERRIDE_FILE" ]]; then
  "$ZEEK_EXE" -C $ZEEK_INPUT_FLAG "$ZEEK_INPUT_OBJECT" "$ZEEK_RULESET" "$ZEEK_EXTRACTOR_SCRIPT" "$ZEEK_EXTRACTOR_OVERRIDE_FILE"
elif [[ -n "$ZEEK_EXTRACTOR_SCRIPT" ]]; then
  "$ZEEK_EXE" -C $ZEEK_INPUT_FLAG "$ZEEK_INPUT_OBJECT" "$ZEEK_RULESET" "$ZEEK_EXTRACTOR_SCRIPT"
else
  "$ZEEK_EXE" -C $ZEEK_INPUT_FLAG "$ZEEK_INPUT_OBJECT" "$ZEEK_RULESET"
fi

popd >/dev/null 2>&1
