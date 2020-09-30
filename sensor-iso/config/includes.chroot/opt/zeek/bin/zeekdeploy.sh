#!/bin/bash

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

# get utilities for finding default zeek path and executable
[[ "$(uname -s)" = 'Darwin' ]] && REALPATH=grealpath || REALPATH=realpath
[[ "$(uname -s)" = 'Darwin' ]] && DIRNAME=gdirname || DIRNAME=dirname
if ! (type "$REALPATH" && type "$DIRNAME") > /dev/null; then
  echo "$(basename "${BASH_SOURCE[0]}") requires $REALPATH and $DIRNAME"
  exit 1
fi
export SCRIPT_PATH="$($DIRNAME $($REALPATH -e "${BASH_SOURCE[0]}"))"

# control_vars.conf file must be specified as argument to script or be found in an expected place
# source configuration variables file if found (precedence: pwd, script directory, /opt/sensor/sensor_ctl)
if [[ -n "$1" ]]; then
  source "$1"
else
  CONTROL_VARS_FILE="control_vars.conf"
  if [[ -r ./"$CONTROL_VARS_FILE" ]]; then
    source ./"$CONTROL_VARS_FILE"
  elif [[ -r "$SCRIPT_PATH"/"$CONTROL_VARS_FILE" ]]; then
    source "$SCRIPT_PATH"/"$CONTROL_VARS_FILE"
  elif [[ -r /opt/sensor/sensor_ctl/"$CONTROL_VARS_FILE" ]]; then
    source /opt/sensor/sensor_ctl/"$CONTROL_VARS_FILE"
  fi
fi

# capture interface(s) *must* be specified
if [[ -z $CAPTURE_INTERFACE ]] ; then
  echo "Zeek capture interface(s) (via \$CAPTURE_INTERFACE) not specified"
  exit 1
fi

# do we have AF_PACKET support in the kernel? true if > 0
AF_PACKET_SUPPORT=$(grep -c -x 'CONFIG_PACKET=[ym]' "/boot/config-$(uname -r)")

# determine location of zeekctl script and relative installation path
ZEEK_CTL="$(which zeekctl)"
[[ ! -x "$ZEEK_CTL" ]] && ZEEK_CTL="/opt/zeek/bin/zeekctl"
[[ ! -x "$ZEEK_CTL" ]] && ZEEK_CTL="/usr/bin/zeekctl"
[[ ! -x "$ZEEK_CTL" ]] && ZEEK_CTL="/usr/local/bin/zeekctl"
if [[ ! -x "$ZEEK_CTL" ]]; then
  echo "zeekctl script not found or not executable"
  exit 1
fi
ZEEK_INSTALL_PATH="$(realpath "$(dirname "$(realpath "$ZEEK_CTL")")"/..)"
if [[ ! -d "$ZEEK_INSTALL_PATH" ]]; then
  echo "zeek root path \"$ZEEK_INSTALL_PATH\" does not exist"
  exit 1
fi

# default file extraction mode is "do not extract files"
[[ -z $ZEEK_EXTRACTOR_MODE ]] && ZEEK_EXTRACTOR_MODE="none"

# some other defaults
[[ -z $ZEEK_LB_PROCS ]] && ZEEK_LB_PROCS="1"
[[ -z $ZEEK_LB_METHOD ]] && ZEEK_LB_METHOD="custom"
[[ -z $ZEEK_AF_PACKET_BUFFER_SIZE ]] && ZEEK_AF_PACKET_BUFFER_SIZE="$(echo "64*1024*1024" | bc)"

# if zeek log path is unspecified, write logs to pwd
[[ -z $ZEEK_LOG_PATH ]] && ZEEK_LOG_PATH=.
ZEEK_LOG_PATH="$($REALPATH "$ZEEK_LOG_PATH")"
ARCHIVE_PATH="$ZEEK_LOG_PATH/logs"
WORK_PATH="$ZEEK_LOG_PATH/spool"
TMP_PATH="$ZEEK_INSTALL_PATH/spool/tmp"
EXTRACT_FILES_PATH="$ZEEK_LOG_PATH/extract_files"
mkdir -p "$ARCHIVE_PATH" "$WORK_PATH" "$EXTRACT_FILES_PATH" "$TMP_PATH"
export TMP="$TMP_PATH"

# if file extraction is enabled and file extraction script exists, set up the argument for zeek to use it
[[ -z $ZEEK_RULESET ]] && ZEEK_RULESET="local"
EXTRACTOR_ZEEK_SCRIPT="extractor.zeek"
ZEEK_EXTRACTOR_SCRIPT="$ZEEK_INSTALL_PATH"/share/zeek/site/"$EXTRACTOR_ZEEK_SCRIPT"
([[ ! -r "$ZEEK_EXTRACTOR_SCRIPT" ]] || [[ "$ZEEK_EXTRACTOR_MODE" = "none" ]]) && ZEEK_EXTRACTOR_SCRIPT=""
([[ ! -r "$ZEEK_EXTRACTOR_OVERRIDE_FILE" ]] || [[ -z "$ZEEK_EXTRACTOR_SCRIPT" ]] || [[ ! "$ZEEK_EXTRACTOR_MODE" = "mapped" ]]) && ZEEK_EXTRACTOR_OVERRIDE_FILE=""

# configure zeek cfg files
pushd "$ZEEK_INSTALL_PATH"/etc >/dev/null 2>&1

# make replacements for variables in zeekctl.cfg
ZEEK_LOG_ROTATE=3600
ZEEK_LOG_EXPIRE=0
ZEEK_STATS=0
sed -r -i "s/(LogRotationInterval)\s*=\s*.*/\1 = $ZEEK_LOG_ROTATE/" ./zeekctl.cfg
sed -r -i "s/(LogExpireInterval)\s*=\s*.*/\1 = $ZEEK_LOG_EXPIRE/" ./zeekctl.cfg
if [[ -n "$ZEEK_EXTRACTOR_SCRIPT" ]] && [[ -n "$ZEEK_EXTRACTOR_OVERRIDE_FILE" ]]; then
  sed -r -i "s@(SitePolicyScripts)\s*=\s*.*@\1 = $ZEEK_RULESET $ZEEK_EXTRACTOR_SCRIPT $ZEEK_EXTRACTOR_OVERRIDE_FILE@" ./zeekctl.cfg
elif [[ -n "$ZEEK_EXTRACTOR_SCRIPT" ]]; then
  sed -r -i "s@(SitePolicyScripts)\s*=\s*.*@\1 = $ZEEK_RULESET $ZEEK_EXTRACTOR_SCRIPT@" ./zeekctl.cfg
else
  sed -r -i "s@(SitePolicyScripts)\s*=\s*.*@\1 = $ZEEK_RULESET@" ./zeekctl.cfg
fi
sed -r -i "s@(LogDir)\s*=\s*.*@\1 = $ARCHIVE_PATH@" ./zeekctl.cfg
sed -r -i "s@(SpoolDir)\s*=\s*.*@\1 = $WORK_PATH@" ./zeekctl.cfg

# completely rewrite node.cfg for one worker per interface
rm -f ./node.cfg
cat << 'EOF' > ./node.cfg
[logger]
type=logger
host=localhost

[manager]
type=manager
host=localhost

[proxy]
type=proxy
host=localhost
EOF

# number of zeek processes so far (logger, manager, proxy)
ZEEK_PROCS=3

# let zeek processes run on whichever processors
CPU_PINS="$(seq -s, 0 $(($(grep -c ^processor /proc/cpuinfo)-1)))"

# incrementing ID of current worker for config file
WORKER_ID=1

# AF_PACKET fanout ID (per-interface)
FANOUT_ID=1

# create a worker for each interface
for IFACE in ${CAPTURE_INTERFACE//,/ }; do
  cat << EOF >> ./node.cfg

[worker-$WORKER_ID]
type=worker
host=localhost
interface=$IFACE
env_vars=ZEEK_EXTRACTOR_MODE=$ZEEK_EXTRACTOR_MODE,ZEEK_EXTRACTOR_PATH=$EXTRACT_FILES_PATH/,TMP=$TMP_PATH
EOF
  # if af_packet is available in the kernel, write it out as well
  if [ $AF_PACKET_SUPPORT -gt 0 ] && [ $ZEEK_LB_PROCS -gt 0 ]; then
    echo "lb_procs=$ZEEK_LB_PROCS" >> ./node.cfg
    echo "lb_method=$ZEEK_LB_METHOD" >> ./node.cfg
    echo "# pin_cpus=$CPU_PINS" >> ./node.cfg
    echo "af_packet_fanout_id=$FANOUT_ID" >> ./node.cfg
    echo "af_packet_fanout_mode=AF_Packet::FANOUT_HASH" >> ./node.cfg
    echo "af_packet_buffer_size=$ZEEK_AF_PACKET_BUFFER_SIZE" >> ./node.cfg
  fi

  WORKER_ID=$((WORKER_ID+1))
  FANOUT_ID=$((FANOUT_ID+1))
  ZEEK_PROCS=$((ZEEK_PROCS+1))
done

# we'll assume we didn't mess with networks.cfg, leave it alone

popd >/dev/null 2>&1

pushd "$ZEEK_LOG_PATH" >/dev/null 2>&1

function finish {
  echo "Stopping via \"$ZEEK_CTL\"" >&2
  "$ZEEK_CTL" stop
  rm -f "$TMP_PATH"/*
}
trap finish EXIT

# execute zeekctl
echo "Running via \"$ZEEK_CTL\"..." >&2
"$ZEEK_CTL" deploy

# wait until interrupted (or somehow if zeek dies on its own)
while [ $("$ZEEK_CTL" status | tail -n +2 | grep -P "localhost\s+running\s+\d+" | wc -l) -ge $ZEEK_PROCS ]; do
  for i in `seq 1 10`; do
    sleep 1
  done
done

popd >/dev/null 2>&1
