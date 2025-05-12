#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

#
# environment variables are used to control the contents of these files
#   - zeekctl.cfg
#   - node.cfg
#   - networks.cfg
#
# CAPTURE_INTERFACE or PCAP_IFACE - defines the capture interfaces, comma-separated list
# CAPTURE_FILTER or PCAP_FILTER - bpf filter for capture, however see idaholab/Malcolm#474 as this does not seem to be propogated correctly
# ZEEK_LB_METHOD - Zeek load balancing method: should be "custom" for AF_Packet
# ZEEK_AF_PACKET_BUFFER_SIZE - AF_Packet [ring buffer size](https://docs.zeek.org/en/master/scripts/builtin-plugins/Zeek_AF_Packet/init.zeek.html#id-AF_Packet::buffer_size) in bytes (default 67108864)
# ZEEK_AF_PACKET_FANOUT_MODE - AF_Packet [fanout mode](https://docs.zeek.org/en/master/scripts/base/bif/plugins/Zeek_AF_Packet.af_packet.bif.zeek.html#type-AF_Packet::FanoutMode) (default FANOUT_HASH)
# ZEEK_LB_PROCS_WORKER_DEFAULT - ["Zeek is not multithreaded, so once the limitations of a single processor core are reached the only option currently is to spread the workload across many cores"](https://docs.zeek.org/en/master/cluster-setup.html#cluster-architecture). This value defines the number of processors to be assigned to each group of [workers](https://docs.zeek.org/en/master/frameworks/cluster.html#worker) created for each capture interface for [load balancing](https://docs.zeek.org/en/master/cluster-setup.html#load-balancing) (default 1). A value of 0 means "autocalculate based on the number of CPUs present in the system."
# ZEEK_LB_PROCS_WORKER_n - Explicitly defines the number of processor to be assigned to the group of workers for the *n*-th capture interface. If unspecified this defaults to the number of CPUs ZEEK_PIN_CPUS_WORKER_n if defined, or ZEEK_LB_PROCS_WORKER_DEFAULT otherwise.
# ZEEK_LB_PROCS_LOGGER - Defines the number of processors to be assigned to the [loggers](https://docs.zeek.org/en/master/frameworks/cluster.html#logger) (default 1)
# ZEEK_LB_PROCS_PROXY - Defines the number of processors to be assigned to the [proxies](https://docs.zeek.org/en/master/frameworks/cluster.html#proxy) (default 1)
# ZEEK_LB_PROCS_CPUS_RESERVED - If ZEEK_LB_PROCS_WORKER_DEFAULT is 0 ("autocalculate"), exclude this number of CPUs from the autocalculation (defaults to 1 (kernel) + 1 (manager) + ZEEK_LB_PROCS_LOGGER + ZEEK_LB_PROCS_PROXY)
# ZEEK_METRICS_PORT - Defines listen port for Prometheus API
# ZEEK_PIN_CPUS_WORKER_AUTO - Automatically [pin worker CPUs](https://en.wikipedia.org/wiki/Processor_affinity) (default false)
# ZEEK_PIN_CPUS_WORKER_n - Explicitly defines the processor IDs to be to be assigned to the group of workers for the *n*-th capture interface (e.g., 0 means "the first CPU"; 12,13,14,15 means "the last four CPUs" on a 16-core system)
# ZEEK_PIN_CPUS_OTHER_AUTO - automatically pin CPUs for manager, loggers, and proxies if possible (default false)
# ZEEK_PIN_CPUS_MANAGER - list of CPUs to pin for the [manager](https://docs.zeek.org/en/master/frameworks/cluster.html#manager) process (default is unset; only used if ZEEK_PIN_CPUS_OTHER_AUTO is false)
# ZEEK_PIN_CPUS_LOGGER - list of CPUs to pin for the logger processes (default is unset; only used if ZEEK_PIN_CPUS_OTHER_AUTO is false)
# ZEEK_PIN_CPUS_PROXY - list of CPUs to pin for the proxy processes (default is unset; only used if ZEEK_PIN_CPUS_OTHER_AUTO is false)

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
if [[ -z "$CAPTURE_INTERFACE" ]] && [[ -n "$PCAP_IFACE" ]]; then
  CAPTURE_INTERFACE="$PCAP_IFACE"
fi
if [[ -z $CAPTURE_INTERFACE ]] ; then
  echo "Zeek capture interface(s) (via \$CAPTURE_INTERFACE) not specified"
  exit 1
fi

if [[ -z "$CAPTURE_FILTER" ]] && [[ -n "$PCAP_FILTER" ]]; then
  CAPTURE_FILTER="$PCAP_FILTER"
fi
export CAPTURE_FILTER

# do we have AF_PACKET support in the kernel? if we can't determine, assume "yes"
BOOT_CONFIG_FILE="/boot/config-$(uname -r)"
[[ -r "$BOOT_CONFIG_FILE" ]] && AF_PACKET_SUPPORT=$(grep -c -x 'CONFIG_PACKET=[ym]' "$BOOT_CONFIG_FILE") || AF_PACKET_SUPPORT=1

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

[[ -z $ZEEK_LOCAL_NETS ]] && ZEEK_LOCAL_NETS=
[[ -z $ZEEK_INTEL_REFRESH_ON_DEPLOY ]] && ZEEK_INTEL_REFRESH_ON_DEPLOY="true"
[[ -z $ZEEK_EXTRACTOR_MODE ]] && ZEEK_EXTRACTOR_MODE="none"

[[ -z $ZEEK_LB_METHOD ]] && ZEEK_LB_METHOD="custom"
[[ -z $ZEEK_AF_PACKET_BUFFER_SIZE ]] && ZEEK_AF_PACKET_BUFFER_SIZE="$(echo "64*1024*1024" | bc)"
[[ -z $ZEEK_AF_PACKET_FANOUT_MODE ]] && ZEEK_AF_PACKET_FANOUT_MODE="FANOUT_HASH"
[[ -z $ZEEK_PIN_CPUS_WORKER_AUTO ]] && ZEEK_PIN_CPUS_WORKER_AUTO="false"
[[ -z $ZEEK_PIN_CPUS_OTHER_AUTO ]] && ZEEK_PIN_CPUS_OTHER_AUTO="false"
[[ -z $ZEEK_LB_PROCS_LOGGER ]] && ZEEK_LB_PROCS_LOGGER="1"
[[ -z $ZEEK_LB_PROCS_PROXY ]] && ZEEK_LB_PROCS_PROXY="1"
(( $ZEEK_LB_PROCS_LOGGER <= 0 )) && ZEEK_LB_PROCS_LOGGER=1
(( $ZEEK_LB_PROCS_PROXY <= 0 )) && ZEEK_LB_PROCS_PROXY=1
[[ -z $ZEEK_LB_PROCS_CPUS_RESERVED ]] && ZEEK_LB_PROCS_CPUS_RESERVED=$(( 1 + 1 + ZEEK_LB_PROCS_LOGGER + ZEEK_LB_PROCS_PROXY ))

# get the total number of CPUs and interfaces which may be used in calculations later
TOTAL_CPUS_UNFILTERED="$(nproc --all 2>/dev/null || echo '0')"
(( $TOTAL_CPUS_UNFILTERED <= 0 )) && TOTAL_CPUS_UNFILTERED=1
TOTAL_CPUS_FILTERED=$(( TOTAL_CPUS_UNFILTERED - ZEEK_LB_PROCS_CPUS_RESERVED ))
(( $TOTAL_CPUS_FILTERED <= 0 )) && TOTAL_CPUS_FILTERED=1
TOTAL_IFACES="$(echo "${CAPTURE_INTERFACE}" | awk -F',' '{print NF}')"
(( $TOTAL_IFACES <= 0 )) && TOTAL_IFACES=1

# calculate workers based on the number of CPUs, minus reserved
[[ -z $ZEEK_LB_PROCS_WORKER_DEFAULT ]] && ZEEK_LB_PROCS_WORKER_DEFAULT="2"
(( $ZEEK_LB_PROCS_WORKER_DEFAULT == 0 )) && ZEEK_LB_PROCS_WORKER_DEFAULT=$(( TOTAL_CPUS_FILTERED / TOTAL_IFACES ))
(( $ZEEK_LB_PROCS_WORKER_DEFAULT <= 0 )) && ZEEK_LB_PROCS_WORKER_DEFAULT=1

# auto-pin manager, logger, and proxy if instructed to and we have enough CPUs
if [[ "$ZEEK_PIN_CPUS_OTHER_AUTO" == "true" ]]; then
  ZEEK_PIN_CPUS_MANAGER=
  ZEEK_PIN_CPUS_LOGGER=
  ZEEK_PIN_CPUS_PROXY=

  (( $TOTAL_CPUS_UNFILTERED > $ZEEK_LB_PROCS_CPUS_RESERVED )) && \
    ZEEK_PIN_CPUS_MANAGER=$(( TOTAL_CPUS_UNFILTERED - 1 ))

  [[ -n $ZEEK_PIN_CPUS_MANAGER ]] && \
    (( $TOTAL_CPUS_UNFILTERED > ( $ZEEK_LB_PROCS_CPUS_RESERVED + $ZEEK_LB_PROCS_LOGGER ) )) && \
    ZEEK_PIN_CPUS_LOGGER=$(seq -s, $(( ZEEK_PIN_CPUS_MANAGER - ZEEK_LB_PROCS_LOGGER )) $(( ZEEK_PIN_CPUS_MANAGER - 1 )) )

  [[ -n $ZEEK_PIN_CPUS_LOGGER ]] && \
    (( $TOTAL_CPUS_UNFILTERED > ( $ZEEK_LB_PROCS_CPUS_RESERVED + $ZEEK_LB_PROCS_LOGGER + $ZEEK_LB_PROCS_PROXY ) )) && \
    ZEEK_PIN_CPUS_LOGGER_LOW=$(echo $ZEEK_PIN_CPUS_LOGGER | cut -d, -f1) && \
    ZEEK_PIN_CPUS_PROXY=$(seq -s, $(( ZEEK_PIN_CPUS_LOGGER_LOW - ZEEK_LB_PROCS_PROXY )) $(( ZEEK_PIN_CPUS_LOGGER_LOW - 1 )) )
fi

# if zeek log path is unspecified, write logs to pwd
[[ -z $ZEEK_LOG_PATH ]] && ZEEK_LOG_PATH=.
ZEEK_LOG_PATH="$($REALPATH "$ZEEK_LOG_PATH")"
ARCHIVE_PATH="$ZEEK_LOG_PATH/logs"
WORK_PATH="$ZEEK_LOG_PATH/spool"
TMP_PATH="$ZEEK_INSTALL_PATH/spool/tmp"
[[ -z $EXTRACT_FILES_PATH ]] && EXTRACT_FILES_PATH="$ZEEK_LOG_PATH/extract_files"
mkdir -p "$ARCHIVE_PATH"/static "$WORK_PATH" "$EXTRACT_FILES_PATH" "$TMP_PATH"
export TMP="$TMP_PATH"

# if file extraction is enabled and file extraction script exists, set up the argument for zeek to use it
[[ -z $ZEEK_RULESET ]] && ZEEK_RULESET="local"
EXTRACTOR_ZEEK_SCRIPT="extractor.zeek"
EXTRACTOR_INTERESTING_ZEEK_SCRIPT="extractor_override.interesting.zeek"
ZEEK_EXTRACTOR_SCRIPT="$ZEEK_INSTALL_PATH"/share/zeek/site/"$EXTRACTOR_ZEEK_SCRIPT"
ZEEK_EXTRACTOR_INTERESTING_SCRIPT="$ZEEK_INSTALL_PATH"/share/zeek/site/"$EXTRACTOR_INTERESTING_ZEEK_SCRIPT"
([[ ! -r "$ZEEK_EXTRACTOR_SCRIPT" ]] || [[ "$ZEEK_EXTRACTOR_MODE" = "none" ]]) && ZEEK_EXTRACTOR_SCRIPT=""
if [[ "$ZEEK_EXTRACTOR_MODE" = "interesting" ]] && [[ -r "$ZEEK_EXTRACTOR_INTERESTING_SCRIPT" ]]; then
  ZEEK_EXTRACTOR_OVERRIDE_FILE="$ZEEK_EXTRACTOR_INTERESTING_SCRIPT"
  export ZEEK_EXTRACTOR_MODE="mapped"
fi
([[ ! -r "$ZEEK_EXTRACTOR_OVERRIDE_FILE" ]] || [[ -z "$ZEEK_EXTRACTOR_SCRIPT" ]] || [[ ! "$ZEEK_EXTRACTOR_MODE" = "mapped" ]]) && ZEEK_EXTRACTOR_OVERRIDE_FILE=""

# make sure "intel" directory exists, even if empty
[[ -n "$ZEEK_INTEL_PATH" ]] && INTEL_DIR="$ZEEK_INTEL_PATH" || INTEL_DIR=/opt/sensor/sensor_ctl/zeek/intel
export INTEL_DIR
mkdir -p "$INTEL_DIR"/STIX "$INTEL_DIR"/MISP "$INTEL_DIR"/Mandiant
[[ ! -f "$INTEL_DIR"/__load__.zeek ]] && ( touch "$INTEL_DIR"/__load__.zeek 2>/dev/null || true )
# autoconfigure load directives for intel files
[[ -x "$ZEEK_INSTALL_PATH"/bin/zeek_intel_setup.sh ]] && \
  [[ "$ZEEK_INTEL_REFRESH_ON_DEPLOY" == "true" ]] && \
  "$ZEEK_INSTALL_PATH"/bin/zeek_intel_setup.sh /bin/true
INTEL_UPDATE_TIME_PREV=0

# make sure "custom" directory exists, even if empty
[[ -n "$ZEEK_CUSTOM_PATH" ]] && CUSTOM_DIR="$ZEEK_CUSTOM_PATH" || CUSTOM_DIR=/opt/sensor/sensor_ctl/zeek/custom
export CUSTOM_DIR
mkdir -p "$CUSTOM_DIR"
[[ ! -f "$CUSTOM_DIR"/__load__.zeek ]] && ( touch "$CUSTOM_DIR"/__load__.zeek 2>/dev/null || true )

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
# We're setting FileExtract::prefix for the directory for file extraction, so we
#   don't want this new default behavior from zeekctl. So, set FileExtractDir
#   there to an empty value.
# See   https://github.com/zeek/zeekctl/blob/7e1a8448083ef0013f15e67ce001836e680589a2/CHANGES#L11-L26
#   and https://github.com/zeek/zeekctl/issues/65
sed -r -i "s@(FileExtractDir)\s*=\s*.*@\1 =@" ./zeekctl.cfg

sed -r -i "s/(MailConnectionSummary)\s*=\s*.*/\1 = 0/" ./zeekctl.cfg
sed -r -i "s/(MinDiskSpace)\s*=\s*.*/\1 = 0/" ./zeekctl.cfg
sed -r -i "s/(MailHostUpDown)\s*=\s*.*/\1 = 0/" ./zeekctl.cfg
if grep --quiet ^SendMail ./zeekctl.cfg; then
  sed -r -i "s/(SendMail)\s*=\s*.*/\1 =/" ./zeekctl.cfg
elif grep --quiet ^MailTo ./zeekctl.cfg; then
  sed -i -r '/^MailTo\s*=\s*/i SendMail =' ./zeekctl.cfg
else
  echo "SendMail =" >> ./zeekctl.cfg
fi
if [ $AF_PACKET_SUPPORT -gt 0 ]; then
  if grep --quiet '^lb_custom\.InterfacePrefix' ./zeekctl.cfg; then
    sed -r -i 's/(lb_custom\.InterfacePrefix)[[:space:]]*=.*/\1=af_packet::/g' ./zeekctl.cfg
  else
    echo >> ./zeekctl.cfg
    echo "# InterfacePrefix=af_packet:: for interfaces using lb_method=custom  " >> ./zeekctl.cfg
    echo "lb_custom.InterfacePrefix=af_packet::" >> ./zeekctl.cfg
  fi
else
  # no af_packet support, so remove InterfacePrefix=af_packet
  sed -r -i '/InterfacePrefix[[:space:]]*=[[:space:]]*af_packet/d'  ./zeekctl.cfg
fi

if [[ -n "$ZEEK_METRICS_PORT" ]]; then
  if grep --quiet ^MetricsPort ./zeekctl.cfg; then
    sed -r -i "s/(MetricsPort)\s*=\s*.*/\1 = $ZEEK_METRICS_PORT/" ./zeekctl.cfg
  else
    echo "MetricsPort = $ZEEK_METRICS_PORT" >> ./zeekctl.cfg
  fi
fi

# completely rewrite node.cfg for one worker per interface
# see idaholab/Malcolm#36 for details on fine-tuning

rm -f ./node.cfg

cat << 'EOF' > ./node.cfg
#
# DO NOT EDIT THIS FILE
#
# It is automatically generated by /opt/zeek/bin/zeekdeploy.sh
#
EOF

echo "[manager]"                         >> ./node.cfg
echo "type=manager"                      >> ./node.cfg
echo "host=localhost"                    >> ./node.cfg
[[ -n $ZEEK_PIN_CPUS_MANAGER ]] && \
  echo "pin_cpus=$ZEEK_PIN_CPUS_MANAGER" >> ./node.cfg
echo ""                                  >> ./node.cfg

for (( ID=1; ID <= ZEEK_LB_PROCS_LOGGER; ID++)); do
  echo "[logger-$ID]"                      >> ./node.cfg
  echo "type=logger"                       >> ./node.cfg
  echo "host=localhost"                    >> ./node.cfg
  if [[ -n $ZEEK_PIN_CPUS_LOGGER ]]; then
    [[ "$ZEEK_PIN_CPUS_LOGGER" == *','* ]] && \
      echo "pin_cpus=$(echo $ZEEK_PIN_CPUS_LOGGER | cut -d, -f${ID})"  >> ./node.cfg || \
      echo "pin_cpus=$ZEEK_PIN_CPUS_LOGGER"                            >> ./node.cfg
  fi
  echo ""                                  >> ./node.cfg
done

for (( ID=1; ID <= ZEEK_LB_PROCS_PROXY; ID++)); do
  echo "[proxy-$ID]"                       >> ./node.cfg
  echo "type=proxy"                        >> ./node.cfg
  echo "host=localhost"                    >> ./node.cfg
  if [[ -n $ZEEK_PIN_CPUS_PROXY ]]; then
    [[ "$ZEEK_PIN_CPUS_PROXY" == *','* ]] && \
      echo "pin_cpus=$(echo $ZEEK_PIN_CPUS_PROXY | cut -d, -f${ID})"  >> ./node.cfg || \
      echo "pin_cpus=$ZEEK_PIN_CPUS_PROXY"                            >> ./node.cfg
  fi
  echo ""                                  >> ./node.cfg
done

# number of zeek processes so far (manager, logger, proxy)
ZEEK_PROCS=$(( 1 + ZEEK_LB_PROCS_LOGGER + ZEEK_LB_PROCS_PROXY ))

# incrementing ID of current worker for config file
WORKER_ID=1

# AF_PACKET fanout ID (per-interface)
FANOUT_ID=1

# for automatic CPU pinning
CURRENT_CPU_ID=0
HIGH_WORKER_CPU_ID=$(( TOTAL_CPUS_FILTERED - 1 ))

# create a worker for each interface
# see idaholab/Malcolm#36 for details on fine-tuning
for IFACE in ${CAPTURE_INTERFACE//,/ }; do

  # determine the number of worker lb_procs
  WORKER_CPU_PINS_VAR=ZEEK_PIN_CPUS_WORKER_${WORKER_ID}
  WORKER_LB_PROCS_VAR=ZEEK_LB_PROCS_WORKER_${WORKER_ID}
  # priority for worker's lb_procs:
  if [[ -n "${!WORKER_LB_PROCS_VAR}" ]]; then
    # 1. ZEEK_LB_PROCS_WORKER_n is explicitly specified
    WORKER_LB_PROCS="${!WORKER_LB_PROCS_VAR}"
  elif [[ -n "${!WORKER_CPU_PINS_VAR}" ]]; then
    # 2. ZEEK_PIN_CPUS_WORKER_n is specified, count the values
    WORKER_LB_PROCS="$(echo "${!WORKER_CPU_PINS_VAR}" | awk -F',' '{print NF}')"
  else
    # default to $ZEEK_LB_PROCS_WORKER_DEFAULT
    WORKER_LB_PROCS="$ZEEK_LB_PROCS_WORKER_DEFAULT"
  fi

  cat << EOF >> ./node.cfg

[worker-$WORKER_ID]
type=worker
host=localhost
interface=$IFACE
env_vars=ZEEK_CAPTURE_INTERFACE=$IFACE,ZEEK_EXTRACTOR_MODE=$ZEEK_EXTRACTOR_MODE,ZEEK_EXTRACTOR_PATH=$EXTRACT_FILES_PATH/,TMP=$TMP_PATH
EOF
  # if af_packet is available in the kernel, write it out as well
  if [ $AF_PACKET_SUPPORT -gt 0 ] && [ $WORKER_LB_PROCS -gt 0 ]; then
    echo "lb_procs=$WORKER_LB_PROCS" >> ./node.cfg
    echo "lb_method=$ZEEK_LB_METHOD" >> ./node.cfg
    if [[ -n "${!WORKER_CPU_PINS_VAR}" ]]; then
      # user explicitly specified worker CPUs to pin
      echo "pin_cpus=${!WORKER_CPU_PINS_VAR}" >> ./node.cfg
    elif [[ "$ZEEK_PIN_CPUS_WORKER_AUTO" == "true" ]]; then
      # user asked us to autmatically PIN worker CPUs
      echo -n "pin_cpus=" >> ./node.cfg
      for (( PIN=1; PIN <= WORKER_LB_PROCS; PIN++)); do
          echo -n "${CURRENT_CPU_ID}" >> ./node.cfg
          CURRENT_CPU_ID=$((CURRENT_CPU_ID+1))
          (( $CURRENT_CPU_ID > $HIGH_WORKER_CPU_ID )) && CURRENT_CPU_ID=0
          (( $PIN < $WORKER_LB_PROCS )) && echo -n ','  >> ./node.cfg || echo >> ./node.cfg
      done
    fi
    echo "af_packet_fanout_id=$FANOUT_ID" >> ./node.cfg
    echo "af_packet_fanout_mode=AF_Packet::$ZEEK_AF_PACKET_FANOUT_MODE" >> ./node.cfg
    echo "af_packet_buffer_size=$ZEEK_AF_PACKET_BUFFER_SIZE" >> ./node.cfg
    ZEEK_PROCS=$((ZEEK_PROCS+WORKER_LB_PROCS))
  else
    ZEEK_PROCS=$((ZEEK_PROCS+1))
  fi
  WORKER_ID=$((WORKER_ID+1))
  FANOUT_ID=$((FANOUT_ID+1))
done

echo -e "\n# Zeek procs: $ZEEK_PROCS" >> ./node.cfg

# populate networks.cfg from ZEEK_LOCAL_NETS
echo "# \$ZEEK_LOCAL_NETS:" > ./networks.cfg
echo "#   $ZEEK_LOCAL_NETS" >> ./networks.cfg
for NET in ${ZEEK_LOCAL_NETS//,/ }; do
  echo "$NET" | sed -re 's/^[[:blank:]]+|[[:blank:]]+$//g' -e 's/[[:blank:]]+/ /g' >> ./networks.cfg
done

popd >/dev/null 2>&1

pushd "$ZEEK_LOG_PATH" >/dev/null 2>&1

function zeek_procs_running {
  if output=$("$ZEEK_CTL" status 2>/dev/null) && [[ -n "$output" ]]; then
    echo "$output" | tail -n +2 | grep -P "localhost\s+running\s+\d+" | wc -l
  else
    pidof zeek 2>/dev/null | wc -w
  fi
}

function finish {
  echo "Stopping via \"$ZEEK_CTL\"" >&2
  "$ZEEK_CTL" stop
  rm -f "$TMP_PATH"/*
}
trap finish EXIT

# execute zeekctl
echo "Running via \"$ZEEK_CTL\" ($ZEEK_PROCS processes) ..." >&2
"$ZEEK_CTL" deploy

for (( i=1; i <= 30; i++)); do sleep 1; done

# keep track of intel updates in order to reload when they occur
INTEL_UPDATE_TIME="$(stat -c %Y "$INTEL_DIR"/__load__.zeek 2>/dev/null || echo '0')"
INTEL_UPDATE_TIME_PREV="$INTEL_UPDATE_TIME"

# wait until interrupted (or somehow if zeek dies on its own)
while :; do
  (( $(zeek_procs_running) >= ZEEK_PROCS )) || break

  # check to see if intel feeds were updated, and if so, restart
  INTEL_UPDATE_TIME="$(stat -c %Y "$INTEL_DIR"/__load__.zeek 2>/dev/null || echo '0')"
  if (( $INTEL_UPDATE_TIME > $INTEL_UPDATE_TIME_PREV )); then
    echo "Redeploying via \"$ZEEK_CTL deploy\" after intel update..." >&2
    "$ZEEK_CTL" deploy
    INTEL_UPDATE_TIME_PREV="$INTEL_UPDATE_TIME"
  fi

  for (( i=1; i <= 30; i++)); do sleep 1; done
done

popd >/dev/null 2>&1
