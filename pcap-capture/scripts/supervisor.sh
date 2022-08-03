#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.


set -e

CONFIG_DIR="/etc/supervisor.d"
CONFIG_FILE="/etc/supervisord.conf"
CAPTURE_GROUPS_FILE="capture-groups.conf"

function join_by { local IFS="$1"; shift; echo "$*"; }

function SetCaptureCapabilities() {
  setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /sbin/ethtool || true
  setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/tcpdump || true
  setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip CAP_SYS_ADMIN+eip' /usr/sbin/netsniff-ng || true
}

# Create config files for each capture interface for the various capture programs (tcpdump, netsniff)
# so that supervisord can manage instances of each of these programs for each interface.
# bro is now managed by broctl (via brodeploy.sh) rather than individually by supervisord so that
# we can use pf_ring
function CreateCaptureConfigs() {

  declare -a CAPTURE_PROGS=("tcpdump" "netsniff")

  if [[ -d "$CONFIG_DIR" ]]; then
    rm -f "$CONFIG_DIR"/"$CAPTURE_GROUPS_FILE"

    for PROG in "${CAPTURE_PROGS[@]}"; do
      declare -a PROG_GROUP=()

      # remove any old .conf files for this capture program, we'll create them all fresh
      rm -f "$CONFIG_DIR"/$PROG*.conf
      if [[ -n $PCAP_IFACE ]]; then

        # for each capture interface, expand the capture program's template and substitute for the $IFACE variable
        for IFACE in ${PCAP_IFACE//,/ }; do
          if [[ -r "$CONFIG_DIR"/$PROG.template ]]; then

            # expand $IFACE into interface name in a new configuration file
            export $IFACE
            sed -e "s/[$]IFACE/${IFACE}/g" "$CONFIG_DIR"/$PROG.template > "$CONFIG_DIR"/$PROG-"$IFACE".conf

            # get new program name for group inclusion
            INSTANCE_NAME="$(grep '^\[program:' "$CONFIG_DIR"/$PROG-"$IFACE".conf | sed "s/^\[program://" | sed "s/\]$//")"
            PROG_GROUP+=($INSTANCE_NAME)

          fi # capture program template exists

          # disable NIC hardware offloading features and adjust ring buffer sizes
          [[ "${PCAP_IFACE_TWEAK:-false}" == "true" ]] && \
            [[ "$IFACE" != "lo" ]] && \
            [[ -x /usr/local/bin/nic-capture-setup.sh ]] && \
            /usr/local/bin/nic-capture-setup.sh "$IFACE" >/dev/null 2>&1 || true

        done # loop over capture interfaces

      fi # capture interface(s) defined

      if (( ${#PROG_GROUP[@]} )); then
        GROUP_PROGS="$(join_by , "${PROG_GROUP[@]}")"
        # define group config file
        echo "[group:$PROG]" >> "$CONFIG_DIR"/"$CAPTURE_GROUPS_FILE"
        echo "programs=$GROUP_PROGS" >> "$CONFIG_DIR"/"$CAPTURE_GROUPS_FILE"
        echo "" >> "$CONFIG_DIR"/"$CAPTURE_GROUPS_FILE"
      fi

    done # loop over capture programs
  fi # config dir exists
}

SetCaptureCapabilities
CreateCaptureConfigs

if [[ -z $PCAP_ROTATE_SECONDS ]] && [[ -n $PCAP_ROTATE_MINUTES ]]; then
  export PCAP_ROTATE_SECONDS=$(echo "$PCAP_ROTATE_MINUTES * 60" | bc)
fi

supervisord -c "$CONFIG_FILE" -n
