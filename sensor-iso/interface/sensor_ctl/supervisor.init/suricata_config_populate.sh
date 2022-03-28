#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

if [[ -n $SUPERVISOR_PATH ]] && [[ -n $CAPTURE_INTERFACE ]] && [[ -r "$SUPERVISOR_PATH"/suricata/suricata.yaml ]]; then

  SURICATA_CONFIG_FILE="$SUPERVISOR_PATH"/suricata/suricata.yaml

  # write interface names for af-packet into suricata configuration file
  IFS=","
  AFPACKET_INTERFACES_YAML_SOURCE=$(for IFACE_NAME in $CAPTURE_INTERFACE; do echo -n "{\"interface\":\"$IFACE_NAME\",\"threads\":\"auto\",\"tpacket-v3\":\"yes\",\"cluster-id\":99,\"cluster-type\":\"cluster_flow\",\"defrag\":\"yes\"},"; done)
  unset IFS
  /usr/bin/yq eval --inplace 'del(."af-packet")' "$SURICATA_CONFIG_FILE"
  /usr/bin/yq eval --inplace ".\"af-packet\"=[${AFPACKET_INTERFACES_YAML_SOURCE}{\"interface\":\"default\"}]" "$SURICATA_CONFIG_FILE"

  # make sure interface flags are set appropriately for capture
  IFS=","
  for IFACE_NAME in $CAPTURE_INTERFACE; do
    sudo --non-interactive /usr/local/bin/nic-capture-setup.sh "$IFACE_NAME" >/dev/null 2>&1
  done
  unset IFS

fi
