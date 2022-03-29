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

  # disable all outputs, then enable only the ones we want
  for OUTPUT in $(/usr/bin/yq -M '... comments=""' "$SURICATA_CONFIG_FILE" | /usr/bin/yq -M '(.outputs.[]|keys)' | sed "s/^- //"); do
    /usr/bin/yq --inplace "(.outputs.[] | select(.$OUTPUT))[].enabled = \"no\"" "$SURICATA_CONFIG_FILE"
  done
  for OUTPUT in eve-log; do
    /usr/bin/yq --inplace "(.outputs.[] | select(.$OUTPUT))[].enabled = \"yes\"" "$SURICATA_CONFIG_FILE"
  done
  /usr/bin/yq --inplace '(.outputs.[] | select(.eve-log))[].community-id = true' "$SURICATA_CONFIG_FILE"

  head -n 2 "$SURICATA_CONFIG_FILE" | grep -Pzq '^%YAML.*\n---' || (echo -e "%YAML 1.1\n---\n" ; cat "$SURICATA_CONFIG_FILE") | sponge "$SURICATA_CONFIG_FILE"

  # make sure interface flags are set appropriately for capture
  IFS=","
  for IFACE_NAME in $CAPTURE_INTERFACE; do
    sudo --non-interactive /usr/local/bin/nic-capture-setup.sh "$IFACE_NAME" >/dev/null 2>&1
  done
  unset IFS

fi
