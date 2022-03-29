#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

if [[ -n $SUPERVISOR_PATH ]] && [[ -n $CAPTURE_INTERFACE ]] && [[ -r "$SUPERVISOR_PATH"/suricata/suricata.yaml ]]; then

  SURICATA_CONFIG_FILE="$SUPERVISOR_PATH"/suricata/suricata.yaml

  # set up capture parameters
  /usr/bin/yq eval --inplace 'del(."capture")' "$SURICATA_CONFIG_FILE"
  /usr/bin/yq eval --inplace ".\"capture\"={\"disable-offloading\":\"${SURICATA_CAPTURE_DISABLE_OFFLOADING:-true}\",\"checksum-validation\":\"${SURICATA_CAPTURE_CHECKSUM_VALIDATION:-none}\"}" "$SURICATA_CONFIG_FILE"

  # write interface names and settings for af-packet into suricata configuration file
  IFS=","
  NEXT_CLUSTER_ID=99
  AFPACKET_INTERFACES_YAML_SOURCE=$(for IFACE_NAME in $CAPTURE_INTERFACE; do echo -n "{\"interface\":\"$IFACE_NAME\",\"cluster-id\":$((NEXT_CLUSTER_ID--)),\"block-size\":${SURICATA_AF_PACKET_BLOCK_SIZE:-32768},\"block-timeout\":${SURICATA_AF_PACKET_BLOCK_TIMEOUT:-10},\"bpf-filter\":\"${CAPTURE_FILTER}\",\"buffer-size\":${SURICATA_AF_PACKET_BUFFER_SIZE:-32768},\"checksum-checks\":\"${SURICATA_AF_PACKET_CHECKSUM_CHECKS:-kernel}\",\"cluster-type\":\"${SURICATA_AF_PACKET_CLUSTER_TYPE:-cluster_flow}\",\"defrag\":\"${SURICATA_AF_PACKET_DEFRAG:-yes}\",\"mmap-locked\":\"${SURICATA_AF_PACKET_MMAP_LOCKED:-no}\",\"ring-size\":${SURICATA_AF_PACKET_RING_SIZE:-2048},\"threads\":\"${SURICATA_AF_PACKET_IFACE_THREADS:-auto}\",\"tpacket-v3\":\"${SURICATA_AF_PACKET_TPACKET_V3:-yes}\",\"use-emergency-flush\":\"${SURICATA_AF_PACKET_EMERGENCY_FLUSH:-no}\",\"use-mmap\":\"${SURICATA_AF_PACKET_USE_MMAP:-yes}\"},"; done)
  unset IFS
  /usr/bin/yq eval --inplace 'del(."af-packet")' "$SURICATA_CONFIG_FILE"
  /usr/bin/yq eval --inplace ".\"af-packet\"=[${AFPACKET_INTERFACES_YAML_SOURCE}{\"interface\":\"default\"}]" "$SURICATA_CONFIG_FILE"

  # disable all outputs, then enable only the ones we want
  /usr/bin/yq --inplace '.stats.enabled="no"' "$SURICATA_CONFIG_FILE"
  for OUTPUT in $(/usr/bin/yq -M '... comments=""' "$SURICATA_CONFIG_FILE" | /usr/bin/yq -M '(.outputs.[]|keys)' | sed "s/^- //"); do
    /usr/bin/yq --inplace "(.outputs.[] | select(.$OUTPUT))[].enabled = \"no\"" "$SURICATA_CONFIG_FILE"
  done
  for OUTPUT in eve-log; do
    /usr/bin/yq --inplace "(.outputs.[] | select(.$OUTPUT))[].enabled = \"yes\"" "$SURICATA_CONFIG_FILE"
  done
  /usr/bin/yq --inplace '(.outputs.[] | select(.eve-log))[].community-id = true' "$SURICATA_CONFIG_FILE"

  # other global settings
  /usr/bin/yq eval --inplace 'del(."run-as")' "$SURICATA_CONFIG_FILE"
  /usr/bin/yq eval --inplace 'del(."coredump")' "$SURICATA_CONFIG_FILE"
  /usr/bin/yq eval --inplace ".\"coredump\"={\"max-dump\":0}" "$SURICATA_CONFIG_FILE"
  /usr/bin/yq eval --inplace 'del(."default-rule-path")' "$SURICATA_CONFIG_FILE"
  /usr/bin/yq eval --inplace ".\"default-rule-path\"=\"${SURICATA_MANAGED_RULES_DIR:-/var/lib/suricata/rules}\"" "$SURICATA_CONFIG_FILE"
  /usr/bin/yq eval --inplace 'del(."unix-command")' "$SURICATA_CONFIG_FILE"
  /usr/bin/yq eval --inplace ".\"unix-command\"={\"enabled\":\"yes\",\"filename\":\"$SUPERVISOR_PATH/suricata/suricata-command.socket\"}" "$SURICATA_CONFIG_FILE"

  # restore YAML head that would have been stripped by yq
  head -n 2 "$SURICATA_CONFIG_FILE" | grep -Pzq '^%YAML.*\n---' || (echo -e "%YAML 1.1\n---\n" ; cat "$SURICATA_CONFIG_FILE") | sponge "$SURICATA_CONFIG_FILE"

  # remove the pidfile and command file for a new run (in case they weren't cleaned up before)
  rm -f "$SUPERVISOR_PATH"/suricata/suricata.pid "$SUPERVISOR_PATH"/suricata/suricata-command.socket
fi
