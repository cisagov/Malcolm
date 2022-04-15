#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

# use YQ to modify suricata.yaml according to many environment variables

#
# suricata.yaml: https://suricata.readthedocs.io/en/suricata-6.0.0/configuration/suricata-yaml.html
#                https://github.com/OISF/suricata/blob/master/suricata.yaml.in
#
# list the vars used here: grep -Po "\bSURICATA_\w+" suricata_config_populate.sh | sort -u
#

function restore_suricata_yaml_header() {
  CONFIG_FILE="$1"
  # restore YAML head that would have been stripped by yq
  head -n 2 "$CONFIG_FILE" | grep -Pzq '^%YAML.*\n---' || (echo -e "%YAML 1.1\n---\n" ; cat "$CONFIG_FILE") | sponge "$CONFIG_FILE"
}

if [[ -z $SURICATA_CONFIG_FILE ]] && [[ -n $SUPERVISOR_PATH ]] && [[ -r "$SUPERVISOR_PATH"/suricata/suricata.yaml ]]; then
  SURICATA_CONFIG_FILE="$SUPERVISOR_PATH"/suricata/suricata.yaml
fi

if [[ -n $SURICATA_CONFIG_FILE ]]; then

  # network variables
  yq --inplace ".vars.address-groups.HOME_NET = \"${SURICATA_HOME_NET:-[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace ".vars.address-groups.EXTERNAL_NET = \"${SURICATA_EXTERNAL_NET:-!\$HOME_NET}\"" "$SURICATA_CONFIG_FILE"

  # port groups
  yq --inplace ".vars.port-groups.HTTP_PORTS = \"${SURICATA_HTTP_PORTS:-80}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace ".vars.port-groups.SHELLCODE_PORTS = \"${SURICATA_SHELLCODE_PORTS:-!80}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace ".vars.port-groups.ORACLE_PORTS = \"${SURICATA_ORACLE_PORTS:-1521}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace ".vars.port-groups.SSH_PORTS = \"${SURICATA_SSH_PORTS:-22}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace ".vars.port-groups.DNP3_PORTS = \"${SURICATA_DNP3_PORTS:-20000}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace ".vars.port-groups.MODBUS_PORTS = \"${SURICATA_MODBUS_PORTS:-502}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace ".vars.port-groups.FILE_DATA_PORTS = \"${SURICATA_FILE_DATA_PORTS:-[\$HTTP_PORTS,110,143]}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace ".vars.port-groups.FTP_PORTS = \"${SURICATA_FTP_PORTS:-21}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace ".vars.port-groups.GENEVE_PORTS = \"${SURICATA_GENEVE_PORTS:-6081}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace ".vars.port-groups.VXLAN_PORTS = \"${SURICATA_VXLAN_PORTS:-4789}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace ".vars.port-groups.TEREDO_PORTS = \"${SURICATA_TEREDO_PORTS:-3544}\"" "$SURICATA_CONFIG_FILE"

  # set up capture parameters
  yq eval --inplace 'del(."capture")' "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".\"capture\"={\"disable-offloading\":\"${SURICATA_CAPTURE_DISABLE_OFFLOADING:-true}\",\"checksum-validation\":\"${SURICATA_CAPTURE_CHECKSUM_VALIDATION:-none}\"}" "$SURICATA_CONFIG_FILE"

  if [[ -n $CAPTURE_INTERFACE ]]; then
    # write interface names and settings for af-packet into suricata configuration file
    IFS=","
    NEXT_CLUSTER_ID=99
    AFPACKET_INTERFACES_YAML_SOURCE=$(for IFACE_NAME in $CAPTURE_INTERFACE; do echo -n "{\"interface\":\"$IFACE_NAME\",\"cluster-id\":$((NEXT_CLUSTER_ID--)),\"block-size\":${SURICATA_AF_PACKET_BLOCK_SIZE:-32768},\"block-timeout\":${SURICATA_AF_PACKET_BLOCK_TIMEOUT:-10},\"bpf-filter\":\"${CAPTURE_FILTER}\",\"buffer-size\":${SURICATA_AF_PACKET_BUFFER_SIZE:-32768},\"checksum-checks\":\"${SURICATA_AF_PACKET_CHECKSUM_CHECKS:-kernel}\",\"cluster-type\":\"${SURICATA_AF_PACKET_CLUSTER_TYPE:-cluster_flow}\",\"defrag\":\"${SURICATA_AF_PACKET_DEFRAG:-yes}\",\"mmap-locked\":\"${SURICATA_AF_PACKET_MMAP_LOCKED:-no}\",\"ring-size\":${SURICATA_AF_PACKET_RING_SIZE:-2048},\"threads\":\"${SURICATA_AF_PACKET_IFACE_THREADS:-auto}\",\"tpacket-v3\":\"${SURICATA_AF_PACKET_TPACKET_V3:-yes}\",\"use-emergency-flush\":\"${SURICATA_AF_PACKET_EMERGENCY_FLUSH:-no}\",\"use-mmap\":\"${SURICATA_AF_PACKET_USE_MMAP:-yes}\"},"; done)
    unset IFS
    yq eval --inplace 'del(."af-packet")' "$SURICATA_CONFIG_FILE"
    yq eval --inplace ".\"af-packet\"=[${AFPACKET_INTERFACES_YAML_SOURCE}{\"interface\":\"default\"}]" "$SURICATA_CONFIG_FILE"
  fi

  # disable all outputs, then enable only the ones we want
  for OUTPUT in $(yq -M '... comments=""' "$SURICATA_CONFIG_FILE" | yq -M '(.outputs.[]|keys)' | sed "s/^- //"); do
    yq --inplace "(.outputs.[] | select(.$OUTPUT))[].enabled = \"no\"" "$SURICATA_CONFIG_FILE"
  done
  for OUTPUT in eve-log; do
    yq --inplace "(.outputs.[] | select(.$OUTPUT))[].enabled = \"yes\"" "$SURICATA_CONFIG_FILE"
  done
  yq --inplace '(.outputs.[] | select(.eve-log))[].community-id = true' "$SURICATA_CONFIG_FILE"
  yq --inplace '(.outputs.[] | select(.eve-log))[].pcap-file = true' "$SURICATA_CONFIG_FILE"

  # don't dump payload, we can pivot to the payload with Arkime via community-id
  for DUMPER in payload payload-printable packet http-body http-body-printable; do
    yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.alert))[].$DUMPER = \"no\"" "$SURICATA_CONFIG_FILE"
  done

  # toggle logging for various protocols
  PROTOCOLS_ENABLED=(
    "anomaly;${SURICATA_ANOMALY_ENABLED:-yes};;"
    "dcerpc;${SURICATA_DCERPC_ENABLED:-yes};;"
    "dhcp;${SURICATA_DHCP_ENABLED:-yes};;"
    "dnp3;${SURICATA_DNP3_ENABLED:-yes};${SURICATA_DNP3_PORTS:-20000};"
    "dns.tcp;${SURICATA_DNS_ENABLED:-yes};${SURICATA_DNS_PORTS:-53};"
    "dns.udp;${SURICATA_DNS_ENABLED:-yes};${SURICATA_DNS_PORTS:-53};"
    "enip;${SURICATA_ENIP_ENABLED:-yes};${SURICATA_ENIP_PORTS:-44818};${SURICATA_ENIP_PORTS:-44818}"
    "files;${SURICATA_FILES_ENABLED:-yes};;"
    "ftp;${SURICATA_FTP_ENABLED:-yes};;"
    "http2;${SURICATA_HTTP2_ENABLED:-no};;"
    "http;${SURICATA_HTTP_ENABLED:-yes};;"
    "ikev2;${SURICATA_IKEV2_ENABLED:-yes};;"
    "imap;${SURICATA_IMAP_ENABLED:-detection-only};;"
    "krb5;${SURICATA_KRB5_ENABLED:-yes};;"
    "modbus;${SURICATA_MODBUS_ENABLED:-yes};${SURICATA_MODBUS_PORTS:-502};"
    "mqtt;${SURICATA_MQTT_ENABLED:-yes};;"
    "nfs;${SURICATA_NFS_ENABLED:-yes};;"
    "ntp;${SURICATA_NTP_ENABLED:-yes};;"
    "rdp;${SURICATA_RDP_ENABLED:-yes};;"
    "rfb;${SURICATA_RFB_ENABLED:-yes};${SURICATA_RFB_PORTS:-5900,5901,5902,5903,5904,5905,5906,5907,5908,5909};"
    "sip;${SURICATA_SIP_ENABLED:-yes};;"
    "smb;${SURICATA_SMB_ENABLED:-yes};${SURICATA_SMB_PORTS:-139,445};"
    "smtp;${SURICATA_SMTP_ENABLED:-yes};;"
    "snmp;${SURICATA_SNMP_ENABLED:-yes};;"
    "ssh;${SURICATA_SSH_ENABLED:-yes};;"
    "tftp;${SURICATA_TFTP_ENABLED:-yes};;"
    "tls;${SURICATA_TLS_ENABLED:-yes};${SURICATA_TLS_PORTS:-443};"
  )
  for i in ${PROTOCOLS_ENABLED[@]}; do
    PROTOCOL_FULL="$(echo "$i" | cut -d';' -f1)"
    PROTOCOL_ONLY="$(echo "$PROTOCOL_FULL" | cut -d'.' -f1)"
    ENABLED="$(echo "$i" | cut -d';' -f2)"
    DPORTS="$(echo "$i" | cut -d';' -f3)"
    SPORTS="$(echo "$i" | cut -d';' -f4)"
    yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.$PROTOCOL_ONLY))[].enabled = \"$ENABLED\"" "$SURICATA_CONFIG_FILE"
    yq --inplace ".app-layer.protocols.$PROTOCOL_FULL.enabled = \"$ENABLED\"" "$SURICATA_CONFIG_FILE"
    if [[ -n $DPORTS ]]; then
      yq --inplace ".app-layer.protocols.$PROTOCOL_FULL.detection-ports.dp = \"$DPORTS\"" "$SURICATA_CONFIG_FILE"
    fi
    if [[ -n $SPORTS ]]; then
      yq --inplace ".app-layer.protocols.$PROTOCOL_FULL.detection-ports.sp = \"$SPORTS\"" "$SURICATA_CONFIG_FILE"
    fi
  done

  DECODERS_ENABLED=(
    "teredo;${SURICATA_TEREDO_ENABLED:-true};${SURICATA_TEREDO_PORTS:-3544}"
    "vxlan;${SURICATA_VXLAN_ENABLED:-true};${SURICATA_VXLAN_PORTS:-4789}"
    "geneve;${SURICATA_GENEVE_ENABLED:-true};${SURICATA_GENEVE_PORTS:-6081}"
  )
  for i in ${DECODERS_ENABLED[@]}; do
    DECODER="$(echo "$i" | cut -d';' -f1)"
    ENABLED="$(echo "$i" | cut -d';' -f2)"
    PORTS="$(echo "$i" | cut -d';' -f3)"
    yq --inplace ".decoder.$DECODER.enabled = \"$ENABLED\"" "$SURICATA_CONFIG_FILE"
    yq --inplace ".decoder.$DECODER.ports = $PORTS" "$SURICATA_CONFIG_FILE"
  done

  # anomaly
  yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.anomaly))[].types.decode = \"${SURICATA_ANOMALY_DECODE:-no}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.anomaly))[].types.stream = \"${SURICATA_ANOMALY_STREAM:-no}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.anomaly))[].types.applayer = \"${SURICATA_ANOMALY_APPLAYER:-yes}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.anomaly))[].types.packethdr = \"${SURICATA_ANOMALY_PACKETHDR:-no}\"" "$SURICATA_CONFIG_FILE"

  # dns
  yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.dns))[].requests = \"${SURICATA_DNS_REQUESTS:-yes}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.dns))[].responses = \"${SURICATA_DNS_RESPONSES:-yes}\"" "$SURICATA_CONFIG_FILE"
  if [[ -n $SURICATA_DNS_FORMATS ]]; then
    yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.dns))[].formats = ${SURICATA_DNS_FORMATS}" "$SURICATA_CONFIG_FILE"
  else
    yq --inplace "del ((.outputs.[] | select(.eve-log))[].types[] | select(.dns))[].formats" "$SURICATA_CONFIG_FILE"
  fi
  if [[ -n $SURICATA_DNS_TYPES ]]; then
    yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.dns))[].types = ${SURICATA_DNS_TYPES}" "$SURICATA_CONFIG_FILE"
  else
    yq --inplace "del ((.outputs.[] | select(.eve-log))[].types[] | select(.dns))[].types" "$SURICATA_CONFIG_FILE"
  fi

  # dhcp
  yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.dhcp))[].extended = \"${SURICATA_DHCP_EXTENDED:-no}\"" "$SURICATA_CONFIG_FILE"

  # http
  yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.http))[].extended = \"${SURICATA_HTTP_EXTENDED:-yes}\"" "$SURICATA_CONFIG_FILE"
  if [[ -n $SURICATA_HTTP_CUSTOM ]]; then
    yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.http))[].custom = ${SURICATA_HTTP_CUSTOM}" "$SURICATA_CONFIG_FILE"
  else
    yq --inplace "del ((.outputs.[] | select(.eve-log))[].types[] | select(.http))[].custom" "$SURICATA_CONFIG_FILE"
  fi
  if [[ -n $SURICATA_HTTP_DUMP_ALL_HEADERS ]]; then
    yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.http))[].dump-all-headers = \"${SURICATA_HTTP_DUMP_ALL_HEADERS}\"" "$SURICATA_CONFIG_FILE"
  else
    yq --inplace "del ((.outputs.[] | select(.eve-log))[].types[] | select(.http))[].dump-all-headers" "$SURICATA_CONFIG_FILE"
  fi

  # files
  yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.files))[].force-magic = \"${SURICATA_FILES_FORCE_MAGIC:-no}\"" "$SURICATA_CONFIG_FILE"
  if [[ -n $SURICATA_FILES_FORCE_HASH ]]; then
    yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.files))[].force-hash = ${SURICATA_FILES_FORCE_HASH}" "$SURICATA_CONFIG_FILE"
  else
    yq --inplace "del ((.outputs.[] | select(.eve-log))[].types[] | select(.files))[].force-hash" "$SURICATA_CONFIG_FILE"
  fi

  # ftp
  yq --inplace ".app-layer.protocols.ftp.memcap = \"${SURICATA_FTP_MEMCAP:-64mb}\"" "$SURICATA_CONFIG_FILE"

  # modbus
  yq --inplace ".app-layer.protocols.modbus.stream-depth = ${SURICATA_MODBUS_STREAM_DEPTH:-0}" "$SURICATA_CONFIG_FILE"

  # mqtt
  yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.mqtt))[].passwords = \"${SURICATA_MQTT_PASSWORDS:-no}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace ".app-layer.protocols.mqtt.max-msg-length = \"${SURICATA_MQTT_MAX_MSG_LENGTH:-1mb}\"" "$SURICATA_CONFIG_FILE"

  # smb
  yq --inplace ".app-layer.protocols.smb.stream-depth = ${SURICATA_SMB_STREAM_DEPTH:-0}" "$SURICATA_CONFIG_FILE"

  # smtp
  yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.smtp))[].extended = \"${SURICATA_SMTP_EXTENDED:-yes}\"" "$SURICATA_CONFIG_FILE"
  if [[ -n $SURICATA_SMTP_CUSTOM ]]; then
    yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.smtp))[].custom = ${SURICATA_SMTP_CUSTOM}" "$SURICATA_CONFIG_FILE"
  else
    yq --inplace "del ((.outputs.[] | select(.eve-log))[].types[] | select(.smtp))[].custom" "$SURICATA_CONFIG_FILE"
  fi
  if [[ -n $SURICATA_SMTP_MD5 ]]; then
    yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.md5))[].custom = ${SURICATA_SMTP_MD5}" "$SURICATA_CONFIG_FILE"
  else
    yq --inplace "del ((.outputs.[] | select(.eve-log))[].types[] | select(.md5))[].custom" "$SURICATA_CONFIG_FILE"
  fi
  yq --inplace ".app-layer.protocols.smtp.raw-extraction = \"${SURICATA_SMTP_RAW_EXTRACTION:-no}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace ".app-layer.protocols.smtp.mime.decode-mime = \"${SURICATA_SMTP_DECODE_MIME:-no}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace ".app-layer.protocols.smtp.mime.decode-base64 = \"${SURICATA_SMTP_DECODE_BASE64:-no}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace ".app-layer.protocols.smtp.mime.decode-quoted-printable = \"${SURICATA_SMTP_DECODE_QUOTED_PRINTABLE:-no}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace ".app-layer.protocols.smtp.mime.header-value-depth = ${SURICATA_SMTP_HEADER_VALUE_DEPTH:-2000}" "$SURICATA_CONFIG_FILE"
  yq --inplace ".app-layer.protocols.smtp.mime.extract-urls = \"${SURICATA_SMTP_EXTRACT_URLS:-yes}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace ".app-layer.protocols.smtp.mime.body-md5 = \"${SURICATA_SMTP_BODY_MD5:-no}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace ".app-layer.protocols.smtp.inspected-tracker.content-limit = ${SURICATA_SMTP_INSPECTED_TRACKER_CONTENT_LIMIT:-100000}" "$SURICATA_CONFIG_FILE"
  yq --inplace ".app-layer.protocols.smtp.inspected-tracker.content-inspect-min-size = ${SURICATA_SMTP_INSPECTED_TRACKER_CONTENT_INSPECT_MIN_SIZE:-32768}" "$SURICATA_CONFIG_FILE"
  yq --inplace ".app-layer.protocols.smtp.inspected-tracker.content-inspect-window = ${SURICATA_SMTP_INSPECTED_TRACKER_CONTENT_INSPECT_WINDOW:-4096}" "$SURICATA_CONFIG_FILE"

  # ssh
  yq --inplace ".app-layer.protocols.ssh.hassh = \"${SURICATA_SSH_HASSH:-yes}\"" "$SURICATA_CONFIG_FILE"

  # tls
  yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.tls))[].extended = \"${SURICATA_TLS_EXTENDED:-yes}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.tls))[].session-resumption = \"${SURICATA_TLS_SESSION_RESUMPTION:-no}\"" "$SURICATA_CONFIG_FILE"
  if [[ -n $SURICATA_TLS_CUSTOM ]]; then
    yq --inplace "((.outputs.[] | select(.eve-log))[].types[] | select(.tls))[].custom = ${SURICATA_TLS_CUSTOM}" "$SURICATA_CONFIG_FILE"
  else
    yq --inplace "del ((.outputs.[] | select(.eve-log))[].types[] | select(.tls))[].custom" "$SURICATA_CONFIG_FILE"
  fi
  yq --inplace ".app-layer.protocols.tls.ja3-fingerprints = \"${SURICATA_TLS_JA3:-auto}\"" "$SURICATA_CONFIG_FILE"
  yq --inplace ".app-layer.protocols.tls.encryption-handling = \"${SURICATA_TLS_ENCRYPTION_HANDLING:-bypass}\"" "$SURICATA_CONFIG_FILE"

  # other global settings
  yq eval --inplace ".runmode = \"${SURICATA_RUNMODE:-autofp}\"" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".autofp-scheduler = \"${SURICATA_AUTOFP_SCHEDULER:-hash}\"" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".default-packet-size = ${SURICATA_PACKET_SIZE:-1514}" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".asn1-max-frames = ${SURICATA_ASN1_MAX_FRAMES:-256}" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".pcre.match-limit = ${SURICATA_PCRE_MATCH_LIMIT:-3500}" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".pcre.match-limit-recursion = ${SURICATA_PCRE_RECURSION:-1500}" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".defrag.memcap = \"${SURICATA_DEFRAG_MEMCAP:-32mb}\"" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".defrag.hash-size = ${SURICATA_DEFRAG_HASH_SIZE:-65536}" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".defrag.trackers = ${SURICATA_DEFRAG_TRACKERS:-65535}" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".defrag.max-frags = ${SURICATA_DEFRAG_MAX_FRAGS:-65535}" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".defrag.prealloc = \"${SURICATA_DEFRAG_PREALLOC:-yes}\"" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".defrag.timeout = ${SURICATA_DEFRAG_TIMEOUT:-60}" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".flow.memcap = \"${SURICATA_FLOW_MEMCAP:-128mb}\"" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".flow.hash-size = ${SURICATA_FLOW_HASH_SIZE:-65536}" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".flow.prealloc = ${SURICATA_FLOW_PREALLOC:-10000}" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".flow.emergency-recovery = ${SURICATA_FLOW_EMERGENCY_RECOVERY:-30}" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".vlan.use-for-tracking = \"${SURICATA_VLAN_USE_FOR_TRACKING:-true}\"" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".stream.memcap = \"${SURICATA_STREAM_MEMCAP:-64mb}\"" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".stream.checksum-validation = \"${SURICATA_STREAM_CHECKSUM_VALIDATION:-yes}\"" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".stream.inline = \"${SURICATA_STREAM_INLINE:-auto}\"" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".stream.reassembly.memcap = \"${SURICATA_STREAM_REASSEMBLY_MEMCAP:-256mb}\"" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".stream.reassembly.depth = \"${SURICATA_STREAM_REASSEMBLY_DEPTH:-1mb}\"" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".stream.reassembly.toserver-chunk-size = ${SURICATA_STREAM_REASSEMBLY_TOSERVER_CHUNK_SIZE:-2560}" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".stream.reassembly.toclient-chunk-size = ${SURICATA_STREAM_REASSEMBLY_TOCLIENT_CHUNK_SIZE:-2560}" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".stream.reassembly.randomize-chunk-size = \"${SURICATA_STREAM_REASSEMBLY_RANDOMIZE_CHUNK_SIZE:-yes}\"" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".host.memcap = \"${SURICATA_HOST_MEMCAP:-32mb}\"" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".host.hash-size = ${SURICATA_HOST_HASH_SIZE:-4096}" "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".host.prealloc = ${SURICATA_HOST_PREALLOC:-1000}" "$SURICATA_CONFIG_FILE"
  yq eval --inplace 'del(."run-as")' "$SURICATA_CONFIG_FILE"
  yq eval --inplace 'del(."coredump")' "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".\"coredump\"={\"max-dump\":0}" "$SURICATA_CONFIG_FILE"
  yq eval --inplace 'del(."default-rule-path")' "$SURICATA_CONFIG_FILE"
  yq eval --inplace ".\"default-rule-path\"=\"${SURICATA_MANAGED_RULES_DIR:-/var/lib/suricata/rules}\"" "$SURICATA_CONFIG_FILE"

  if [[ -n $SUPERVISOR_PATH ]]; then
    yq eval --inplace 'del(."unix-command")' "$SURICATA_CONFIG_FILE"
    yq eval --inplace ".\"unix-command\"={\"enabled\":\"yes\",\"filename\":\"$SUPERVISOR_PATH/suricata/suricata-command.socket\"}" "$SURICATA_CONFIG_FILE"
  fi

  # validate suricata config before setting our final settings
  TEST_CONFIG_WORKDIR="$(mktemp -d)"
  pushd "$TEST_CONFIG_WORKDIR"/ >/dev/null 2>&1
  yq --inplace '.stats.enabled="yes"' "$SURICATA_CONFIG_FILE"
  yq eval --inplace 'del(."rule-files")' "$SURICATA_CONFIG_FILE"
  restore_suricata_yaml_header "$SURICATA_CONFIG_FILE"
  suricata ${SURICATA_TEST_CONFIG_VERBOSITY:-} -c "$SURICATA_CONFIG_FILE" -T >&2
  popd >/dev/null 2>&1
  rm -rf "$TEST_CONFIG_WORKDIR"/

  # finalize the config file
  yq --inplace '.stats.enabled="no"' "$SURICATA_CONFIG_FILE"
  yq eval --inplace 'del(."rule-files")' "$SURICATA_CONFIG_FILE"
  if [[ -n $SURICATA_CUSTOM_RULES_DIR ]]; then
    yq eval --inplace ".\"rule-files\"=[\"suricata.rules\", \"$SURICATA_CUSTOM_RULES_DIR/*.rules\"]" "$SURICATA_CONFIG_FILE"
  else
    yq eval --inplace ".\"rule-files\"=[\"suricata.rules\"]" "$SURICATA_CONFIG_FILE"
  fi
  restore_suricata_yaml_header "$SURICATA_CONFIG_FILE"

  if [[ -n $SUPERVISOR_PATH ]]; then
    # remove the pidfile and command file for a new run (in case they weren't cleaned up before)
    rm -f "$SUPERVISOR_PATH"/suricata/suricata.pid "$SUPERVISOR_PATH"/suricata/suricata-command.socket
  fi
fi
