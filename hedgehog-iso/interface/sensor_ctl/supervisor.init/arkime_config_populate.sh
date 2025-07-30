#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

export ARKIME_HTTPS_FLAG=""
ARKIME_WISE_PLUGIN=${ARKIME_WISE_PLUGIN-"false"}
ARKIME_WISE_URL=${ARKIME_WISE_URL-"127.0.0.1"}


if [[ -n $SUPERVISOR_PATH ]] && [[ -r "$SUPERVISOR_PATH"/arkime/config.ini ]]; then

  ARKIME_CONFIG_FILE="$SUPERVISOR_PATH"/arkime/config.ini

  # capture interface(s)
  if [[ -n $CAPTURE_INTERFACE ]]; then
    # in config.ini multiple interfaces are separated by ;
    ARKIME_CAPTURE_INTERFACE="$(echo "$CAPTURE_INTERFACE" | sed "s/,/;/g")"
    # place capture interfaces in the config file
    sed -r -i "s|(interface)\s*=\s*.*|\1=$ARKIME_CAPTURE_INTERFACE|" "$ARKIME_CONFIG_FILE"
  fi

  # stick OpenSearch connection information in arkime config file
  if [[ -n $OS_PROTOCOL ]] && [[ -n $OS_HOST ]]; then

    # build OpenSearch URL for moloch-capture
    ARKIME_ELASTICSEARCH="${OS_PROTOCOL}://"

    if [[ -n $OS_USERNAME ]] && [[ -n $OS_PASSWORD ]]; then
      ARKIME_ELASTICSEARCH+="${OS_USERNAME}:${OS_PASSWORD}@"
    fi

    ARKIME_ELASTICSEARCH+="${OS_HOST}"

    if [[ -n $OS_PORT ]]; then
      ARKIME_ELASTICSEARCH+=":${OS_PORT}"
    else
      ARKIME_ELASTICSEARCH+=":9200"
    fi

    # place the URL in the config file
    sed -r -i "s|(elasticsearch)\s*=\s*.*|\1=$ARKIME_ELASTICSEARCH|" "$ARKIME_CONFIG_FILE"
  fi

  if [[ -n $ARKIME_VIEWER_PORT ]]; then
    sed -r -i "s/(viewPort)\s*=\s*.*/\1=$ARKIME_VIEWER_PORT/" "$ARKIME_CONFIG_FILE"
  fi

  if [[ -n $ARKIME_PASSWORD_SECRET ]]; then
    # place the Arkime viewer cluster password hash in the config file
    sed -r -i "s|(passwordSecret)\s*=\s*.*|\1=$ARKIME_PASSWORD_SECRET|" "$ARKIME_CONFIG_FILE"
  fi

  # if SSL certificate verification is turned off, supply the --insecure flag
  if [[ -n $OS_SSL_VERIFY ]] && [ "$OS_SSL_VERIFY" = none ]; then
    export ARKIME_HTTPS_FLAG="--insecure"
  fi

  # convert pcap rotation size units (MB to GB) and stick in config file
  if [[ -n $PCAP_ROTATE_MEGABYTES ]]; then
    PCAP_ROTATE_GIGABYTES=$(awk "BEGIN { printf \"%.4f\", $PCAP_ROTATE_MEGABYTES/1024 }")
    sed -r -i "s/(maxFileSizeG)\s*=\s*.*/\1=$PCAP_ROTATE_GIGABYTES/" "$ARKIME_CONFIG_FILE"
  fi

  # convert pcap rotation time units (sec to min) and stick in config file
  if [[ -n $PCAP_ROTATE_SECONDS ]]; then
    PCAP_ROTATE_MINUTES=$(echo "($PCAP_ROTATE_SECONDS + 60 - 1)/60" | bc)
    sed -r -i "s/(maxFileTimeM)\s*=\s*.*/\1=$PCAP_ROTATE_MINUTES/" "$ARKIME_CONFIG_FILE"
  fi

  # pcap deletion threshold
  if [[ -n $ARKIME_FREESPACEG ]]; then
    sed -r -i "s/(freeSpaceG)\s*=\s*.*/\1=$ARKIME_FREESPACEG/" "$ARKIME_CONFIG_FILE"
  fi
  # pcap compression
  COMPRESSION_TYPE="${ARKIME_COMPRESSION_TYPE:-zstd}"
  COMPRESSION_LEVEL="${ARKIME_COMPRESSION_LEVEL:-3}"
  sed -r -i "s/(simpleCompression)\s*=\s*.*/\1=$COMPRESSION_TYPE/" "$ARKIME_CONFIG_FILE"
  if [[ "$COMPRESSION_TYPE" == "zstd" ]]; then
    sed -r -i "s/(simpleZstdLevel)\s*=\s*.*/\1=$COMPRESSION_LEVEL/" "$ARKIME_CONFIG_FILE"
  elif [[ "$COMPRESSION_TYPE" == "gzip" ]]; then
    sed -r -i "s/(simpleGzipLevel)\s*=\s*.*/\1=$COMPRESSION_LEVEL/" "$ARKIME_CONFIG_FILE"
  fi

  # capture performance-related settings
  DB_BULK_SIZE="${ARKIME_DB_BULK_SIZE:-4000000}"
  MAGIC_MODE="${ARKIME_MAGIC_MODE:-basic}"
  MAX_PACKETS_IN_QUEUE="${ARKIME_MAX_PACKETS_IN_QUEUE:-300000}"
  PACKET_THREADS="${ARKIME_PACKET_THREADS:-2}"
  PCAP_READ_METHOD="${ARKIME_PCAP_READ_METHOD:-tpacketv3}"
  PCAP_WRITE_METHOD="${ARKIME_PCAP_WRITE_METHOD:-simple}"
  PCAP_WRITE_SIZE="${ARKIME_PCAP_WRITE_SIZE:-2560000}"
  TPACKETV3_BLOCK_SIZE="${ARKIME_TPACKETV3_BLOCK_SIZE:-8388608}"
  TPACKETV3_NUM_THREADS="${ARKIME_TPACKETV3_NUM_THREADS:-2}"

  sed -r -i "s/(dbBulkSize)\s*=\s*.*/\1=$DB_BULK_SIZE/" "$ARKIME_CONFIG_FILE"
  sed -r -i "s/(magicMode)\s*=\s*.*/\1=$MAGIC_MODE/" "$ARKIME_CONFIG_FILE"
  sed -r -i "s/(maxPacketsInQueue)\s*=\s*.*/\1=$MAX_PACKETS_IN_QUEUE/" "$ARKIME_CONFIG_FILE"
  sed -r -i "s/(packetThreads)\s*=\s*.*/\1=$PACKET_THREADS/" "$ARKIME_CONFIG_FILE"
  sed -r -i "s/(pcapReadMethod)\s*=\s*.*/\1=$PCAP_READ_METHOD/" "$ARKIME_CONFIG_FILE"
  sed -r -i "s/(pcapWriteMethod)\s*=\s*.*/\1=$PCAP_WRITE_METHOD/" "$ARKIME_CONFIG_FILE"
  sed -r -i "s/(pcapWriteSize)\s*=\s*.*/\1=$PCAP_WRITE_SIZE/" "$ARKIME_CONFIG_FILE"
  sed -r -i "s/(tpacketv3BlockSize)\s*=\s*.*/\1=$TPACKETV3_BLOCK_SIZE/" "$ARKIME_CONFIG_FILE"
  sed -r -i "s/(tpacketv3NumThreads)\s*=\s*.*/\1=$TPACKETV3_NUM_THREADS/" "$ARKIME_CONFIG_FILE"

  # how often OpenSearch/Elasticsearch should create a new index
  if [[ -n $ARKIME_ROTATE_INDEX ]]; then
    sed -r -i "s/(rotateIndex)\s*=\s*.*/\1=$ARKIME_ROTATE_INDEX/" "$ARKIME_CONFIG_FILE"
  fi

  # debug setting (https://arkime.com/settings#debug)
  if [[ -n $ARKIME_DEBUG_LEVEL ]]; then
    sed -r -i "s/(debug)\s*=\s*.*/\1=$ARKIME_DEBUG_LEVEL/" "$ARKIME_CONFIG_FILE"
  fi

  # rules files
  ARKIME_RULES_DIR="$SUPERVISOR_PATH"/arkime/rules
  if [[ -d "${ARKIME_RULES_DIR}" ]]; then
    RULES_FILES="$(find "${ARKIME_RULES_DIR}" -mindepth 1 -maxdepth 1 -type f -size +0c \( -name '*.yml' -o -name '*.yaml' \) | tr '\n' ';' | sed 's/;$//' )"
    sed -r -i "s|(rulesFiles)\s*=\s*.*|\1=$RULES_FILES|" "$ARKIME_CONFIG_FILE"
  fi

  # lua plugins
  ARKIME_LUA_DIR="$SUPERVISOR_PATH"/arkime/lua
  if [[ -d "${ARKIME_LUA_DIR}" ]]; then
    LUA_FILES="$(find "${ARKIME_LUA_DIR}" -mindepth 1 -maxdepth 1 -type f -size +0c -name '*.lua' | tr '\n' ';' | sed 's/;$//' )"
    sed -r -i "s|(luaFiles)\s*=\s*.*|\1=$LUA_FILES|" "$ARKIME_CONFIG_FILE"
  fi

  # enable ja4+ plugin if it's present
  JA4_PLUGIN_FILE="/opt/arkime/plugins/ja4plus.$(dpkg --print-architecture).so"
  if [[ -f "${JA4_PLUGIN_FILE}" ]]; then
    JA4_PLUGIN_FILE_BASE="$(basename "${JA4_PLUGIN_FILE}")"
    JA4_PLUGIN_FILE_ESCAPED="$(echo "${JA4_PLUGIN_FILE_BASE}" | sed 's@\.@\\\.@g')"
    # clean up old references to the plugin
    sed -i "/plugins=.*${JA4_PLUGIN_FILE_ESCAPED}/s/;\?${JA4_PLUGIN_FILE_ESCAPED}//g" "$ARKIME_CONFIG_FILE"
    # append ja4 plugin filename to end of plugins= line in config file and uncomment it if necessary
    sed -i "s/^#*[[:space:]]*\(plugins=\)/\1${JA4_PLUGIN_FILE_BASE};/" "$ARKIME_CONFIG_FILE"
    # squash semicolons
    sed -i 's/;\{2,\}/;/g' "$ARKIME_CONFIG_FILE"
    # remove trailing semicolon from plugins= line if it exists
    sed -i "s/^\(plugins=.*\)[[:space:]]*;[[:space:]]*$/\1/" "$ARKIME_CONFIG_FILE"
  fi

  # identify node in session metadata for PCAP reachback
  ROUTE_DEST_IP=
  if [[ -n "$OS_HOST" ]]; then
    if [[ "$OS_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      ROUTE_DEST_IP="$OS_HOST"
    else
      ROUTE_DEST_IP=$(dig +short "$OS_HOST" 2>/dev/null | head -n 1)
    fi
  fi
  [[ -n "$ROUTE_DEST_IP" ]] || ROUTE_DEST_IP=255.255.255.255
  PRIMARY_IP=$(ip route get "$ROUTE_DEST_IP" | grep -Po '(?<=src )(\d{1,3}.){4}' | sed "s/ //g")
  export ARKIME_NODE_NAME="$(hostname --long)"
  export ARKIME_NODE_HOST="$PRIMARY_IP"

  # get sensor user-owned copies of the capture lookup files into /opt/sensor/sensor_ctl/arkime
  rsync -a --update /opt/arkime/etc/{ipv4-address-space.csv,oui.txt,GeoLite2-Country.mmdb,GeoLite2-ASN.mmdb} /opt/sensor/sensor_ctl/arkime/
  chmod 600 /opt/sensor/sensor_ctl/arkime/{ipv4-address-space.csv,oui.txt,GeoLite2-Country.mmdb,GeoLite2-ASN.mmdb}

  # generate self-signed TLS keys for arkime viewer if they don't already exist
  if ( [[ -n "$ARKIME_VIEWER_CERT" ]] && [[ -n "$ARKIME_VIEWER_KEY" ]] ); then
    CRT_FILESPEC="$SUPERVISOR_PATH"/arkime/"$ARKIME_VIEWER_CERT"
    KEY_FILESPEC="$SUPERVISOR_PATH"/arkime/"$ARKIME_VIEWER_KEY"
    if ( [[ ! -f "$CRT_FILESPEC" ]] || [[ ! -f "$KEY_FILESPEC" ]] ) && [[ -x /usr/local/bin/self_signed_key_gen.sh ]]; then
      pushd "$SUPERVISOR_PATH"/arkime >/dev/null 2>&1
      /usr/local/bin/self_signed_key_gen.sh -n -o ./newcerts >/dev/null 2>&1
      mv ./newcerts/server.crt "$CRT_FILESPEC"
      mv ./newcerts/server.key "$KEY_FILESPEC"
      rm -rf ./newcerts
      popd >/dev/null 2>&1
    fi
  fi

  if [[ ${ARKIME_WISE_PLUGIN}  == "true" ]]; then
    # make sure the wise plugin is enabled in the config file
    WISE_PLUGIN_NAME="wise.so"
    WISE_PLUGIN_ESCAPED="$(echo "${WISE_PLUGIN_NAME}" | sed 's@\.@\\\.@g')"
    # clean up old references to the plugin
    sed -i "/plugins=.*${WISE_PLUGIN_ESCAPED}/s/;\?${WISE_PLUGIN_ESCAPED}//g" "$ARKIME_CONFIG_FILE"
    # append wise plugin filename to end of plugins= line in config file and uncomment it if necessary
    sed -i "s/^#*[[:space:]]*\(plugins=\)/\1${WISE_PLUGIN_NAME};/" "$ARKIME_CONFIG_FILE"
    # squash semicolons
    sed -i 's/;\{2,\}/;/g' "$ARKIME_CONFIG_FILE"
    # remove trailing semicolon from plugins= line if it exists
    sed -i "s/^\(plugins=.*\)[[:space:]]*;[[:space:]]*$/\1/" "$ARKIME_CONFIG_FILE"
    sed -i "s|^\(wiseURL=\).*|\1""${ARKIME_WISE_URL}""|" "${ARKIME_CONFIG_FILE}"
  fi

  # update the firewall ACL (via ufw) to allow retrieval of packets
  sudo --non-interactive /usr/local/bin/ufw_allow_requests.sh

  # make sure interface flags are set appropriately for capture
  if [[ -n $CAPTURE_INTERFACE ]]; then
    IFS=","
    for IFACE_NAME in $CAPTURE_INTERFACE; do
      sudo --non-interactive /usr/local/bin/nic-capture-setup.sh "$IFACE_NAME" >/dev/null 2>&1
    done
    unset IFS
  fi

fi
