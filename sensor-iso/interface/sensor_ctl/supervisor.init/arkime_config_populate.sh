#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

export ARKIME_HTTPS_FLAG=""

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

  # if SSL certificate verification is turned off, supply the --insecure flag
  if [[ -n $OS_SSL_VERIFY ]] && [ "$OS_SSL_VERIFY" = none ]; then
    export ARKIME_HTTPS_FLAG="--insecure"
  fi

  # convert pcap rotation size units (MB to GB) and stick in config file
  if [[ -n $PCAP_ROTATE_MEGABYTES ]]; then
    PCAP_ROTATE_GIGABYTES=$(echo "($PCAP_ROTATE_MEGABYTES + 1024 - 1)/1024" | bc)
    sed -r -i "s/(maxFileSizeG)\s*=\s*.*/\1=$PCAP_ROTATE_GIGABYTES/" "$ARKIME_CONFIG_FILE"
  fi

  # convert pcap rotation time units (sec to min) and stick in config file
  if [[ -n $PCAP_ROTATE_SECONDS ]]; then
    PCAP_ROTATE_MINUTES=$(echo "($PCAP_ROTATE_SECONDS + 60 - 1)/60" | bc)
    sed -r -i "s/(maxFileTimeM)\s*=\s*.*/\1=$PCAP_ROTATE_MINUTES/" "$ARKIME_CONFIG_FILE"
  fi

  # pcap compression
  COMPRESSION_TYPE="${ARKIME_COMPRESSION_TYPE:-none}"
  COMPRESSION_LEVEL="${ARKIME_COMPRESSION_LEVEL:-0}"
  sed -r -i "s/(simpleCompression)\s*=\s*.*/\1=$COMPRESSION_TYPE/" "$ARKIME_CONFIG_FILE"
  if [[ "$COMPRESSION_TYPE" == "zstd" ]]; then
    sed -r -i "s/(simpleZstdLevel)\s*=\s*.*/\1=$COMPRESSION_LEVEL/" "$ARKIME_CONFIG_FILE"
  elif [[ "$COMPRESSION_TYPE" == "gzip" ]]; then
    sed -r -i "s/(simpleGzipLevel)\s*=\s*.*/\1=$COMPRESSION_LEVEL/" "$ARKIME_CONFIG_FILE"
  fi

  # identify node in session metadata for PCAP reachback
  PRIMARY_IP=$(ip route get 255.255.255.255 | grep -Po '(?<=src )(\d{1,3}.){4}' | sed "s/ //g")
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

  # update the firewall ACL (via ufw) to allow retrieval of packets
  sudo --non-interactive /usr/local/bin/ufw_allow_viewer.sh

  # make sure interface flags are set appropriately for capture
  if [[ -n $CAPTURE_INTERFACE ]]; then
    IFS=","
    for IFACE_NAME in $CAPTURE_INTERFACE; do
      sudo --non-interactive /usr/local/bin/nic-capture-setup.sh "$IFACE_NAME" >/dev/null 2>&1
    done
    unset IFS
  fi

fi
