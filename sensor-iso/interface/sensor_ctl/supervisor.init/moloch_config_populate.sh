#!/bin/bash

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

export MOLOCH_HTTPS_FLAG=""

if [[ -n $SUPERVISOR_PATH ]] && [[ -r "$SUPERVISOR_PATH"/moloch/config.ini ]]; then

  MOLOCH_CONFIG_FILE="$SUPERVISOR_PATH"/moloch/config.ini

  # capture interface(s)
  if [[ -n $CAPTURE_INTERFACE ]]; then
    # in config.ini multiple interfaces are separated by ;
    MOLOCH_CAPTURE_INTERFACE="$(echo "$CAPTURE_INTERFACE" | sed "s/,/;/g")"
    # place capture interfaces in the config file
    sed -r -i "s|(interface)\s*=\s*.*|\1=$MOLOCH_CAPTURE_INTERFACE|" "$MOLOCH_CONFIG_FILE"
  fi

  # stick elasticsearch connection information in moloch config file
  if [[ -n $ES_PROTOCOL ]] && [[ -n $ES_HOST ]]; then

    # build elasticsearch URL for moloch-capture
    MOLOCH_ELASTICSEARCH="${ES_PROTOCOL}://"

    if [[ -n $ES_USERNAME ]] && [[ -n $ES_PASSWORD ]]; then
      MOLOCH_ELASTICSEARCH+="${ES_USERNAME}:${ES_PASSWORD}@"
    fi

    MOLOCH_ELASTICSEARCH+="${ES_HOST}"

    if [[ -n $ES_PORT ]]; then
      MOLOCH_ELASTICSEARCH+=":${ES_PORT}"
    else
      MOLOCH_ELASTICSEARCH+=":9200"
    fi

    # place the URL in the config file
    sed -r -i "s|(elasticsearch)\s*=\s*.*|\1=$MOLOCH_ELASTICSEARCH|" "$MOLOCH_CONFIG_FILE"
  fi

  # if SSL certificate verification is turned off, supply the --insecure flag
  if [[ -n $ES_SSL_VERIFY ]] && [ "$ES_SSL_VERIFY" = none ]; then
    export MOLOCH_HTTPS_FLAG="--insecure"
  fi

  # convert pcap rotation size units (MB to GB) and stick in config file
  if [[ -n $PCAP_ROTATE_MEGABYTES ]]; then
    PCAP_ROTATE_GIGABYTES=$(echo "($PCAP_ROTATE_MEGABYTES + 1024 - 1)/1024" | bc)
    sed -r -i "s/(maxFileSizeG)\s*=\s*.*/\1=$PCAP_ROTATE_GIGABYTES/" "$MOLOCH_CONFIG_FILE"
  fi

  # convert pcap rotation time units (sec to min) and stick in config file
  if [[ -n $PCAP_ROTATE_SECONDS ]]; then
    PCAP_ROTATE_MINUTES=$(echo "($PCAP_ROTATE_SECONDS + 60 - 1)/60" | bc)
    sed -r -i "s/(maxFileTimeM)\s*=\s*.*/\1=$PCAP_ROTATE_MINUTES/" "$MOLOCH_CONFIG_FILE"
  fi

  # identify node in session metadata for PCAP reachback
  PRIMARY_IP=$(ip route get 255.255.255.255 | grep -Po '(?<=src )(\d{1,3}.){4}' | sed "s/ //g")
  export MOLOCH_NODE_NAME="$(hostname --long)"
  export MOLOCH_NODE_HOST="$PRIMARY_IP"

  # get sensor user-owned copies of the moloch-capture lookup files into /opt/sensor/sensor_ctl/moloch
  rsync -a --update /opt/moloch/etc/{ipv4-address-space.csv,oui.txt,GeoLite2-Country.mmdb,GeoLite2-ASN.mmdb} /opt/sensor/sensor_ctl/moloch/
  chmod 600 /opt/sensor/sensor_ctl/moloch/{ipv4-address-space.csv,oui.txt,GeoLite2-Country.mmdb,GeoLite2-ASN.mmdb}

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
