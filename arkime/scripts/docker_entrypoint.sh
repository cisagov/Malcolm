#!/bin/bash

function urlencodeall() {
    local length="${#1}"
    for (( i = 0; i < length; i++ )); do
        local c="${1:i:1}"
        printf '%%%02X' "'$c"
    done
}

ARKIME_DIR=${ARKIME_DIR:-"/opt/arkime"}
ARKIME_PASSWORD_SECRET=${ARKIME_PASSWORD_SECRET:-"Malcolm"}
ARKIME_FREESPACEG=${ARKIME_FREESPACEG:-"10%"}
CAPTURE_INTERFACE=${PCAP_IFACE:-}
LIVE_CAPTURE=${ARKIME_LIVE_CAPTURE:-false}
VIEWER_PORT=${ARKIME_VIEWER_PORT:-8005}

MALCOLM_PROFILE=${MALCOLM_PROFILE:-"malcolm"}
OPENSEARCH_URL_FINAL=${OPENSEARCH_URL:-"http://opensearch:9200"}
OPENSEARCH_PRIMARY=${OPENSEARCH_PRIMARY:-"opensearch-local"}
OPENSEARCH_CREDS_CONFIG_FILE=${OPENSEARCH_CREDS_CONFIG_FILE:-"/var/local/curlrc/.opensearch.primary.curlrc"}
if ( [[ "$OPENSEARCH_PRIMARY" == "opensearch-remote" ]] || [[ "$OPENSEARCH_PRIMARY" == "elasticsearch-remote" ]] ) && [[ -r "$OPENSEARCH_CREDS_CONFIG_FILE" ]]; then
    # need to build the opensearch URL (including username/password) by combining
    # OPENSEARCH_URL and parameters from OPENSEARCH_CREDS_CONFIG_FILE

    # get the new username/password from the curl file (I already wrote python code to do this, so sue me)
    pushd "$(dirname $(realpath -e "${BASH_SOURCE[0]}"))" >/dev/null 2>&1
    NEW_USER_PASSWORD="$(python3 -c "import malcolm_utils; result=malcolm_utils.ParseCurlFile('$OPENSEARCH_CREDS_CONFIG_FILE'); print(result['user']+'|'+result['password']);")"
    NEW_USER="$(echo "$NEW_USER_PASSWORD" | cut -d'|' -f1)"
    NEW_PASSWORD="$(urlencodeall "$(echo "$NEW_USER_PASSWORD" | cut -d'|' -f2-)")"
    popd >/dev/null 2>&1

    # extract the other stuff from OPENSEARCH_URL_FINAL
    # extract the protocol
    PROTOCOL=$(echo "$OPENSEARCH_URL_FINAL" | grep "://" | sed -e's,^\(.*://\).*,\1,g')
    # Remove the PROTOCOL
    URL_NO_PROTOCOL=$(echo "${OPENSEARCH_URL_FINAL/$PROTOCOL/}")
    # Use tr: Make the PROTOCOL lower-case for easy string compare
    PROTOCOL=$(echo "$PROTOCOL" | tr '[:upper:]' '[:lower:]')

    # Extract the old user and password (if any)
    USERPASS=$(echo "$URL_NO_PROTOCOL" | grep "@" | cut -d"/" -f1 | rev | cut -d"@" -f2- | rev)

    # Extract the host
    HOSTPORT=$(echo "${URL_NO_PROTOCOL/$USERPASS@/}" | cut -d"/" -f1)

    # smoosh them all together for the new URL
    OPENSEARCH_URL_FINAL="${PROTOCOL}${NEW_USER}:${NEW_PASSWORD}@${HOSTPORT}"
fi

if [[ -r "${ARKIME_DIR}"/etc/config.orig.ini ]]; then
    cp "${ARKIME_DIR}"/etc/config.orig.ini "${ARKIME_DIR}"/etc/config.ini

    sed -i "s|^\(elasticsearch=\).*|\1"${OPENSEARCH_URL_FINAL}"|" "${ARKIME_DIR}"/etc/config.ini
    sed -i "s/^\(passwordSecret=\).*/\1"${ARKIME_PASSWORD_SECRET}"/" "${ARKIME_DIR}"/etc/config.ini
    sed -i "s/^\(freeSpaceG=\).*/\1"${ARKIME_FREESPACEG}"/" "${ARKIME_DIR}"/etc/config.ini
    sed -i "s/^\(viewPort=\).*/\1"${VIEWER_PORT}"/" "${ARKIME_DIR}"/etc/config.ini

    # capture interface(s)
    if [[ -n "$CAPTURE_INTERFACE" ]] && [[ "$LIVE_CAPTURE" == "true" ]] ; then

      # in config.ini multiple interfaces are separated by ;
      ARKIME_CAPTURE_INTERFACE="$(echo "$CAPTURE_INTERFACE" | sed "s/,/;/g")"

      # place capture interfaces in the config file
      sed -r -i "s|(interface)\s*=\s*.*|\1=$ARKIME_CAPTURE_INTERFACE|" "${ARKIME_DIR}"/etc/config.ini
      sed -i "s/^\(readTruncatedPackets=\).*/\1"false"/" "${ARKIME_DIR}"/etc/config.ini
      sed -r -i "s/(bpf)\s*=\s*.*/\1=${PCAP_FILTER:-}/" "${ARKIME_DIR}"/etc/config.ini

      # convert pcap rotation size units (MB to GB) and stick in config file
      if [[ -n $PCAP_ROTATE_MEGABYTES ]]; then
        PCAP_ROTATE_GIGABYTES=$(echo "($PCAP_ROTATE_MEGABYTES + 1024 - 1)/1024" | bc)
        sed -r -i "s/(maxFileSizeG)\s*=\s*.*/\1=$PCAP_ROTATE_GIGABYTES/" "${ARKIME_DIR}"/etc/config.ini
      fi

      # convert pcap rotation time units (sec to min) and stick in config file
      if [[ -n $PCAP_ROTATE_SECONDS ]]; then
        PCAP_ROTATE_MINUTES=$(echo "($PCAP_ROTATE_SECONDS + 60 - 1)/60" | bc)
        sed -r -i "s/(maxFileTimeM)\s*=\s*.*/\1=$PCAP_ROTATE_MINUTES/" "${ARKIME_DIR}"/etc/config.ini
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

      # ensure capabilities for capture
      setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /sbin/ethtool || true
      setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip' "${ARKIME_DIR}"/bin/capture || true
    fi

    # comment-out features that are unused in hedgehog run profile mode and in live-capture mode
    if [[ "$MALCOLM_PROFILE" == "hedgehog" ]] || [[ "$LIVE_CAPTURE" == "true" ]]; then
        sed -i "s/^\(userNameHeader=\)/# \1/" "${ARKIME_DIR}"/etc/config.ini
        sed -i "s/^\(userAuthIps=\)/# \1/" "${ARKIME_DIR}"/etc/config.ini
        sed -i "s/^\(userAutoCreateTmpl=\)/# \1/" "${ARKIME_DIR}"/etc/config.ini
        sed -i "s/^\(wiseHost=\)/# \1/" "${ARKIME_DIR}"/etc/config.ini
        sed -i "s/^\(wisePort=\)/# \1/" "${ARKIME_DIR}"/etc/config.ini
        sed -i "s/^\(plugins=\)/# \1/" "${ARKIME_DIR}"/etc/config.ini
        sed -i "s/^\(viewerPlugins=\)/# \1/" "${ARKIME_DIR}"/etc/config.ini
        sed -i '/^\[custom-fields\]/,$d' "${ARKIME_DIR}"/etc/config.ini
    fi

    chmod 600 "${ARKIME_DIR}"/etc/config.ini || true
    [[ -n ${PUID} ]] && chown -f ${PUID} "${ARKIME_DIR}"/etc/config.ini || true
    [[ -n ${PGID} ]] && chown -f :${PGID} "${ARKIME_DIR}"/etc/config.ini || true
fi

unset OPENSEARCH_URL_FINAL

# start supervisor or whatever the default command is
exec "$@"
