#!/bin/bash

function urlencodeall() {
    local length="${#1}"
    for (( i = 0; i < length; i++ )); do
        local c="${1:i:1}"
        printf '%%%02X' "'$c"
    done
}

ARKIME_DIR=${ARKIME_DIR:-"/opt/arkime"}
ARKIME_RULES_DIR=${ARKIME_RULES_DIR:-"/opt/arkime/rules"}
ARKIME_CONFIG_FILE="${ARKIME_DIR}"/etc/config.ini
ARKIME_PASSWORD_SECRET=${ARKIME_PASSWORD_SECRET:-"Malcolm"}
ARKIME_FREESPACEG=${ARKIME_FREESPACEG:-"10%"}
CAPTURE_INTERFACE=${PCAP_IFACE:-}
LIVE_CAPTURE=${ARKIME_LIVE_CAPTURE:-false}
VIEWER_PORT=${ARKIME_VIEWER_PORT:-8005}
NODE_NAME=${PCAP_NODE_NAME:-malcolm}

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

# iff config.ini does not exist but config.orig.ini does, use it as a basis and modify based on env. vars
if [[ ! -f "${ARKIME_CONFIG_FILE}" ]] && [[ -r "${ARKIME_DIR}"/etc/config.orig.ini ]]; then
    cp "${ARKIME_DIR}"/etc/config.orig.ini "${ARKIME_CONFIG_FILE}"

    sed -i "s|^\(elasticsearch=\).*|\1"${OPENSEARCH_URL_FINAL}"|" "${ARKIME_CONFIG_FILE}"
    sed -i "s/^\(passwordSecret=\).*/\1"${ARKIME_PASSWORD_SECRET}"/" "${ARKIME_CONFIG_FILE}"
    sed -i "s/^\(freeSpaceG=\).*/\1"${ARKIME_FREESPACEG}"/" "${ARKIME_CONFIG_FILE}"
    sed -i "s/^\(viewPort=\).*/\1"${VIEWER_PORT}"/" "${ARKIME_CONFIG_FILE}"
    sed -i "s/^\(pcapDir=\).*/\1\/data\/pcap\/arkime-live/" "${ARKIME_CONFIG_FILE}"
    sed -i "s/MALCOLM_PCAP_NODE_NAME/${NODE_NAME}-upload/g" "${ARKIME_CONFIG_FILE}"

    # performance tuning parameters
    [[ -n "$ARKIME_DB_BULK_SIZE" ]] && \
      sed -r -i "s/(dbBulkSize)\s*=\s*.*/\1=$ARKIME_DB_BULK_SIZE/" "${ARKIME_CONFIG_FILE}"
    [[ -n "$ARKIME_MAGIC_MODE" ]] && \
      sed -r -i "s/(magicMode)\s*=\s*.*/\1=$ARKIME_MAGIC_MODE/" "${ARKIME_CONFIG_FILE}"
    [[ -n "$ARKIME_MAX_PACKETS_IN_QUEUE" ]] && \
      sed -r -i "s/(maxPacketsInQueue)\s*=\s*.*/\1=$ARKIME_MAX_PACKETS_IN_QUEUE/" "${ARKIME_CONFIG_FILE}"
    [[ -n "$ARKIME_PACKET_THREADS" ]] && \
      sed -r -i "s/(packetThreads)\s*=\s*.*/\1=$ARKIME_PACKET_THREADS/" "${ARKIME_CONFIG_FILE}"
    [[ -n "$ARKIME_PCAP_WRITE_METHOD" ]] && \
      sed -r -i "s/(pcapWriteMethod)\s*=\s*.*/\1=$ARKIME_PCAP_WRITE_METHOD/" "${ARKIME_CONFIG_FILE}"
    [[ -n "$ARKIME_PCAP_WRITE_SIZE" ]] && \
      sed -r -i "s/(pcapWriteSize)\s*=\s*.*/\1=$ARKIME_PCAP_WRITE_SIZE/" "${ARKIME_CONFIG_FILE}"
    [[ -n "$ARKIME_PCAP_READ_METHOD" ]] && \
      sed -r -i "s/(pcapReadMethod)\s*=\s*.*/\1=$ARKIME_PCAP_READ_METHOD/" "${ARKIME_CONFIG_FILE}"
    [[ -n "$ARKIME_TPACKETV3_NUM_THREADS" ]] && \
      sed -r -i "s/(tpacketv3NumThreads)\s*=\s*.*/\1=$ARKIME_TPACKETV3_NUM_THREADS/" "${ARKIME_CONFIG_FILE}"
    [[ -n "$ARKIME_TPACKETV3_BLOCK_SIZE" ]] && \
      sed -r -i "s/(tpacketv3BlockSize)\s*=\s*.*/\1=$ARKIME_TPACKETV3_BLOCK_SIZE/" "${ARKIME_CONFIG_FILE}"

    # capture interface(s)
    if [[ -n "$CAPTURE_INTERFACE" ]] && [[ "$LIVE_CAPTURE" == "true" ]] ; then

      # in config.ini multiple interfaces are separated by ;
      ARKIME_CAPTURE_INTERFACE="$(echo "$CAPTURE_INTERFACE" | sed "s/,/;/g")"

      # place capture interfaces in the config file
      sed -r -i "s|(interface)\s*=\s*.*|\1=$ARKIME_CAPTURE_INTERFACE|" "${ARKIME_CONFIG_FILE}"
      sed -i "s/^\(readTruncatedPackets=\).*/\1"false"/" "${ARKIME_CONFIG_FILE}"
      sed -r -i "s/(bpf)\s*=\s*.*/\1=${PCAP_FILTER:-}/" "${ARKIME_CONFIG_FILE}"

      # convert pcap rotation size units (MB to GB) and stick in config file
      if [[ -n $PCAP_ROTATE_MEGABYTES ]]; then
        PCAP_ROTATE_GIGABYTES=$(echo "($PCAP_ROTATE_MEGABYTES + 1024 - 1)/1024" | bc)
        sed -r -i "s/(maxFileSizeG)\s*=\s*.*/\1=$PCAP_ROTATE_GIGABYTES/" "${ARKIME_CONFIG_FILE}"
      fi

      # convert pcap rotation time units (sec to min) and stick in config file
      if [[ -n $PCAP_ROTATE_SECONDS ]]; then
        PCAP_ROTATE_MINUTES=$(echo "($PCAP_ROTATE_SECONDS + 60 - 1)/60" | bc)
        sed -r -i "s/(maxFileTimeM)\s*=\s*.*/\1=$PCAP_ROTATE_MINUTES/" "${ARKIME_CONFIG_FILE}"
      fi

      # pcap compression
      COMPRESSION_TYPE="${ARKIME_COMPRESSION_TYPE:-none}"
      COMPRESSION_LEVEL="${ARKIME_COMPRESSION_LEVEL:-0}"
      sed -r -i "s/(simpleCompression)\s*=\s*.*/\1=$COMPRESSION_TYPE/" "${ARKIME_CONFIG_FILE}"
      if [[ "$COMPRESSION_TYPE" == "zstd" ]]; then
        sed -r -i "s/(simpleZstdLevel)\s*=\s*.*/\1=$COMPRESSION_LEVEL/" "${ARKIME_CONFIG_FILE}"
      elif [[ "$COMPRESSION_TYPE" == "gzip" ]]; then
        sed -r -i "s/(simpleGzipLevel)\s*=\s*.*/\1=$COMPRESSION_LEVEL/" "${ARKIME_CONFIG_FILE}"
      fi

      # ensure capabilities for capture
      setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip' "${ARKIME_DIR}"/bin/capture || true
      setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /sbin/ethtool || true

      # disable NIC hardware offloading features and adjust ring buffer sizes for each interface
      for IFACE in ${CAPTURE_INTERFACE//,/ }; do

        [[ "${PCAP_IFACE_TWEAK:-false}" == "true" ]] && \
          [[ "$IFACE" != "lo" ]] && \
          [[ -x /usr/local/bin/nic-capture-setup.sh ]] && \
          /usr/local/bin/nic-capture-setup.sh "$IFACE" >/dev/null 2>&1 || true

      done # loop over capture interfaces

    fi # capture interface(s) defined and live capture enabled

    # rules files
    if [[ -d "${ARKIME_RULES_DIR}" ]]; then
      RULES_FILES="$(find "${ARKIME_RULES_DIR}" -mindepth 1 -maxdepth 1 -type f -size +0c \( -name '*.yml' -o -name '*.yaml' \) | tr '\n' ';' | sed 's/;$//' )"
      sed -r -i "s|(rulesFiles)\s*=\s*.*|\1=$RULES_FILES|" "${ARKIME_CONFIG_FILE}"
    fi

    # comment-out features that are unused in hedgehog run profile mode and in live-capture mode
    if [[ "$MALCOLM_PROFILE" == "hedgehog" ]] || [[ "$LIVE_CAPTURE" == "true" ]]; then
        sed -i "s/^\(userNameHeader=\)/# \1/" "${ARKIME_CONFIG_FILE}"
        sed -i "s/^\(userAuthIps=\)/# \1/" "${ARKIME_CONFIG_FILE}"
        sed -i "s/^\(userAutoCreateTmpl=\)/# \1/" "${ARKIME_CONFIG_FILE}"
        sed -i "s/^\(wiseHost=\)/# \1/" "${ARKIME_CONFIG_FILE}"
        sed -i "s/^\(wisePort=\)/# \1/" "${ARKIME_CONFIG_FILE}"
        sed -i "s/^\(plugins=\)/# \1/" "${ARKIME_CONFIG_FILE}"
        sed -i "s/^\(viewerPlugins=\)/# \1/" "${ARKIME_CONFIG_FILE}"
        sed -i '/^\[custom-fields\]/,$d' "${ARKIME_CONFIG_FILE}"
    fi

    chmod 600 "${ARKIME_CONFIG_FILE}" || true
    [[ -n ${PUID} ]] && chown -f ${PUID} "${ARKIME_CONFIG_FILE}" || true
    [[ -n ${PGID} ]] && chown -f :${PGID} "${ARKIME_CONFIG_FILE}" || true
fi

unset OPENSEARCH_URL_FINAL

# start supervisor or whatever the default command is
exec "$@"
