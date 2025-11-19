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
ARKIME_LUA_DIR=${ARKIME_LUA_DIR:-"/opt/arkime/lua"}
ARKIME_CONFIG_FILE="${ARKIME_DIR}"/etc/config.ini
ARKIME_PASSWORD_SECRET=${ARKIME_PASSWORD_SECRET:-"Malcolm"}
ARKIME_FREESPACEG=${ARKIME_FREESPACEG:-"10%"}
ARKIME_ROTATE_INDEX=${ARKIME_ROTATE_INDEX:-"daily"}
ARKIME_QUERY_ALL_INDICES=${ARKIME_QUERY_ALL_INDICES:-"false"}
ARKIME_SPI_DATA_MAX_INDICES=${ARKIME_SPI_DATA_MAX_INDICES:-7}
ARKIME_NETWORK_INDEX_PATTERN=${ARKIME_NETWORK_INDEX_PATTERN:-arkime_sessions3-*}
MALCOLM_NETWORK_INDEX_PATTERN=${MALCOLM_NETWORK_INDEX_PATTERN:-}

ARKIME_DEBUG_LEVEL=${ARKIME_DEBUG_LEVEL:-0}
CAPTURE_INTERFACE=${PCAP_IFACE:-}
LIVE_CAPTURE=${ARKIME_LIVE_CAPTURE:-false}
VIEWER_PORT=${ARKIME_VIEWER_PORT:-8005}
NODE_NAME=${PCAP_NODE_NAME:-malcolm}
ROLE_BASED_ACCESS=${ROLE_BASED_ACCESS:-false}
ARKIME_EXPOSE_WISE_GUI=${ARKIME_EXPOSE_WISE_GUI:-"true"}
ARKIME_ALLOW_WISE_GUI_CONFIG=${ARKIME_ALLOW_WISE_GUI_CONFIG:-"false"}
ARKIME_WISE_CONFIG_PIN_CODE=${ARKIME_WISE_CONFIG_PIN_CODE:-"WISE2019"}
ARKIME_WISE_EXAMPLE_FILE="${ARKIME_DIR}"/etc/wise.ini.example
ARKIME_WISE_CONFIG_FILE="${ARKIME_DIR}"/wiseini/wise.ini
ARKIME_WISE_SERVICE_SCRIPT=/usr/local/bin/wise_service.sh

MALCOLM_PROFILE=${MALCOLM_PROFILE:-"malcolm"}
OPENSEARCH_URL_FINAL=${OPENSEARCH_URL:-"https://opensearch:9200"}
OPENSEARCH_PRIMARY=${OPENSEARCH_PRIMARY:-"opensearch-local"}
OPENSEARCH_CREDS_CONFIG_FILE=${OPENSEARCH_CREDS_CONFIG_FILE:-"/var/local/curlrc/.opensearch.primary.curlrc"}

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

# Extract the host:port
if [ -n "${USERPASS}" ]; then
    # URL **had** credentials, strip them out from the host:port
    HOSTPORT="${URL_NO_PROTOCOL/$USERPASS@/}"
else
    # URL had **no** credentials—keep everything
    HOSTPORT="$URL_NO_PROTOCOL"
fi

# smoosh them all together for the new URL
OPENSEARCH_URL_FINAL="${PROTOCOL}${NEW_USER}:${NEW_PASSWORD}@${HOSTPORT}"

# if config.ini does not exist but config.orig.ini does, use it as a basis and modify based on env. vars
if [[ ! -f "${ARKIME_CONFIG_FILE}" ]] && [[ -r "${ARKIME_DIR}"/etc/config.orig.ini ]]; then
    cp "${ARKIME_DIR}"/etc/config.orig.ini "${ARKIME_CONFIG_FILE}"

    sed -i "s|^\(elasticsearch=\).*|\1"${OPENSEARCH_URL_FINAL}"|" "${ARKIME_CONFIG_FILE}"
    sed -i "s/^\(passwordSecret=\).*/\1"${ARKIME_PASSWORD_SECRET}"/" "${ARKIME_CONFIG_FILE}"
    sed -i "s/^\(freeSpaceG=\).*/\1"${ARKIME_FREESPACEG}"/" "${ARKIME_CONFIG_FILE}"
    sed -i "s/^\(rotateIndex=\).*/\1"${ARKIME_ROTATE_INDEX}"/" "${ARKIME_CONFIG_FILE}"
    sed -i "s/^\(queryAllIndices=\).*/\1"${ARKIME_QUERY_ALL_INDICES}"/" "${ARKIME_CONFIG_FILE}"
    sed -i "s/^\(spiDataMaxIndices=\).*/\1"${ARKIME_SPI_DATA_MAX_INDICES}"/" "${ARKIME_CONFIG_FILE}"
    [[ -n "${MALCOLM_NETWORK_INDEX_PATTERN}" ]] && \
      [[ "${MALCOLM_NETWORK_INDEX_PATTERN}" != "${ARKIME_NETWORK_INDEX_PATTERN}" ]] && \
      sed -i "s/^\(queryExtraIndices=\).*/\1"${MALCOLM_NETWORK_INDEX_PATTERN}"/" "${ARKIME_CONFIG_FILE}" || \
      sed -i "s/^\(queryExtraIndices=\).*/\1/" "${ARKIME_CONFIG_FILE}"
    sed -i "s/^\(debug=\).*/\1"${ARKIME_DEBUG_LEVEL}"/" "${ARKIME_CONFIG_FILE}"
    sed -i "s/^\(viewPort=\).*/\1"${VIEWER_PORT}"/" "${ARKIME_CONFIG_FILE}"
    # note: when setting the node name, the viewer_service.sh script needs to match
    sed -i "s/MALCOLM_PCAP_NODE_NAME/${NODE_NAME}-upload/g" "${ARKIME_CONFIG_FILE}"

    # certFile/keyFile is cleared based on ARKIME_SSL, or overriden via ARKIME_CERTFILE/ARKIME_KEYFILE
    [[ "${ARKIME_SSL:-true}" == "false" ]] && \
      ( sed -r -i "s/(certFile)\s*=\s*.*/\1=/" "${ARKIME_CONFIG_FILE}" ; sed -r -i "s/(keyFile)\s*=\s*.*/\1=/" "${ARKIME_CONFIG_FILE}" )
    [[ -n "$ARKIME_CERTFILE" ]] && \
      sed -r -i "s/(certFile)\s*=\s*.*/\1=$ARKIME_CERTFILE/" "${ARKIME_CONFIG_FILE}"
    [[ -n "$ARKIME_KEYFILE" ]] && \
      sed -r -i "s/(keyFile)\s*=\s*.*/\1=$ARKIME_KEYFILE/" "${ARKIME_CONFIG_FILE}"

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
    [[ -n "$PCAP_PROCESSED_DIRECTORY" ]] && \
      sed -r -i "s|(pcapDir)\s*=\s*.*|\1=$PCAP_PROCESSED_DIRECTORY|" "${ARKIME_CONFIG_FILE}"

    # capture interface(s)
    if [[ -n "$CAPTURE_INTERFACE" ]] && [[ "$LIVE_CAPTURE" == "true" ]] ; then

      # in config.ini multiple interfaces are separated by ;
      ARKIME_CAPTURE_INTERFACE="$(echo "$CAPTURE_INTERFACE" | sed "s/,/;/g")"

      # place capture interfaces in the config file
      sed -r -i "s|(interface)\s*=\s*.*|\1=$ARKIME_CAPTURE_INTERFACE|" "${ARKIME_CONFIG_FILE}"
      sed -i "s/^\(readTruncatedPackets=\).*/\1"false"/" "${ARKIME_CONFIG_FILE}"
      sed -r -i "s/(bpf)\s*=\s*.*/\1=${PCAP_FILTER:-}/" "${ARKIME_CONFIG_FILE}"

      # PCAP capture location
      sed -i "s/^\(pcapDir=\).*/\1\/data\/pcap\/arkime-live/" "${ARKIME_CONFIG_FILE}"

      # convert pcap rotation size units (MB to GB) and stick in config file
      if [[ -n $PCAP_ROTATE_MEGABYTES ]]; then
        PCAP_ROTATE_GIGABYTES=$(awk "BEGIN { printf \"%.4f\", $PCAP_ROTATE_MEGABYTES/1024 }")
        sed -r -i "s/(maxFileSizeG)\s*=\s*.*/\1=$PCAP_ROTATE_GIGABYTES/" "${ARKIME_CONFIG_FILE}"
      fi

      # convert pcap rotation time units (sec to min) and stick in config file
      if [[ -n $PCAP_ROTATE_SECONDS ]]; then
        PCAP_ROTATE_MINUTES=$(echo "($PCAP_ROTATE_SECONDS + 60 - 1)/60" | bc)
        sed -r -i "s/(maxFileTimeM)\s*=\s*.*/\1=$PCAP_ROTATE_MINUTES/" "${ARKIME_CONFIG_FILE}"
      fi

      # pcap compression
      COMPRESSION_TYPE="${ARKIME_COMPRESSION_TYPE:-zstd}"
      COMPRESSION_LEVEL="${ARKIME_COMPRESSION_LEVEL:-3}"
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

    # lua plugins
    if [[ -d "${ARKIME_LUA_DIR}" ]]; then
      LUA_FILES="$(find "${ARKIME_LUA_DIR}" -mindepth 1 -maxdepth 1 -type f -size +0c -name '*.lua' | tr '\n' ';' | sed 's/;$//' )"
      sed -r -i "s|(luaFiles)\s*=\s*.*|\1=$LUA_FILES|" "${ARKIME_CONFIG_FILE}"
    fi

    if [[ "$MALCOLM_PROFILE" == "hedgehog" ]] || [[ "$LIVE_CAPTURE" == "true" ]]; then
      # comment-out features that are unused in hedgehog run profile mode and in live-capture mode
        sed -i "s/^\(userNameHeader=\)/# \1/" "${ARKIME_CONFIG_FILE}"
        sed -i "s/^\(userAuthIps=\)/# \1/" "${ARKIME_CONFIG_FILE}"
        sed -i "s/^\(userAutoCreateTmpl=\)/# \1/" "${ARKIME_CONFIG_FILE}"
        sed -i "s/^\(wiseHost=\)/# \1/" "${ARKIME_CONFIG_FILE}"
        sed -i "s/^\(wisePort=\)/# \1/" "${ARKIME_CONFIG_FILE}"
        sed -i "s/^\(viewerPlugins=\)/# \1/" "${ARKIME_CONFIG_FILE}"
        sed -i '/^\[custom-fields\]/,$d' "${ARKIME_CONFIG_FILE}"
    fi

    # enable ja4+ plugin if it's present
    JA4_PLUGIN_FILE="${ARKIME_DIR}/plugins/ja4plus.$(dpkg --print-architecture).so"
    if [[ -f "${JA4_PLUGIN_FILE}" ]]; then
      JA4_PLUGIN_FILE_BASE="$(basename "${JA4_PLUGIN_FILE}")"
      JA4_PLUGIN_FILE_ESCAPED="$(echo "${JA4_PLUGIN_FILE_BASE}" | sed 's@\.@\\\.@g')"
      # clean up old references to the plugin
      sed -i "/plugins=.*${JA4_PLUGIN_FILE_ESCAPED}/s/;\?${JA4_PLUGIN_FILE_ESCAPED}//g" "${ARKIME_CONFIG_FILE}"
      # append ja4 plugin filename to end of plugins= line in config file and uncomment it if necessary
      sed -i "s/^#*[[:space:]]*\(plugins=\)/\1${JA4_PLUGIN_FILE_BASE};/" "${ARKIME_CONFIG_FILE}"
      # squash semicolons
      sed -i 's/;\{2,\}/;/g' "${ARKIME_CONFIG_FILE}"
      # remove trailing semicolon from plugins= line if it exists
      sed -i "s/^\(plugins=.*\)[[:space:]]*;[[:space:]]*$/\1/" "${ARKIME_CONFIG_FILE}"
    fi 

    # build mappings from Malcolm roles to Arkime roles for config.ini
    #   - https://arkime.com/settings#user-role-mappings
    #   - https://arkime.com/roles
    # TODO: until Arkime v6.0.0 is out, as per Andy Wick and I's discussion in slack, at the moment not all of the Arkime permissions can be set on roles,
    #   so creating these doesn't really do us any good. For now, then, Arkime roles (the user-defined ones, at least, the ones that start with role: below)
    #   are going to be handled purely based on URI path in the NGINX stuff (nginx/lua/nginx_auth_helpers.lua).
    #   Once all of these permissions are settable at the role level in Arkime, we can uncomment those and revisit it.
    # -SG 2025.06.17
    RBAC_FILE="$(mktemp)"
    CONFIG_RBAC_FILE="$(mktemp)"
    echo -e "\n[user-role-mappings]" >> "${RBAC_FILE}"
    if [[ "${ROLE_BASED_ACCESS,,}" =~ ^(1|true|yes|on)$ ]]; then
      echo "arkimeUser=true" >> "${RBAC_FILE}"
      [[ -n "$ROLE_ARKIME_ADMIN" ]] && \
        echo "arkimeAdmin=(vals['x-forwarded-roles'] || '').split(',').map(s => s.trim()).includes('$ROLE_ARKIME_ADMIN')" >> "${RBAC_FILE}"
      # [[ -n "$ROLE_ARKIME_READ_ACCESS" ]]  && \
      #   echo "role:read_access=(vals['x-forwarded-roles'] || '').split(',').map(s => s.trim()).includes('$ROLE_ARKIME_READ_ACCESS')" >> "${RBAC_FILE}"
      # [[ -n "$ROLE_ARKIME_READ_WRITE_ACCESS" ]]  && \
      #   echo "role:read_write_access=(vals['x-forwarded-roles'] || '').split(',').map(s => s.trim()).includes('$ROLE_ARKIME_READ_WRITE_ACCESS')" >> "${RBAC_FILE}"
      # [[ -n "$ROLE_ARKIME_PCAP_ACCESS" ]]  && \
      #   echo "role:pcap_access=(vals['x-forwarded-roles'] || '').split(',').map(s => s.trim()).includes('$ROLE_ARKIME_PCAP_ACCESS')" >> "${RBAC_FILE}"
      # [[ -n "$ROLE_ARKIME_HUNT_ACCESS" ]]  && \
      #   echo "role:hunt_access=(vals['x-forwarded-roles'] || '').split(',').map(s => s.trim()).includes('$ROLE_ARKIME_HUNT_ACCESS')" >> "${RBAC_FILE}"
      [[ -n "$ROLE_ARKIME_WISE_READ_ACCESS" ]]  && \
        echo "wiseUser=(vals['x-forwarded-roles'] || '').split(',').map(s => s.trim()).includes('$ROLE_ARKIME_WISE_READ_ACCESS')" >> "${RBAC_FILE}"
      [[ -n "$ROLE_ARKIME_WISE_READ_WRITE_ACCESS" ]]  && \
        echo "wiseAdmin=(vals['x-forwarded-roles'] || '').split(',').map(s => s.trim()).includes('$ROLE_ARKIME_WISE_READ_WRITE_ACCESS')" >> "${RBAC_FILE}"
    else
      echo "arkimeAdmin=true" >> "${RBAC_FILE}"
    fi
    echo -e "\n" >> "${RBAC_FILE}"
    awk '
        FNR==NR { insert_lines[NR] = $0; insert_count = NR; next }
        /^\[custom-fields\]/ && !inserted {
            for (i = 1; i <= insert_count; i++) print insert_lines[i]
            inserted = 1
        }
        { print }
        END {
            if (!inserted) {
                for (i = 1; i <= insert_count; i++) print insert_lines[i]
            }
        }
    ' "${RBAC_FILE}" "${ARKIME_CONFIG_FILE}" > "${CONFIG_RBAC_FILE}" && mv "${CONFIG_RBAC_FILE}" "${ARKIME_CONFIG_FILE}"
    rm -f "${RBAC_FILE}" "${CONFIG_RBAC_FILE}"

    # make sure permissions and ownership are nice
    chmod 600 "${ARKIME_CONFIG_FILE}" || true
    [[ -n ${PUID} ]] && chown -f ${PUID} "${ARKIME_CONFIG_FILE}" || true
    [[ -n ${PGID} ]] && chown -f :${PGID} "${ARKIME_CONFIG_FILE}" || true
fi 


# An example wise.ini file is baked into the container image by the Dockerfile as $ARKIME_DIR/etc/wise.ini.example
# After the container is booted we copy wise.ini.example from $ARMIKE_DIR/etc/ to $ARKIME_DIR/wiseini/
# if $ARKIME_DIR/wiseini/wise.ini does not already exist.
# $ARKIME_DIR/wiseini/wise.ini will either be a R/W mounted file, when run under Docker Compose or
# $ARKIME_DIR/wiseini/ will be a persistent volume when run under Kubernetes.
# This allows changes to persist when the wise application edits its own ini file at runtime.

if [[ ! -f "${ARKIME_WISE_CONFIG_FILE}" ]] && [[ -r "${ARKIME_WISE_EXAMPLE_FILE}" ]] && [[ "$LIVE_CAPTURE" == "false" ]]; then
    cp "${ARKIME_WISE_EXAMPLE_FILE}" "${ARKIME_WISE_CONFIG_FILE}"
fi

if [[  -d "${ARKIME_DIR}/wiseini" ]]; then
  [[ -n ${PUID} ]] && chown -fR ${PUID} "${ARKIME_DIR}/wiseini" || true
  [[ -n ${PGID} ]] && chown -fR :${PGID} "${ARKIME_DIR}/wiseini" || true
fi

if [[ "${ARKIME_EXPOSE_WISE_GUI}"  == "true" ]]; then
  sed "s|^\(elasticsearch=\).*|\1"${OPENSEARCH_URL_FINAL}"|" "${ARKIME_WISE_CONFIG_FILE}" > ./wise.tmp
  sed -i "s|^\(wiseHost=\).*|\1""0.0.0.0""|" ./wise.tmp
  if [[ "${ARKIME_ALLOW_WISE_GUI_CONFIG}"  == "true" ]]; then
    sed -i "s|^\(usersElasticsearch=\).*|\1"${OPENSEARCH_URL_FINAL}"|"  ./wise.tmp
    sed -i "s|^\(\s*\$ARKIME_DIR\/bin\/node wiseService.js\).*|\1 --webcode "${ARKIME_WISE_CONFIG_PIN_CODE}" --webconfig --insecure -c \$ARKIME_DIR/wiseini/wise.ini|" "${ARKIME_WISE_SERVICE_SCRIPT}"
  fi
  truncate --size=0 "${ARKIME_WISE_CONFIG_FILE}" 2>/dev/null || true
  tee -a "${ARKIME_WISE_CONFIG_FILE}" < ./wise.tmp >/dev/null 2>&1 || true
  rm ./wise.tmp
fi

unset OPENSEARCH_URL_FINAL

# start supervisor or whatever the default command is
exec "$@"
