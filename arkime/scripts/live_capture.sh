#!/bin/bash

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

function urlencodeall() {
    local length="${#1}"
    for (( i = 0; i < length; i++ )); do
        local c="${1:i:1}"
        printf '%%%02X' "'$c"
    done
}

function arkime_backend_ready() {
    curl "${CURL_CONFIG_PARAMS[@]}" --connect-timeout 2 --max-time 5 -fs \
      -H'Content-Type: application/json' -XGET \
      "${OPENSEARCH_URL}/_index_template/malcolm_template" 2>/dev/null | grep -q index_templates || return 1

    (( $(curl "${CURL_CONFIG_PARAMS[@]}" --connect-timeout 2 --max-time 5 -fs \
      -H'Content-Type: application/json' -XGET \
      "${OPENSEARCH_URL}/_cat/indices/arkime_users_v*" 2>/dev/null | wc -l) >= 1 ))
}

function wait_for_arkime_backend() {
    local wait_started=${SECONDS}

    until arkime_backend_ready; do
        if (( ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS > 0 )) && \
           (( SECONDS - wait_started >= ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS )); then
            return 1
        fi
        sleep 1
    done
}

function tcpdump_fallback() {
    local iface
    local status
    local rotate_seconds
    local -a filter_args=()
    local -a tcpdump_pids=()

    if [[ -z "${PCAP_IFACE}" ]]; then
        echo "Cannot start tcpdump fallback: PCAP_IFACE is empty" >&2
        return 1
    fi

    rotate_seconds=$(( PCAP_ROTATE_MINUTES * 60 ))
    [[ -n "${PCAP_FILTER}" ]] && filter_args+=( "${PCAP_FILTER}" )

    echo "Falling back to local tcpdump capture on ${PCAP_IFACE}"
    pushd /data/pcap/upload >/dev/null 2>&1 || return 1

    for iface in ${PCAP_IFACE//,/ }; do
        /usr/bin/tcpdump \
          -i "${iface}" \
          -j host \
          -s "${PCAP_SNAPLEN}" \
          -w "mtcpdump-${iface}_${PCAP_TCPDUMP_FILENAME_PATTERN}" \
          -G "${rotate_seconds}" \
          -C "${PCAP_ROTATE_MEGABYTES}" \
          -K \
          -n \
          -Z "${PUSER}" \
          "${filter_args[@]}" &
        tcpdump_pids+=( "$!" )
    done

    wait -n "${tcpdump_pids[@]}"
    status=$?
    kill "${tcpdump_pids[@]}" >/dev/null 2>&1 || true
    wait "${tcpdump_pids[@]}" >/dev/null 2>&1 || true
    popd >/dev/null 2>&1
    return "${status}"
}

ARKIME_DIR=${ARKIME_DIR:-"/opt/arkime"}
ARKIME_CONFIG_FILE="${ARKIME_DIR}"/etc/config.ini
CERT_FILE="${ARKIME_DIR}"/etc/viewer.crt
KEY_FILE="${ARKIME_DIR}"/etc/viewer.key
PUSER=${PUSER:-"arkime"}
PGROUP=${PGROUP:-"arkime"}

ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS=${ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS:-300}
[[ "${ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS}" =~ ^[0-9]+$ ]] || ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS=300
PCAP_IFACE=${PCAP_IFACE:-}
PCAP_FILTER=${PCAP_FILTER:-}
PCAP_ROTATE_MINUTES=${PCAP_ROTATE_MINUTES:-10}
PCAP_ROTATE_MEGABYTES=${PCAP_ROTATE_MEGABYTES:-4096}
PCAP_SNAPLEN=${PCAP_SNAPLEN:-0}
PCAP_TCPDUMP_FILENAME_PATTERN=${PCAP_TCPDUMP_FILENAME_PATTERN:-%Y%m%d%H%M%S.pcap}

OPENSEARCH_PRIMARY=${OPENSEARCH_PRIMARY:-"opensearch-local"}
OPENSEARCH_URL=${OPENSEARCH_URL:-"https://opensearch:9200"}
OPENSEARCH_PRIMARY=${OPENSEARCH_PRIMARY:-"opensearch-local"}
OPENSEARCH_SSL_CERTIFICATE_VERIFICATION=${OPENSEARCH_SSL_CERTIFICATE_VERIFICATION:-"false"}
OPENSEARCH_CREDS_CONFIG_FILE=${OPENSEARCH_CREDS_CONFIG_FILE:-"/var/local/curlrc/.opensearch.primary.curlrc"}
if [[ -r "$OPENSEARCH_CREDS_CONFIG_FILE" ]]; then
  CURL_CONFIG_PARAMS=(
    --config
    "$OPENSEARCH_CREDS_CONFIG_FILE"
    )
else
  CURL_CONFIG_PARAMS=()
fi

NODE_NAME=${PCAP_NODE_NAME}
NODE_HOST=${ARKIME_LIVE_NODE_HOST}
[[ -z "${NODE_HOST}" ]] && [[ -n "${NODE_NAME}" ]] && NODE_HOST="${NODE_NAME}"
NODE_ARGS=()
[[ -n "$NODE_NAME" ]] && NODE_ARGS+=( --node ) && NODE_ARGS+=( "$NODE_NAME" )
[[ -n "$NODE_HOST" ]] && NODE_ARGS+=( --host ) && NODE_ARGS+=( "$NODE_HOST" )

rm -f /var/run/arkime/initialized /var/run/arkime/runwise

# make sure TLS certificates exist prior to starting up
CERT_FILE=$ARKIME_DIR/etc/viewer.crt
KEY_FILE=$ARKIME_DIR/etc/viewer.key
if ( [[ ! -f "$CERT_FILE" ]] || [[ ! -f "$KEY_FILE" ]] ) && [[ -x /usr/local/bin/self_signed_key_gen.sh ]]; then
  rm -f "$CERT_FILE" "$KEY_FILE" ./newcerts
  pushd $ARKIME_DIR/etc/ >/dev/null 2>&1
  /usr/local/bin/self_signed_key_gen.sh -n -o ./newcerts >/dev/null 2>&1
  mv ./newcerts/server.crt "$CERT_FILE"
  mv ./newcerts/server.key "$KEY_FILE"
  rm -rf ./newcerts
  popd >/dev/null 2>&1
fi

# download and/or update geo updates (see not in initarkime.sh about these proxy vars)
[[ -n "${HTTP_PROXY:-}" && -z "${http_proxy:-}" ]] && export http_proxy="$HTTP_PROXY"
[[ -n "${HTTPS_PROXY:-}" && -z "${https_proxy:-}" ]] && export https_proxy="$HTTPS_PROXY"
[[ -n "${NO_PROXY:-}" && -z "${no_proxy:-}" ]] && export no_proxy="$NO_PROXY"
$ARKIME_DIR/bin/arkime_update_geo.sh

# calculate tags
TAGS_ARGS=()
if [[ -n "${EXTRA_TAGS}" ]]; then
  while read EXTRA_TAG; do
    TAGS_ARGS+=( -t )
    TAGS_ARGS+=( "${EXTRA_TAG}" )
  done < <(echo "${EXTRA_TAGS}" | tr ',' '\n') # loop over ',' separated EXTRA_TAGS values
fi

# wait for the non-live Arkime to initialize the database
echo "Waiting for $OPENSEARCH_PRIMARY and Arkime initialization..."
if ! wait_for_arkime_backend; then
    echo "Arkime backend did not become ready within ${ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS} seconds"
    tcpdump_fallback
    exit $?
fi
echo "$OPENSEARCH_PRIMARY and Arkime are ready!"

# set (or remove) wiseURL and wise.so in config file
if [ -z "${ARKIME_WISE_SERVICE_URL+x}" ]; then
    # variable does not exist
    WISE_URL="http://arkime:8081"
elif [ -z "${ARKIME_WISE_SERVICE_URL}" ] || [ "${ARKIME_WISE_SERVICE_URL,,}" == "disabled" ]; then
    # variable exists but is empty, or is explicitly disabled
    WISE_URL=
else
    WISE_URL="${ARKIME_WISE_SERVICE_URL}"
fi
while [[ "$WISE_URL" == */ ]]; do WISE_URL="${WISE_URL%/}"; done

WISE_PLUGIN_FILE_BASE="wise.so"
WISE_PLUGIN_FILE_ESCAPED="$(echo "${WISE_PLUGIN_FILE_BASE}" | sed 's@\.@\\\.@g')"
sed -i "/plugins=.*${WISE_PLUGIN_FILE_ESCAPED}/s/;\?${WISE_PLUGIN_FILE_ESCAPED}//g" "${ARKIME_CONFIG_FILE}"

if [[ -n "${WISE_URL}" ]] && [[ ! "${WISE_URL}" =~ ^https?://(localhost|127\.0\.0\.1) ]]; then
    WISE_HTTP_RESPONSE=$(curl -skL --max-time 10 -A "arkime" -w "\n%{http_code}" "${WISE_URL}/_ns_/nstest.html")
    WISE_HTTP_STATUS=$(echo "${WISE_HTTP_RESPONSE}" | tail -1)
    WISE_HTTP_BODY=$(echo "${WISE_HTTP_RESPONSE}" | head -n -1)
    if [[ ( "${WISE_HTTP_STATUS}" == "401" || "${WISE_HTTP_STATUS}" == "403" ) || ( "${WISE_HTTP_STATUS}" == "200" && -n "${WISE_HTTP_BODY}" ) ]] && [[ "${WISE_URL}" != "http://arkime:8081" ]] && [[ -r "${OPENSEARCH_CREDS_CONFIG_FILE}" ]]; then
        # we failed auth, so let's grab creds from OPENSEARCH_CREDS_CONFIG_FILE and try that

        # get the username/password from the curl file (I already wrote python code to do this, so sue me)
        pushd "$(dirname $(realpath -e "${BASH_SOURCE[0]}"))" >/dev/null 2>&1
        WISE_USER_PASSWORD="$(python3 -c "import malcolm_utils; result=malcolm_utils.ParseCurlFile('${OPENSEARCH_CREDS_CONFIG_FILE}'); print(result['user']+'|'+result['password']);")"
        WISE_USER="$(echo "${WISE_USER_PASSWORD}" | cut -d'|' -f1)"
        WISE_PASSWORD="$(urlencodeall "$(echo "${WISE_USER_PASSWORD}" | cut -d'|' -f2-)")"
        popd >/dev/null 2>&1

        # extract the other stuff from WISE_URL to rebuild it
        # extract the protocol
        WISE_PROTOCOL=$(echo "${WISE_URL}" | grep "://" | sed -e's,^\(.*://\).*,\1,g')
        # Remove the PROTOCOL
        WISE_URL_NO_PROTOCOL=$(echo "${WISE_URL/$WISE_PROTOCOL/}")
        # Use tr: Make the PROTOCOL lower-case for easy string compare
        WISE_PROTOCOL=$(echo "${WISE_PROTOCOL}" | tr '[:upper:]' '[:lower:]')

        # Extract the old user and password (if any)
        OLD_WISE_USER_PASSWORD=$(echo "${WISE_URL_NO_PROTOCOL}" | grep "@" | cut -d"/" -f1 | rev | cut -d"@" -f2- | rev)

        # Extract the host:port
        if [ -n "${OLD_WISE_USER_PASSWORD}" ]; then
            # URL **had** credentials, strip them out from the host:port
            WISE_HOST_AND_PORT="${WISE_URL_NO_PROTOCOL/$OLD_WISE_USER_PASSWORD@/}"
        else
            # URL had **no** credentials—keep everything
            WISE_HOST_AND_PORT="$WISE_URL_NO_PROTOCOL"
        fi

        # smoosh them all together for the new URL
        TEST_WISE_URL="${WISE_PROTOCOL}${WISE_USER}:${WISE_PASSWORD}@${WISE_HOST_AND_PORT}"
        while [[ "$TEST_WISE_URL" == */ ]]; do TEST_WISE_URL="${TEST_WISE_URL%/}"; done
        WISE_URL="${TEST_WISE_URL}"
    fi
    # set the wiseURL in the config file
    sed -i "s|^\(wiseURL=\).*|\1""${WISE_URL}""|" "${ARKIME_CONFIG_FILE}"
    # append wise plugin filename to end of plugins= line in config file and uncomment it if necessary
    sed -i "s/^#*[[:space:]]*\(plugins=\)/\1${WISE_PLUGIN_FILE_BASE};/" "${ARKIME_CONFIG_FILE}"
    # squash semicolons
    sed -i 's/;\{2,\}/;/g' "${ARKIME_CONFIG_FILE}"
    # remove trailing semicolon from plugins= line if it exists
    sed -i "s/^\(plugins=.*\)[[:space:]]*;[[:space:]]*$/\1/" "${ARKIME_CONFIG_FILE}"

else
    # no wiseURL, plugin .so has been removed, comment-out wiseURL
    sed -i "s/^\(wiseURL=\)/# \1/" "${ARKIME_CONFIG_FILE}"
fi
unset WISE_URL
unset TEST_WISE_URL

# we haven't dropUser/dropGroup'ed yet, so make sure the regular user owns the files we just touched
[[ -n ${PUID} ]] && [[ -n ${PGID} ]] && chown -f -R ${PUID}:${PGID} "${ARKIME_DIR}"/etc/ || true

# this allows viewer to kick off
touch /var/run/arkime/initialized

echo "Arkime is initialized!"
echo

"${ARKIME_DIR}"/bin/capture --insecure "${TAGS_ARGS[@]}" "${NODE_ARGS[@]}" \
  -c "${ARKIME_DIR}"/etc/config.ini \
  -o pcapDir=/data/pcap/arkime-live \
  -o dropUser=${PUSER} \
  -o dropGroup=${PGROUP} \
  -o ecsEventProvider=arkime \
  -o ecsEventDataset=session
CAPTURE_STATUS=$?

if (( ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS > 0 )); then
    echo "Arkime live capture exited with status ${CAPTURE_STATUS}"
    tcpdump_fallback
    exit $?
fi

exit "${CAPTURE_STATUS}"
