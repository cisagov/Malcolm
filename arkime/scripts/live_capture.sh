#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

function urlencodeall() {
    local length="${#1}"
    for (( i = 0; i < length; i++ )); do
        local c="${1:i:1}"
        printf '%%%02X' "'$c"
    done
}

ARKIME_DIR=${ARKIME_DIR:-"/opt/arkime"}
ARKIME_CONFIG_FILE="${ARKIME_DIR}"/etc/config.ini
CERT_FILE="${ARKIME_DIR}"/etc/viewer.crt
KEY_FILE="${ARKIME_DIR}"/etc/viewer.key
PUSER=${PUSER:-"arkime"}
PGROUP=${PGROUP:-"arkime"}

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

# download and/or update geo updates
$ARKIME_DIR/bin/arkime_update_geo.sh

# calculate tags
TAGS_ARGS=()
if [[ -n "${EXTRA_TAGS}" ]]; then
  while read EXTRA_TAG; do
    TAGS_ARGS+=( -t )
    TAGS_ARGS+=( "${EXTRA_TAG}" )
  done < <(echo "${EXTRA_TAGS}" | tr ',' '\n') # loop over ',' separated EXTRA_TAGS values
fi

# wait patiently for the non-live Arkime to initialize the database
echo "Giving $OPENSEARCH_PRIMARY time to start..."
/usr/local/bin/opensearch_status.sh -t malcolm_template 2>&1 && echo "$OPENSEARCH_PRIMARY is running!"
echo "Giving Arkime time to initialize..."
sleep 5
until (( $(curl "${CURL_CONFIG_PARAMS[@]}" -fs -XGET -H'Content-Type: application/json' "${OPENSEARCH_URL}/_cat/indices/arkime_users_v*" | wc -l) >= 1 )); do
    sleep 1
done

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

WISE_PLUGIN_FILE_BASE="wise.so"
WISE_PLUGIN_FILE_ESCAPED="$(echo "${WISE_PLUGIN_FILE_BASE}" | sed 's@\.@\\\.@g')"
sed -i "/plugins=.*${WISE_PLUGIN_FILE_ESCAPED}/s/;\?${WISE_PLUGIN_FILE_ESCAPED}//g" "${ARKIME_CONFIG_FILE}"

if [[ -n "${WISE_URL}" ]] && [[ ! "${WISE_URL}" =~ ^https?://(localhost|127\.0\.0\.1) ]]; then
    WISE_HTTP_STATUS=$(curl -sk --max-time 10 -A "arkime" -o /dev/null -w "%{http_code}" "${WISE_URL}")
    if [[ "${WISE_HTTP_STATUS}" == "401" || "${WISE_HTTP_STATUS}" == "403" ]] && [[ "${WISE_URL}" != "http://arkime:8081" ]] && [[ -r "${OPENSEARCH_CREDS_CONFIG_FILE}" ]]; then
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

        # see if that works better, and if so, use it
        curl -skf --max-time 10 -A "arkime" -o /dev/null "${TEST_WISE_URL}" && WISE_URL="${TEST_WISE_URL}"
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
