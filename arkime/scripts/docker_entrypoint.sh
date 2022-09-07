#!/bin/bash

function urlencodeall() {
    local length="${#1}"
    for (( i = 0; i < length; i++ )); do
        local c="${1:i:1}"
        printf '%%%02X' "'$c"
    done
}

ARKIME_DIR=${ARKIME_DIR:-"/opt/arkime"}

OPENSEARCH_URL_FINAL=${OPENSEARCH_URL:-"http://opensearch:9200"}
OPENSEARCH_LOCAL=${OPENSEARCH_LOCAL:-"true"}
OPENSEARCH_CREDS_CONFIG_FILE=${OPENSEARCH_CREDS_CONFIG_FILE:-"/var/local/opensearch.primary.curlrc"}
if [[ "$OPENSEARCH_LOCAL" == "false" ]] && [[ -r "$OPENSEARCH_CREDS_CONFIG_FILE" ]]; then
    # need to build the opensearch URL (including username/password) by combining
    # OPENSEARCH_URL and parameters from OPENSEARCH_CREDS_CONFIG_FILE

    # get the new username/password from the curl file (I already wrote python code to do this, so sue me)
    pushd "$(dirname $(realpath -e "${BASH_SOURCE[0]}"))" >/dev/null 2>&1
    NEW_USER_PASSWORD="$(python3 -c "import malcolm_common; result=malcolm_common.ParseCurlFile('$OPENSEARCH_CREDS_CONFIG_FILE'); print(result['user']+'|'+result['password']);")"
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
    chmod 600 "${ARKIME_DIR}"/etc/config.ini
fi
unset OPENSEARCH_URL_FINAL

# start supervisor or whatever the default command is
exec "$@"
