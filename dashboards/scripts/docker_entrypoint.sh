#!/bin/bash

# tweak some things in the opensearch_dashboards.yml file for opensearch output
ORIG_YML=/usr/share/opensearch-dashboards/config/opensearch_dashboards.orig.yml
FINAL_YML=/usr/share/opensearch-dashboards/config/opensearch_dashboards.yml

OPENSEARCH_SSL_CERTIFICATE_VERIFICATION=${OPENSEARCH_SSL_CERTIFICATE_VERIFICATION:-"false"}
OPENSEARCH_LOCAL=${OPENSEARCH_LOCAL:-"true"}
OPENSEARCH_CREDS_CONFIG_FILE=${OPENSEARCH_CREDS_CONFIG_FILE:-"/var/local/opensearch.primary.curlrc"}

if [[ -f "$ORIG_YML" ]]; then
    cp "$ORIG_YML" "$FINAL_YML"

    # get the new username/password from the curl file (I already wrote python code to do this, so sue me)
    OPENSSL_USER=
    OPENSSL_PASSWORD=
    if [[ "$OPENSEARCH_LOCAL" == "false" ]] && [[ -r "$OPENSEARCH_CREDS_CONFIG_FILE" ]]; then
        pushd "$(dirname $(realpath -e "${BASH_SOURCE[0]}"))" >/dev/null 2>&1
        NEW_USER_PASSWORD="$(python3 -c "import malcolm_common; result=malcolm_common.ParseCurlFile('$OPENSEARCH_CREDS_CONFIG_FILE'); print(result['user']+'|'+result['password']);")"
        OPENSSL_USER="$(echo "$NEW_USER_PASSWORD" | cut -d'|' -f1)"
        OPENSSL_PASSWORD="$(echo "$NEW_USER_PASSWORD" | cut -d'|' -f2-)"
        popd >/dev/null 2>&1
    fi

    # replace things in the YML file for dashboards to use
    [[ -n "$OPENSSL_USER" ]] && \
        sed -i "s/_MALCOLM_DASHBOARDS_OPENSEARCH_USER_/$OPENSSL_USER/g" "$FINAL_YML" || \
        sed -i '/_MALCOLM_DASHBOARDS_OPENSEARCH_USER_/d' "$FINAL_YML"

    [[ -n "$OPENSSL_PASSWORD" ]] && \
        sed -i "s/_MALCOLM_DASHBOARDS_OPENSEARCH_PASSWORD_/$OPENSSL_PASSWORD/g" "$FINAL_YML" || \
        sed -i '/_MALCOLM_DASHBOARDS_OPENSEARCH_PASSWORD_/d' "$FINAL_YML"

    [[ "$OPENSEARCH_SSL_CERTIFICATE_VERIFICATION" == "true" ]] && \
        SSL_VERIFICATION_MODE=certificate || \
        SSL_VERIFICATION_MODE=none

    [[ "$OPENSEARCH_LOCAL" == "false" ]] && \
        sed -i "s/_MALCOLM_DASHBOARDS_OPENSEARCH_SSL_VERIFICATION_MODE_/$SSL_VERIFICATION_MODE/g" "$FINAL_YML" || \
        sed -i '/_MALCOLM_DASHBOARDS_OPENSEARCH_SSL_VERIFICATION_MODE_/d' "$FINAL_YML"

    chmod 600 "$FINAL_YML"
fi

# start the default dashboards entrypoint
exec "$@"
