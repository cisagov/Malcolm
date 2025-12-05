#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

# This script will check command-line parameters and environment variables to see
# if the service (determined by the hostname, unless otherwise specified) is
# disabled. If it is disabled, it will attempt to serve a static HTTP page
# to that effect. If it is not disabled, it will just pass through to the
# default command.

###############################################################################
# script options
set -o pipefail
shopt -s nocasematch
ENCODING="utf-8"

###############################################################################
# command-line parameters
# options
# -v          (verbose)
# -d          (service is disabled)
# -s service  (service name)
# -p port     (port)
# -f format   (http|json)
VERBOSE_FLAG=
SERVICE=
DISABLED=0
PORT=
FORMAT=
while getopts 'vds:p:f:' OPTION; do
  case "$OPTION" in
    v)
      VERBOSE_FLAG="-v"
      set -x
      ;;

    d)
      DISABLED=1
      ;;

    s)
      SERVICE="$OPTARG"
      ;;

    p)
      PORT="$OPTARG"
      ;;

    f)
      FORMAT="$OPTARG"
      ;;

    ?)
      echo "script usage: $(basename $0) [-v (verbose)] [-d (disabled)] [-s <service>] [-p <port>] [-f <format>]" >&2
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"

is_truthy_disabled() {
    case "${1,,}" in
        ""|0|false|no|f|n) return 1 ;;  # service is NOT disabled
    esac
    return 0                            # service IS disabled
}

is_disabled_because_not_local() {
    case "${1,,}" in
        0|false|no|f|n) return 0 ;;     # service is NOT local, so it IS disabled locally
    esac
    return 1                            # service IS local, so it is NOT disabled locally
}

is_host_net() {
    # If eth0 doesn't exist, this is extremely likely host net
    [ -e /sys/class/net/eth0 ] || return 0

    # Count host-like interfaces (docker0, veth*, wlan*, etc.)
    for iface in /sys/class/net/*; do
        b=$(basename "$iface")
        case "$b" in
            lo|eth0) ;;  # normal container
            *)
                # More than lo+eth0 == probably host net
                return 0
                ;;
        esac
    done

    return 1
}

# if service not specified via command line, use hostname instead
if [[ -z "$SERVICE" ]]; then
    if command -v hostname >/dev/null 2>&1; then
        SERVICE="$(hostname -s)"
    elif hostnamectl status >/dev/null 2>&1; then
        SERVICE="$(hostnamectl status | grep "hostname" | cut -d: -f2- | xargs echo)"
    elif [[ -r /proc/sys/kernel/hostname ]] >/dev/null 2>&1; then
        SERVICE="$(head -n 1 /proc/sys/kernel/hostname)"
    elif [[ -s /etc/hostname ]] >/dev/null 2>&1; then
        SERVICE="$(head -n 1 /etc/hostname)"
    elif command -v uname >/dev/null 2>&1; then
        SERVICE="$(uname -a | awk '{print $2}')"
    fi
fi

# if disabled wasn't specified, but service was, check environment variables
if [[ "$DISABLED" == "0" ]] && [[ -n "$SERVICE" ]]; then

    SERVICE_UCASE="$(echo ${SERVICE^^} | tr '-' '_')"
    DISABLED_VARNAME="${SERVICE_UCASE}_DISABLED"
    LOCAL_VARNAME="${SERVICE_UCASE}_LOCAL"

    is_truthy_disabled "${!DISABLED_VARNAME}" && DISABLED=1
    [[ "$DISABLED" == "0" ]] && is_disabled_because_not_local "${!LOCAL_VARNAME}" && DISABLED=1

    # kinda hacky special cases
    if [[ "$SERVICE" == "opensearch" ]] && [[ "${OPENSEARCH_PRIMARY:-opensearch-local}" != "opensearch-local" ]]; then
        DISABLED=1
    fi
    if [[ "$SERVICE" == "dashboards" ]] && \
       [[ "${OPENSEARCH_PRIMARY:-opensearch-local}" != "opensearch-local" ]] && \
       [[ "${OPENSEARCH_PRIMARY:-opensearch-local}" != "opensearch-remote" ]]; then
        DISABLED=1
    fi
    if [[ "$SERVICE" == "keycloak" ]] && [[ "${NGINX_AUTH_MODE:-keycloak}" != "keycloak" ]]; then
        DISABLED=1
    fi
    if [[ "$SERVICE" == "netbox" ]] && [[ "${NETBOX_MODE:-local}" != "local" ]]; then
        DISABLED=1
    fi
    if ( [[ "$SERVICE_UCASE" == STRELKA* ]] || [[ "$SERVICE_UCASE" == FILESCAN* ]] ) && \
        is_truthy_disabled "${PIPELINE_DISABLED:-false}"; then
        DISABLED=1
    fi
fi

# if port and/or format not specified via command line, make some inferences based on service
if [[ -n "$SERVICE" ]]; then
    if [[ -z "$PORT" ]]; then
        if [[ "$SERVICE" == "api" ]]; then
            PORT=5000
        elif [[ "$SERVICE" == "arkime" ]]; then
            PORT=8005
        elif [[ "$SERVICE" == "dashboards" ]]; then
            PORT=5601
        elif [[ "$SERVICE" == "dashboards-helper" ]]; then
            PORT=28991
        elif [[ "$SERVICE" == "filescan" ]]; then
            PORT=8006
        elif [[ "$SERVICE" == "freq" ]]; then
            PORT=10004
        elif [[ "$SERVICE" == "keycloak" ]]; then
            PORT=8080
        elif [[ "$SERVICE" == "logstash" ]]; then
            PORT=9600
        elif [[ "$SERVICE" == "netbox" ]]; then
            PORT=8080
        elif [[ "$SERVICE" == "opensearch" ]]; then
            PORT=9200
        fi
    fi
    [[ -z "$FORMAT" ]] && \
        ([[ "$SERVICE" == "api" ]] || \
         [[ "$SERVICE" == "dashboards-helper" ]] || \
         [[ "$SERVICE" == "freq" ]] || \
         [[ "$SERVICE" == "logstash" ]] || \
         [[ "$SERVICE" == "netbox" ]] || \
         [[ "$SERVICE" == "opensearch" ]]) && FORMAT=json
fi
[[ -z "$PORT" ]] && PORT=80
[[ -z "$FORMAT" ]] && FORMAT=http

if [[ "$DISABLED" == "1" ]]; then
    echo "The local service $SERVICE has been disabled." >&2

    if is_host_net; then
        # don't go exposing things if we're in host networking mode
        command -v sleep >/dev/null 2>&1 && sleep infinity

    else
        pushd "$(mktemp -d)" >/dev/null 2>&1

        if [[ "$FORMAT" == "json" ]]; then
            cat << EOF > index.html
{ "error": { "code": 501, "message": "The local service $SERVICE has been disabled." } }
EOF
        else
            cat << EOF > index.html
<html>
<header><title>$SERVICE Disabled</title></header>
<body>
<h1>The local service $SERVICE has been disabled.</h1>
<p>Refer to the <a href="/readme/" onclick="javascript:event.target.port=443">Malcolm documentation</a>.</p>
</body>
</html>
EOF
        fi # json vs http

        if command -v goStatic >/dev/null 2>&1; then
            goStatic -vhost "" -path "$(pwd)" -fallback "index.html" -port $PORT
        elif command -v python3 >/dev/null 2>&1; then
            python3 -m http.server --bind 0.0.0.0 $PORT
        elif command -v python >/dev/null 2>&1; then
            python -m SimpleHTTPServer $PORT
        elif command -v ruby >/dev/null 2>&1; then
            ruby -run -ehttpd --bind-address=0.0.0.0 --port=$PORT .
        elif command -v http-server >/dev/null 2>&1; then
            http-server -a 0.0.0.0 --port $PORT
        elif command -v php >/dev/null 2>&1; then
            php -S 0.0.0.0:$PORT -t .
        else
            echo "No tool available for $FORMAT disabled status page" >&2
            command -v sleep >/dev/null 2>&1 && sleep infinity
        fi

        popd >/dev/null 2>&1
    fi

else
    # the service isn't disabled, just play the song, Schneebly!
    exec "$@"
fi

