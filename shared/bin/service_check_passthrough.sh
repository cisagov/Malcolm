#!/bin/bash

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

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
DISABLED=
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
SERVICE_UCASE="$(echo ${SERVICE^^} | tr '-' '_')"

# if disabled wasn't specified, but service was, check environment variables
if [[ -z "$DISABLED" ]] && [[ -n "$SERVICE" ]]; then
    DISABLED_VARNAME="${SERVICE_UCASE}_DISABLED"
    if [[ -n "${!DISABLED_VARNAME}" ]] && \
       [[ "${!DISABLED_VARNAME}" != "0" ]] && \
       [[ "${!DISABLED_VARNAME}" != "false" ]] && \
       [[ "${!DISABLED_VARNAME}" != "no" ]] && \
       [[ "${!DISABLED_VARNAME}" != "f" ]] && \
       [[ "${!DISABLED_VARNAME}" != "n" ]]; then
        DISABLED=1
    fi
    LOCAL_VARNAME="${SERVICE_UCASE}_LOCAL"
    if [[ -n "${!LOCAL_VARNAME}" ]] && \
       ( [[ "${!LOCAL_VARNAME}" == "0" ]] || \
         [[ "${!LOCAL_VARNAME}" == "false" ]] || \
         [[ "${!LOCAL_VARNAME}" == "no" ]] || \
         [[ "${!LOCAL_VARNAME}" == "f" ]] || \
         [[ "${!LOCAL_VARNAME}" == "n" ]] ); then
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
        elif [[ "$SERVICE" == "file-monitor" ]]; then
            PORT=8440
        elif [[ "$SERVICE" == "freq" ]]; then
            PORT=10004
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

if [[ -n "$DISABLED" ]]; then
    pushd "$(mktemp -d)" >/dev/null 2>&1

    if [[ "$FORMAT" == "json" ]]; then
        cat << EOF > index.html
{ "error": { "code": 422, "message": "The local service $SERVICE has been disabled." } }
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
        goStatic -path "$(pwd)" -fallback "index.html" -port $PORT
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
        echo "No tool available for service HTTP" >&2
    fi

    popd >/dev/null 2>&1

else
    # the service isn't disabled, just do the service already
    exec "$@"
fi

