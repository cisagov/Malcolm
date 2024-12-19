#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.
PATH_HOME=
PATH_CONFIG=
PATH_DATA=
CONFIG_FILE=
MODULES=
VERBOSE_FLAG=
[[ -n "${EXTRA_TAGS}" ]] || EXTRA_TAGS=
SLEEP_SEC=0

while getopts vh:c:d:f:m:t:s: opts; do
   case ${opts} in
      v)
        VERBOSE_FLAG="-v"
        set -x
        ;;
      h)
        PATH_HOME="${OPTARG}"
        ;;
      c)
        PATH_CONFIG="${OPTARG}"
        ;;
      d)
        PATH_DATA="${OPTARG}"
        ;;
      f)
        CONFIG_FILE="${OPTARG}"
        ;;
      m)
        MODULES="${OPTARG}"
        ;;
      t)
        EXTRA_TAGS="${OPTARG}"
        ;;
      s)
        SLEEP_SEC="${OPTARG}"
        ;;
      ?)
        echo "script usage: $(basename "$0") [-v (verbose)] -h <path.home> -c <path.config> -d <path.data> -c <config YML> [-m <module>] [-s <sleep sec.>]" >&2
        exit 1
        ;;
   esac
done

INSTANCE_UID="$(tr -dc A-Za-z0-9 </dev/urandom 2>/dev/null | head -c 16; echo)"
(( ${#INSTANCE_UID} == 16 )) || INSTANCE_UID=$RANDOM

TMP_CONFIG_FILE="$(dirname "$(realpath "${CONFIG_FILE}")")/filebeat.$INSTANCE_UID.yml"

function cleanup {
    rm -f "${TMP_CONFIG_FILE}"
}

trap cleanup EXIT

if [[ -n "${EXTRA_TAGS}" ]]; then
  readarray -td '' EXTRA_TAGS_ARRAY < <(awk '{ gsub(/,/,"\0"); print; }' <<<"${EXTRA_TAGS},"); unset 'EXTRA_TAGS_ARRAY[-1]';
  yq -P eval "(.\"filebeat.inputs\"[] | select(.type == \"log\").tags) += $(jo -a "${EXTRA_TAGS_ARRAY[@]}")" "${CONFIG_FILE}" > "${TMP_CONFIG_FILE}"
else
  cp "${CONFIG_FILE}" "${TMP_CONFIG_FILE}"
fi

MODULES_ARGS=()
if [[ -n "${MODULES}" ]]; then
  readarray -td '' MODULES_ARRAY < <(awk '{ gsub(/,/,"\0"); print; }' <<<"${MODULES},")
  unset 'MODULES_ARRAY[-1]'
  MODULES_ARGS=('-modules' "${MODULES_ARRAY[@]}")
fi

sleep ${SLEEP_SEC}

/usr/local/bin/docker-entrypoint -e --strict.perms=false \
  --path.home "${PATH_HOME}" \
  --path.config "${PATH_CONFIG}" \
  --path.data "${PATH_DATA}" \
  -c "${TMP_CONFIG_FILE}" "${MODULES_ARGS[@]}"

popd  >/dev/null 2>&1


