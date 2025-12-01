#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

if [[ ! ${LOGSTASH_HOST+x} ]]; then
  # variable does not exist at all, use default
  LOGSTASH_HOST="logstash:5044"
fi

if [[ -z "${LOGSTASH_HOST}" ]] || [[ "${LOGSTASH_HOST,,}" == "disabled" ]]; then
  # LOGSTASH_HOST exists, but is empty, or is explicitly disabled,
  # implying we are generating logs but *not* forwarding them. Just sleep.
  echo "No Logstash host specified, going to sleep" >&2
  sleep infinity
  exit 1

else
  PATH_HOME=
  PATH_CONFIG=
  PATH_DATA=
  CONFIG_FILE=
  MODULES=
  VERBOSE_FLAG=
  NETBOX_SITE=${NETBOX_DEFAULT_SITE:-}

  [[ -n "${EXTRA_TAGS}" ]] || EXTRA_TAGS=

  SLEEP_SEC=0

  while getopts vh:c:d:f:m:n:t:s: opts; do
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
        n)
          NETBOX_SITE="${OPTARG}"
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

  cp "${CONFIG_FILE}" "${TMP_CONFIG_FILE}"

  # add the extra tags to all logs
  if [[ -n "${EXTRA_TAGS}" ]]; then
    readarray -td '' EXTRA_TAGS_ARRAY < <(awk '{ gsub(/,/,"\0"); print; }' <<<"${EXTRA_TAGS},"); unset 'EXTRA_TAGS_ARRAY[-1]';
    yq -P eval "(.\"filebeat.inputs\"[] | select(.type == \"log\").tags) += $(jo -a "${EXTRA_TAGS_ARRAY[@]}")" -i "${TMP_CONFIG_FILE}"
  fi

  # for hedgehog profile, add `_filebeat_zeek_hedgehog` just to the Zeek logs
  if [[ "${MALCOLM_PROFILE:-malcolm}" == "hedgehog" ]]; then
     yq -P eval '
      (
        .["filebeat.inputs"][]
        | select(
            (.type | test("(?i)log")) and
            (.tags[] | test("^_filebeat_zeek"))
          )
      ).tags += ["_filebeat_zeek_hedgehog"]
    ' -i "${TMP_CONFIG_FILE}"
  fi


  if [[ -n "${NETBOX_SITE}" ]]; then
    yq -P eval ".processors |= (. // []) | .processors += [{\"add_fields\": {\"target\": \"netbox\", \"fields\": {\"site\": \"${NETBOX_SITE}\"}}}]" -i "${TMP_CONFIG_FILE}"
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

fi # LOGSTASH_HOST check

