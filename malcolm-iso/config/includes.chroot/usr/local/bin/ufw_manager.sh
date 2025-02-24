#!/usr/bin/env bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

set -euo pipefail

SCRIPT_DIR=$(dirname "$(realpath "$0")")
SCRIPT_NAME=$(basename "$0")

# Actions passed directly in to UFW (with "delete" prepended if -d is specified):
#   - allow
#   - deny
#   - reject
#   - limit
# Actions converted to the appropriate status command:
#   - status
#   - numbered
# Other actions:
#   - reset:
#        Reads the contents of UFW_STATUS_YML and performs "delete" operations
#        for all of the entries contained therein.
ALLOWED_ACTIONS=( "allow" "deny" "reject" "limit" "reset" "status" "numbered" )
ACTION=status
VERBOSE=0
DELETE=
RESET_FILE=
YQ="$(command -v yq || echo yq)"

# We'll keep a ~/Malcolm/.ufw-rules.yml file to keep track of entries that have been
#   previously added to the firewall.
MAIN_USER="$(id -nu 1000)"
MAIN_USER_HOME=
[[ -n $MAIN_USER ]] && MAIN_USER_HOME="$(getent passwd "$MAIN_USER" | cut -d: -f6)" || MAIN_USER_HOME=
[[ -d $MAIN_USER_HOME ]] && UFW_STATUS_YML="$MAIN_USER_HOME/Malcolm/.ufw-rules.yml" || UFW_STATUS_YML=

while getopts a:du:y:v opts; do
   case ${opts} in
      a) ACTION=${OPTARG,,} ;;
      d) DELETE=delete ;;
      v) VERBOSE=1 ;;
      u) UFW_STATUS_YML=${OPTARG} ;;
      y) YQ=${OPTARG} ;;
   esac
done
# remaining command-line options are UFW rule args
shift "$(($OPTIND -1))"
RULE=("${@}")

[[ $VERBOSE == 1 ]] && set -x

if [[ ! -x /usr/sbin/ufw ]]; then
  echo "/usr/sbin/ufw does not exist or is not executable" >&2
  exit 1
elif ! ( printf "%s\n" "${ALLOWED_ACTIONS[@]}" | grep -qx "$ACTION" ); then
  echo "\"$ACTION\" is not an allowed action" >&2
  exit 1
fi

function add_to_yml {
  local ACTION_ARG=$1
  local -n RULE_ARG=$2
  if [[ -n "$UFW_STATUS_YML" ]]; then
    if [[ ! -f "$UFW_STATUS_YML" ]] || [[ ! -s "$UFW_STATUS_YML" ]]; then
      echo 'rules: []' > "$UFW_STATUS_YML"
      chown 1000:1000 "$UFW_STATUS_YML"
      chmod 600 "$UFW_STATUS_YML"
    fi
    export ACTION_ENV=$ACTION_ARG
    export RULE_ENV="$(IFS=,; echo "${RULE_ARG[*]}")"
    export DATE_ENV=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    "$YQ" -i '.rules += [{"action": strenv(ACTION_ENV), "rule": (strenv(RULE_ENV) | split(",")), "timestamp": strenv(DATE_ENV)}]' "$UFW_STATUS_YML"
  fi
}

function delete_from_yml {
  local ACTION_ARG=$1
  local -n RULE_ARG=$2
  if [[ -n "$UFW_STATUS_YML" ]]; then
    if [[ ! -f "$UFW_STATUS_YML" ]] || [[ ! -s "$UFW_STATUS_YML" ]]; then
      echo 'rules: []' > "$UFW_STATUS_YML"
      chown 1000:1000 "$UFW_STATUS_YML"
      chmod 600 "$UFW_STATUS_YML"
    fi
    export ACTION_ENV=$ACTION_ARG
    export RULE_ENV="$(IFS=,; echo "${RULE_ARG[*]}")"
    "$YQ" -i '.rules |= map(select(
      (.action != strenv(ACTION_ENV)) or
      (.rule | join(",")) != (strenv(RULE_ENV) | split(",") | join(","))
    ))' "$UFW_STATUS_YML" || true # a failed delete is non-fatal
  fi
}

if [[ $ACTION == "status" ]]; then
  /usr/sbin/ufw status

elif [[ $ACTION == "numbered" ]]; then
  /usr/sbin/ufw status numbered

elif [[ $ACTION == "reset" ]]; then
  if [[ -n "$UFW_STATUS_YML" ]] && [[ -f "$UFW_STATUS_YML" ]]; then
    # make a copy of the YML file to read entries out of so we're not modifying the same one we're reading
    TEMP_YML=$(mktemp --suffix=.yml)
    cp "$UFW_STATUS_YML" "$TEMP_YML"
    for entry in $("$YQ" '.rules | keys | .[]' "$TEMP_YML"); do
      ACTION_VAL=$("$YQ" -r ".rules[$entry].action" "$TEMP_YML")
      RULE_ITEMS=($("$YQ" -r ".rules[$entry].rule[]" "$TEMP_YML"))
      # recursively call this script for to delete the rule (failures are non-fatal, what else can we do?)
      [[ $VERBOSE == 1 ]] && VERBOSE_FLAG=-v || VERBOSE_FLAG=
      "$SCRIPT_DIR"/"$SCRIPT_NAME" $VERBOSE_FLAG -d -a "$ACTION_VAL" -u "$UFW_STATUS_YML" -y "$YQ" "${RULE_ITEMS[@]}" || true
    done
    rm -f "$TEMP_YML"
  else
    echo "The YML file tracking UFW rules does not exist or was not defined" >&2
    exit 1
  fi

else
  # call UFW to add or delete the rule
  /usr/sbin/ufw $DELETE $ACTION "${RULE[@]}"

  # track rules created using this script in a YML file that we can use
  #   later to reset the whole thing back to a clean state
  if [[ -n "$UFW_STATUS_YML" ]]; then
    mkdir -p "$(dirname "$UFW_STATUS_YML")"

    # we do a delete first (even if we're doing an add) to avoid duplicate entries in the YML

    # remove the action from our YML file
    delete_from_yml $ACTION RULE

    # now if we're adding, add the action to the YML file
    [[ -z "$DELETE" ]] && add_to_yml $ACTION RULE

  fi # $UFW_STATUS_YML file check
fi # $ACTION check