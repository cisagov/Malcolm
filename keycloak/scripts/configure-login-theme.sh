#!/usr/bin/env bash

# Copyright (c) 2026 Battelle Energy Alliance, LLC. All rights reserved.

# Run after kcadm authentication. Change only an unset login theme; never replace
# an administrator's explicit selection or configure other theme types.
set -euo pipefail

ADM_SCRIPT=${1:?Keycloak admin CLI is required}
REALM=${2:?Keycloak realm is required}
LOGIN_THEME=${3-malcolm}
[[ -n "${LOGIN_THEME}" ]] || exit 0

if ! REALM_JSON=$("${ADM_SCRIPT}" get "realms/${REALM}" --fields loginTheme); then
    echo "Unable to read Keycloak login theme for ${REALM}" >&2
    exit 1
fi
if ! CURRENT_THEME=$(jq -er '
    if type == "object" and (has("error") | not) and (has("errorMessage") | not) and (.loginTheme == null or (.loginTheme | type) == "string")
    then (.loginTheme // "") else error("invalid realm response") end
' <<< "${REALM_JSON}"); then
    echo "Invalid Keycloak realm response; leaving login theme unchanged" >&2
    exit 1
fi
if [[ -z "${CURRENT_THEME}" ]]; then
    # Use a JSON file rather than interpreting a theme name as a CLI expression.
    THEME_FILE=$(mktemp)
    trap 'rm -f "${THEME_FILE}"' EXIT
    jq -n --arg theme "${LOGIN_THEME}" '{loginTheme: $theme}' > "${THEME_FILE}"
    "${ADM_SCRIPT}" update "realms/${REALM}" -f "${THEME_FILE}"
fi
