#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

AUTH_URL="https://localhost"
if [[ -d "$HOME"/Malcolm ]] && [[ -f "$HOME"/Malcolm/.configured ]] && [[ -f "$HOME"/Malcolm/config/auth-common.env ]]; then
  pushd "$HOME"/Malcolm >/dev/null 2>&1
  source "$HOME"/Malcolm/config/auth-common.env
  if [[ "$NGINX_AUTH_MODE" == "basic" ]]; then
    AUTH_URL="https://localhost/auth/"
  elif [[ "$NGINX_AUTH_MODE" == keycloak* ]] && [[ -f "$HOME"/Malcolm/config/keycloak.env ]]; then
    source "$HOME"/Malcolm/config/keycloak.env
    [[ -n "$KEYCLOAK_AUTH_URL" ]] && AUTH_URL="$KEYCLOAK_AUTH_URL"
  fi
  popd >/dev/null 2>&1
fi
[[ -n "$AUTH_URL" ]] && nohup /usr/bin/firefox "$AUTH_URL" >/dev/null 2>&1 </dev/null &
