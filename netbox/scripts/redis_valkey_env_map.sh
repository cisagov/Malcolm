#!/usr/bin/env bash
set -e

while IFS='=' read -r name value; do
  if [[ "$name" == VALKEY_* ]]; then
    new_name="REDIS_${name#VALKEY_}"
    if [[ -z "${!new_name+x}" ]]; then
      export "${new_name}=${value}"
    fi
  fi
done < <(env)

exec "$@"
