#!/usr/bin/env bash

set -euo pipefail

FILES=(
  /etc/strelka/manager.yaml
  /etc/strelka/backend.yaml
  /etc/strelka/frontend.yaml
)

for FILE in "${FILES[@]}"; do
  if [[ -f "$FILE" ]]; then
    yq -i '
      .coordinator.addr = strenv(REDIS_CACHE_HOST) + ":" + strenv(REDIS_CACHE_PORT) |
      .coordinator.db = strenv(REDIS_STRELKA_COORDINATOR_CACHE_DATABASE) |
      .coordinator.password = strenv(REDIS_PASSWORD) |
      .gatekeeper.addr = strenv(REDIS_CACHE_HOST) + ":" + strenv(REDIS_CACHE_PORT) |
      .gatekeeper.db = strenv(REDIS_STRELKA_GATEKEEPER_CACHE_DATABASE) |
      .gatekeeper.password = strenv(REDIS_PASSWORD)
    ' "$FILE"
  fi
done

[[ $# -gt 0 ]] && exec "$@"
