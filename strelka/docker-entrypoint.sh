#!/usr/bin/env bash

set -euo pipefail

# expand REDIS environment variables into the appropriate config yaml files
FILES=(
  /etc/strelka/manager.yaml
  /etc/strelka/backend.yaml
  /etc/strelka/frontend.yaml
)

for FILE in "${FILES[@]}"; do
  if [[ -f "$FILE" ]]; then
    yq -i '
      .coordinator.addr = strenv(REDIS_CACHE_HOST) + ":" + strenv(REDIS_CACHE_PORT) |
      .coordinator.db = (strenv(REDIS_STRELKA_COORDINATOR_CACHE_DATABASE) | tonumber) |
      .coordinator.password = strenv(REDIS_PASSWORD) |
      .gatekeeper.addr = strenv(REDIS_CACHE_HOST) + ":" + strenv(REDIS_CACHE_PORT) |
      .gatekeeper.db = (strenv(REDIS_STRELKA_GATEKEEPER_CACHE_DATABASE) | tonumber) |
      .gatekeeper.password = strenv(REDIS_PASSWORD)
    ' "$FILE"
  fi
done

# Find the directory containing libcrypto.so, and add it to LD_LIBRARY_PATH
export LIBCRYPTO_DIR=$(dirname "$(find /usr/lib /lib -name 'libcrypto.so*' | head -n 1)")
export LD_LIBRARY_PATH="${LIBCRYPTO_DIR}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

[[ $# -gt 0 ]] && exec "$@"
