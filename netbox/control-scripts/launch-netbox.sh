#!/usr/bin/env bash

# see https://github.com/netbox-community/netbox-docker/discussions/1662#discussioncomment-16773154

# NetBox 4.5+ uses Granian. Static files must match Django STATIC_URL ("/<base>/static/"
# when BASE_PATH is set). Many reverse proxies strip the external prefix and call the
# container at "/static/...", so we register both "/static" and "/<base>/static" when
# BASE_PATH is non-empty.

STATIC_ROOT="/opt/netbox/netbox/static/"

bp="${BASE_PATH:-}"
if [ -z "$bp" ]; then
  bp="$(
    { /opt/netbox/venv/bin/python -c "
import sys
sys.path.insert(0, '/opt/netbox/netbox')
try:
    import netbox.configuration as cfg
    print(cfg.BASE_PATH, end='')
except AttributeError:
    pass
" 2>/dev/null || true; } | tail -n 1
  )"
fi
bp="${bp#/}"
bp="${bp%/}"

static_args=(
  --static-path-route "/static"
  --static-path-mount "$STATIC_ROOT"
)
if [ -n "$bp" ]; then
  static_args+=(--static-path-route "/${bp}/static" --static-path-mount "$STATIC_ROOT")
fi

exec granian \
  --host "::" \
  --port "8080" \
  --interface "wsgi" \
  --no-ws \
  --workers "${GRANIAN_WORKERS:-4}" \
  --respawn-failed-workers \
  --backpressure "${GRANIAN_BACKPRESSURE:-${GRANIAN_WORKERS:-4}}" \
  --loop "uvloop" \
  --log \
  --log-level "info" \
  --access-log \
  --working-dir "/opt/netbox/netbox/" \
  "${static_args[@]}" \
  --static-path-dir-to-file index.html \
  --pid-file "/tmp/granian.pid" \
  "${GRANIAN_EXTRA_ARGS[@]}" \
  "netbox.granian:application"
