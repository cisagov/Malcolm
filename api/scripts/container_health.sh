#!/bin/bash

set -euo pipefail

# check if api is responding on its health check endpoint
curl --insecure --silent --fail "http://localhost:5000/mapi/ping" >/dev/null || exit 1

# if we got here, everything is good
exit 0 