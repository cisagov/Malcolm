#!/bin/bash

set -euo pipefail

# check if freq-server is responding on its health check endpoint
curl --insecure --silent --fail "http://localhost:10004" >/dev/null || exit 1

# if we got here, everything is good
exit 0 