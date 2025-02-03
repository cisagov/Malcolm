#!/bin/bash

set -euo pipefail

# check if arkime is responding on its health check endpoint
curl --insecure --silent --fail "https://localhost:8005/_ns_/nstest.html" >/dev/null || exit 1

# if we got here, everything is good
exit 0 