#!/bin/bash

set -euo pipefail

# check if netbox is responding on its health check endpoint
curl --insecure --silent --fail "http://localhost:8080/netbox/api/" >/dev/null || exit 1

# if we got here, everything is good
exit 0 