#!/bin/bash

set -euo pipefail

# check if nginx is responding on its health check endpoint
curl --insecure --silent "https://localhost:443" >/dev/null || exit 1

# if we got here, everything is good
exit 0 