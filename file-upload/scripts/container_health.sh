#!/bin/bash

set -euo pipefail

# check if the upload web server is responding locally
curl --silent --fail "http://localhost" >/dev/null || exit 1

# if we got here, everything is good
exit 0 