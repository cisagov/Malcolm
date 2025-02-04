#!/usr/bin/env bash

set -euo pipefail

curl --insecure --silent --output /dev/null --fail "https://localhost:8005/_ns_/nstest.html"
