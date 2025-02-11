#!/usr/bin/env bash

set -euo pipefail

curl --silent --output /dev/null --fail "http://localhost:5601/dashboards/api/status"
