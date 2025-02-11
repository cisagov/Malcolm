#!/usr/bin/env bash

set -euo pipefail

curl --silent --output /dev/null --fail "http://localhost:8080/netbox/api/"
