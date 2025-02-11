#!/usr/bin/env bash

set -euo pipefail

supervisorctl status cron maps >/dev/null 2>&1
