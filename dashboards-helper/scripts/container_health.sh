#!/bin/bash

set -euo pipefail

# check if both required processes are running via supervisorctl
supervisorctl status cron | grep -q "RUNNING" || exit 1
supervisorctl status maps | grep -q "RUNNING" || exit 1

# if we got here, everything is good
exit 0 