#!/bin/bash

set -euo pipefail

# check if file-monitor process is running via supervisorctl
supervisorctl status watcher | grep -q "RUNNING" || exit 1
supervisorctl status logger  | grep -q "RUNNING" || exit 1

# if we got here, everything is good
exit 0 