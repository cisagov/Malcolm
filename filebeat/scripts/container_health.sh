#!/bin/bash

set -euo pipefail

# check if filebeat process is running via supervisorctl
supervisorctl status filebeat | grep -q "RUNNING" || exit 1

# if we got here, everything is good
exit 0 