#!/usr/bin/env bash

set -euo pipefail

supervisorctl status logger watcher >/dev/null 2>&1
