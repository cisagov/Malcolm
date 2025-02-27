#!/usr/bin/env bash

set -euo pipefail

supervisorctl status nginx >/dev/null 2>&1