#!/usr/bin/env bash

set -euo pipefail

supervisorctl status filebeat >/dev/null 2>&1
