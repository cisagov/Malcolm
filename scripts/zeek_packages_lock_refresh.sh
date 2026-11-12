#!/usr/bin/env bash

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

# Superseded by scripts/update_pins.py, which resolves zeek/zeek-packages.list the same way and
#   reports each changed package with a compare link. This keeps the old entry point working:
#   it accepts every resolved commit without asking, as this script always did.
#
# For an interactive review instead, run:  scripts/update_pins.py --zeek-packages --apply
#
# Review `git diff zeek/zeek-packages.lock` before committing: every changed line is upstream code
#   that will be built into the Zeek image.

set -euo pipefail

if (( $# > 0 )); then
  echo "The list and lock paths are now set in shared/pins/pins.yml (zeek_packages: list/lock)" >&2
  exit 2
fi

exec python3 "$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)/update_pins.py" --zeek-packages --apply --yes
