# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

function in_array() {
  local haystack="${1}[@]"
  local needle="${2}"
  for i in "${!haystack}"; do
    if [[ "${i}" == "${needle}" ]]; then
      return 0
    fi
  done
  return 1
}
