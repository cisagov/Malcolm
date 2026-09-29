#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
otkb_enrich_rb="${1:-${OTKB_ENRICH_RB:-${script_dir}/../otkb_enrich.rb}}"
test_file="${script_dir}/otkb_enrich_test.rb"

if [[ ! -f "${otkb_enrich_rb}" ]]; then
  echo "otkb_enrich.rb was not found at ${otkb_enrich_rb}" >&2
  exit 2
fi

if [[ -x /usr/share/logstash/bin/ruby ]]; then
  ruby_command=(/usr/share/logstash/bin/ruby)
elif command -v jruby >/dev/null 2>&1; then
  ruby_command=(jruby)
elif command -v ruby >/dev/null 2>&1; then
  ruby_command=(ruby)
else
  echo "No Ruby interpreter was found. Run this script in the Logstash container." >&2
  exit 2
fi

OTKB_ENRICH_RB="${otkb_enrich_rb}" "${ruby_command[@]}" "${test_file}"
