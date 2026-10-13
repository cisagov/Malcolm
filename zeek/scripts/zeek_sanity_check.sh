#!/usr/bin/env bash

# Verify the third-party Zeek plugins and scripts installed by zeek_install_plugins.sh
# actually load, and report each one that doesn't by name.
#
# Expects ZEEK_THIRD_PARTY_PLUGINS_GREP and ZEEK_THIRD_PARTY_SCRIPTS_GREP in the
# environment, in the same "(a|b|c)" / "(a|b|c)\.(zeek|bro)" form used in zeek.Dockerfile.

set -uo pipefail

ZEEK_DIR="${ZEEK_DIR:-/usr/local/zeek}"
ZEEK_BIN="${ZEEK_BIN:-$ZEEK_DIR/bin/zeek-offline}"
PCAP="${ZEEK_SANITY_PCAP:-/tmp/pcaps/udp.pcap}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR" || exit 1

FAILED=0

# split "(a|b|c)<suffix>" into one pattern per line, with <suffix> re-attached to each
explode() {
  local regex="$1" group suffix
  group="$(grep -oP '^\([^)]+\)' <<<"$regex")"
  suffix="${regex#"$group"}"
  group="${group#(}"
  group="${group%)}"
  tr '|' '\n' <<<"$group" | sed "s/\$/$(sed 's/[\/&]/\\&/g' <<<"$suffix")/"
}

run_zeek() {
  local label="$1" out="$2" err="$3"
  shift 3
  "$ZEEK_BIN" "$@" >"$out" 2>"$err"
  local rc=$?
  if (( rc != 0 )); then
    echo "!! '$ZEEK_BIN $*' exited with code $rc ($label)"
    echo "---- stderr ----"
    cat "$err"
    echo "----------------"
  fi
  return $rc
}

# check every pattern from list file $1 against log $2; mode "atleast" or "exactly"
check_patterns() {
  local kind="$1" patterns="$2" log="$3" mode="$4"
  local total=0 ok=0 count pat
  local -a missing=() dupes=()
  while IFS= read -r pat; do
    [[ -z "$pat" ]] && continue
    total=$((total + 1))
    count="$(grep -cP -- "$pat" "$log" 2>/dev/null)"
    count="${count:-0}"
    if (( count == 0 )); then
      missing+=("$pat")
    elif [[ "$mode" == "exactly" ]] && (( count > 1 )); then
      dupes+=("$pat ($count matches)")
    else
      ok=$((ok + 1))
    fi
  done <"$patterns"

  echo "$kind: $ok/$total OK"
  if (( ${#missing[@]} > 0 )); then
    echo "  MISSING ${kind,,}:"
    printf '    - %s\n' "${missing[@]}"
  fi
  if (( ${#dupes[@]} > 0 )); then
    echo "  DUPLICATE ${kind,,}:"
    printf '    - %s\n' "${dupes[@]}"
  fi
  (( ${#missing[@]} == 0 && ${#dupes[@]} == 0 ))
}

explode "$ZEEK_THIRD_PARTY_PLUGINS_GREP" >"$WORKDIR/plugin_patterns.txt"
explode "$ZEEK_THIRD_PARTY_SCRIPTS_GREP" >"$WORKDIR/script_patterns.txt"

# plugins: try with local first, and if local fails to parse, retry bare so a
# broken script doesn't hide which plugins are or aren't present
if ! run_zeek "plugins, with local" "$WORKDIR/zeeknn.log" "$WORKDIR/zeeknn.err" -NN local; then
  FAILED=1
  echo "Retrying plugin listing without 'local'..."
  run_zeek "plugins, bare" "$WORKDIR/zeeknn.log" "$WORKDIR/zeeknn.err" -NN || true
fi
check_patterns "Plugins" "$WORKDIR/plugin_patterns.txt" "$WORKDIR/zeeknn.log" atleast || FAILED=1

# scripts
if ! run_zeek "scripts" "$WORKDIR/scripts.out" "$WORKDIR/scripts.err" \
    -C -r "$PCAP" local policy/misc/loaded-scripts; then
  FAILED=1
fi
# policy/misc/loaded-scripts writes loaded_scripts.log into the cwd
check_patterns "Scripts" "$WORKDIR/script_patterns.txt" "$WORKDIR/loaded_scripts.log" exactly || FAILED=1

if (( FAILED )); then
  echo "Zeek sanity check FAILED"
  exit 1
fi
echo "Zeek sanity check passed"
