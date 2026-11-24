#!/usr/bin/env bash

# For each package in zeek-packages.lock, start a fresh container, install the package the same way
# Malcolm's zeek/scripts/zeek_install_plugins.sh does, then time `zeek -C -r <pcap> local` with and
# without ZAM (-O ZAM).
#
# Packages are installed at their pinned commits with `zkg install --nodeps --force --skiptests`,
# and clone: entries are checked out at their pinned commit with submodules.
#
# A baseline row (no extra package) is measured first so per-package costs can be compared to it.
#
# Usage:
#   zeek-zam-bench.sh -p capture.pcap [-l zeek-packages.lock] [-i image] [-o outdir]
#                     [-t timeout_seconds] [-r runs] [-f regex] [-u user] [-j cpus] [-n] [-B]
#
#   -p  PCAP to read (required)
#   -l  package lock file (default: ./zeek-packages.lock)
#   -i  container image (default: oci.guero.org/zeek:latest)
#   -o  output directory for results.csv and logs (default: ./zeek-zam-bench-<timestamp>)
#   -t  timeout per Zeek run, in seconds (default: 900)
#   -r  runs per mode; the fastest successful run is reported (default: 1)
#   -f  only test packages whose URL matches this extended regex
#   -u  user to run as inside the container (default: 0, since zkg writes to the Zeek prefix)
#   -j  CPUs for Spicy compilation, passed to the container as HILTI_JIT_PARALLELISM
#       (default: $BUILD_JOBS if set, else half the host's CPUs, as zeek_install_plugins.sh does)
#   -n  don't pull the image first
#   -B  skip the baseline row
#
# Environment:
#   CONTAINER_ENGINE  docker (default) or podman
#   BUILD_JOBS        default for -j

set -uo pipefail

if [[ -z "${BASH_VERSINFO:-}" ]] || (( BASH_VERSINFO[0] < 5 )); then
  echo "bash 5 or newer is required (for EPOCHREALTIME)" >&2
  exit 1
fi

ENGINE="${CONTAINER_ENGINE:-docker}"
IMAGE="oci.guero.org/zeek:latest"
LIST="./zeek-packages.lock"
PCAP=""
OUTDIR=""
TIMEOUT=900
RUNS=1
FILTER=""
CUSER="0"
JOBS=""
PULL=true
BASELINE=true

while getopts "p:l:i:o:t:r:f:u:j:nBh" opt; do
  case "$opt" in
    p) PCAP="$OPTARG" ;;
    l) LIST="$OPTARG" ;;
    i) IMAGE="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    t) TIMEOUT="$OPTARG" ;;
    r) RUNS="$OPTARG" ;;
    f) FILTER="$OPTARG" ;;
    u) CUSER="$OPTARG" ;;
    j) JOBS="$OPTARG" ;;
    n) PULL=false ;;
    B) BASELINE=false ;;
    h|*) sed -n '3,31p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
  esac
done

[[ -n "$PCAP" && -f "$PCAP" ]] || { echo "a readable PCAP is required (-p)" >&2; exit 1; }
[[ -r "$LIST" ]] || { echo "package lock file not found: $LIST" >&2; exit 1; }
command -v "$ENGINE" >/dev/null || { echo "$ENGINE not found" >&2; exit 1; }
if [[ -z "$JOBS" ]]; then
  if [[ -n "${BUILD_JOBS:-}" ]]; then
    JOBS="$BUILD_JOBS"
  else
    JOBS=$(( $(nproc --all 2>/dev/null || echo 1) / 2 ))
    (( JOBS <= 0 )) && JOBS=1
  fi
fi
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || { echo "-j (or BUILD_JOBS) must be a positive integer" >&2; exit 1; }

# read the whole lock file up front, validating it the same way zeek_install_plugins.sh does
mapfile -t LOCK_ENTRIES < <(grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$LIST")
for entry in "${LOCK_ENTRIES[@]}"; do
  IFS='|' read -r url commit _ _ method <<< "$entry"
  if [[ -z "$url" ]] || [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
    echo "Invalid entry in $LIST: $entry" >&2
    exit 1
  fi
  case "${method:-zkg}" in
    zkg|clone:*) ;;
    *) echo "Unknown install method '$method' for $url" >&2; exit 1 ;;
  esac
done

PCAP="$(realpath "$PCAP")"
PCAP_NAME="$(basename "$PCAP")"
OUTDIR="${OUTDIR:-./zeek-zam-bench-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUTDIR/logs"
OUTDIR="$(realpath "$OUTDIR")"
RESULTS="$OUTDIR/results.csv"
echo "package,ref,commit,install_status,install_secs,plain_status,plain_secs,zam_status,zam_secs,zam_minus_plain_secs" > "$RESULTS"

CONTAINER=""
cleanup() {
  [[ -n "$CONTAINER" ]] && "$ENGINE" rm -f "$CONTAINER" >/dev/null 2>&1
  CONTAINER=""
}
trap 'cleanup; exit 130' INT TERM
trap cleanup EXIT

now() { echo "$EPOCHREALTIME"; }
elapsed() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.3f", b - a }'; }

# run a command in the current container as the configured user
cexec() { "$ENGINE" exec -u "$CUSER" "$@"; }

start_container() {
  CONTAINER="zeek-zam-bench-$$-$RANDOM"
  # set on the container, so every exec (installs and Zeek runs) inherits it
  "$ENGINE" run -d --rm --name "$CONTAINER" -u "$CUSER" -e "HILTI_JIT_PARALLELISM=$JOBS" \
    -v "$PCAP:/bench/$PCAP_NAME:ro" \
    --entrypoint sleep "$IMAGE" infinity >/dev/null
}

# time one Zeek run; prints "<status> <seconds>"
#   status is ok, fail(<rc>) or timeout
time_zeek() {
  local label="$1" log="$2"
  shift 2
  local best="" status="" rc start end secs run
  for (( run = 1; run <= RUNS; run++ )); do
    start="$(now)"
    # ZEEK_ZAM is unset so ZAM is controlled only by -O ZAM (Zeek enables ZAM if ZEEK_ZAM exists at all)
    cexec "$CONTAINER" env -u ZEEK_ZAM timeout --signal=KILL "$TIMEOUT" \
      sh -c 'cd "$(mktemp -d)" && exec zeek "$@" -C -r "/bench/$0" local' "$PCAP_NAME" "$@" \
      >> "$log" 2>&1
    rc=$?
    end="$(now)"
    secs="$(elapsed "$start" "$end")"
    echo "--- $label run $run: rc=$rc secs=$secs" >> "$log"
    if (( rc == 0 )); then
      status="ok"
      if [[ -z "$best" ]] || awk -v a="$secs" -v b="$best" 'BEGIN { exit !(a < b) }'; then best="$secs"; fi
    elif (( rc == 124 || rc == 137 )); then
      [[ "$status" == "ok" ]] || status="timeout"
      [[ -n "$best" ]] || best="$secs"
    else
      [[ "$status" == "ok" ]] || status="fail($rc)"
      [[ -n "$best" ]] || best="$secs"
    fi
  done
  echo "$status $best"
}

# install one lock entry into the current container; returns non-zero on failure
#   sets INSTALL_SECS to the time taken by the install step alone (zkg install or git checkout),
#   not counting zkg setup or the local.zeek edits around it
INSTALL_SECS=""
install_package() {
  local url="$1" commit="$2" envs="$3" method="$4" log="$5"
  local -a env_args=()
  local kv start end rc
  if [[ -n "$envs" ]]; then
    IFS=';' read -r -a kvs <<< "$envs"
    for kv in "${kvs[@]}"; do [[ -n "$kv" ]] && env_args+=(-e "$kv"); done
  fi
  INSTALL_SECS=""

  if [[ "$method" == clone:* ]]; then
    local path="${method#clone:}"
    # same steps as git_clone_pinned in zeek_install_plugins.sh
    start="$(now)"
    cexec "${env_args[@]}" "$CONTAINER" sh -c '
      set -e
      dest="$(zeek-config --prefix)/$2"
      mkdir -p "$dest"
      git -C "$dest" init -q
      git -C "$dest" remote add origin "$0"
      git -C "$dest" fetch -q --depth 1 origin "$1"
      git -C "$dest" checkout -q FETCH_HEAD
      git -C "$dest" submodule update -q --init --recursive --depth 1' "$url" "$commit" "$path" >> "$log" 2>&1
    rc=$?
    end="$(now)"
    INSTALL_SECS="$(elapsed "$start" "$end")"
    echo "--- install (git checkout): rc=$rc secs=$INSTALL_SECS" >> "$log"
    (( rc == 0 )) || return $rc
    # Malcolm's local.zeek loads clone: packages itself, so load them here if they're under the site dir
    cexec "$CONTAINER" sh -c '
      dest="$(zeek-config --prefix)/$0"
      site="$(zeek-config --site_dir)"
      case "$dest" in
        "$site"/*) echo "@load ${dest#$site/}" >> "$site/local.zeek" ;;
        *) echo "warning: $dest is outside the site dir, so it is not loaded by local.zeek" ;;
      esac' "$path" >> "$log" 2>&1
    return $?
  fi

  cexec "$CONTAINER" sh -c 'zkg config >/dev/null 2>&1 || zkg autoconfig --force' >> "$log" 2>&1 || return $?

  # same arguments as zkg_install_pinned in zeek_install_plugins.sh
  local -a zkg_args=(install --nodeps --force --skiptests)
  if [[ "$url" =~ "zeek-kafka" ]]; then
    zkg_args+=(--user-var LIBRDKAFKA_ROOT=/usr/include/librdkafka)
  fi
  zkg_args+=(--version "$commit" "$url")
  start="$(now)"
  cexec "${env_args[@]}" "$CONTAINER" zkg "${zkg_args[@]}" >> "$log" 2>&1
  rc=$?
  end="$(now)"
  INSTALL_SECS="$(elapsed "$start" "$end")"
  echo "--- install (zkg): rc=$rc secs=$INSTALL_SECS" >> "$log"
  (( rc == 0 )) || return $rc

  cexec "$CONTAINER" sh -c '
    set -e
    find "$(zeek-config --prefix)"/lib/zeek/plugins/packages -type f -name "*.hlto" -exec chmod 755 "{}" \; 2>/dev/null || true
    zkg list installed
    site="$(zeek-config --site_dir)"
    grep -q "^@load packages" "$site/local.zeek" || echo "@load packages" >> "$site/local.zeek"' >> "$log" 2>&1
}

bench_one() {
  local name="$1" url="$2" commit="$3" ref="$4" envs="$5" method="$6"
  local log="$OUTDIR/logs/$(echo "$name" | tr '/:' '__').log"
  local install_status="n/a" install_secs="" plain zam start end

  printf '%-55s ' "$name"
  : > "$log"
  if ! start_container >> "$log" 2>&1; then
    echo "container failed to start"
    echo "\"$name\",\"$ref\",$commit,container_failed,,,,,," >> "$RESULTS"
    cleanup
    return
  fi

  if [[ -n "$url" ]]; then
    if install_package "$url" "$commit" "$envs" "$method" "$log"; then
      install_status="ok"
    else
      install_status="fail"
    fi
    install_secs="$INSTALL_SECS"
  fi

  if [[ "$install_status" == "fail" ]]; then
    echo "install failed after ${install_secs:-?}s (see $log)"
    echo "\"$name\",\"$ref\",$commit,fail,$install_secs,,,,," >> "$RESULTS"
    cleanup
    return
  fi

  read -r plain_status plain_secs <<< "$(time_zeek plain "$log")"
  read -r zam_status zam_secs <<< "$(time_zeek zam "$log" -O ZAM)"

  local delta=""
  if [[ "$plain_status" == "ok" && "$zam_status" == "ok" ]]; then
    delta="$(elapsed "$plain_secs" "$zam_secs")"
  fi
  printf 'install %10s   plain %-8s %9ss   zam %-8s %9ss\n' "${install_secs:+${install_secs}s}" "$plain_status" "$plain_secs" "$zam_status" "$zam_secs"
  echo "\"$name\",\"$ref\",$commit,$install_status,$install_secs,$plain_status,$plain_secs,$zam_status,$zam_secs,$delta" >> "$RESULTS"
  cleanup
}

if [[ "$PULL" == true ]]; then
  "$ENGINE" pull "$IMAGE" >/dev/null || { echo "failed to pull $IMAGE" >&2; exit 1; }
fi

echo "image:   $IMAGE"
echo "pcap:    $PCAP"
echo "timeout: ${TIMEOUT}s per run, best of $RUNS"
echo "jit:     HILTI_JIT_PARALLELISM=$JOBS"
echo "output:  $OUTDIR"
echo

[[ "$BASELINE" == true ]] && bench_one "(baseline)" "" "" "" "" ""

for entry in "${LOCK_ENTRIES[@]}"; do
  IFS='|' read -r url commit resolved_ref envs method <<< "$entry"
  [[ -n "$FILTER" && ! "$url" =~ $FILTER ]] && continue
  bench_one "${url#https://github.com/}" "$url" "$commit" "${resolved_ref:-}" "${envs:-}" "${method:-zkg}"
done

echo
echo "results: $RESULTS"
