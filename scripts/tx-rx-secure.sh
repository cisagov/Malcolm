#!/usr/bin/env bash

# use croc (https://github.com/schollz/croc) to securely send and receive file(s)
# via the use of single-use code phrase using a local-only relay by default

###############################################################################
# script options
set -o pipefail
shopt -s nocasematch
ENCODING="utf-8"

unset MACOS
unset LINUX
if [[ $(uname -s) = 'Darwin' ]]; then
  export MACOS=1
elif [[ $(uname -s) = 'Linux' ]]; then
  export LINUX=1
fi

[[ -n $MACOS ]] && REALPATH=grealpath || REALPATH=realpath
[[ -n $MACOS ]] && DIRNAME=gdirname || DIRNAME=dirname
if ! (type "$REALPATH" && type "$DIRNAME") > /dev/null; then
  echo "$(basename "${BASH_SOURCE[0]}") requires $REALPATH and $DIRNAME" >&2
  exit 1
fi
SCRIPT_REAL="$($REALPATH -e "${BASH_SOURCE[0]}")"
SCRIPT_PATH="$($DIRNAME "$SCRIPT_REAL")"
SCRIPT_NAME="$(basename "$SCRIPT_REAL")"

unset CROC_BIN
if command -v croc >/dev/null 2>&1; then
  CROC_BIN=croc
elif [[ -x "$SCRIPT_PATH"/croc ]]; then
  CROC_BIN="$SCRIPT_PATH"/croc
fi

###############################################################################
# script variables
MODE=
SERVER=
PORTS="9009,9010,9011,9012,9013"
TOKEN=
LOCAL_RELAY=yes
RELAY_PID=
RELAY_OUTPUT_REDIR=/dev/null
OUTPUT_ARGS=()
VERBOSE_FLAG=
DEBUG_FLAG=

# don't let the environment variables croc normally uses get in our way
unset CROC_RELAY
unset CROC_RELAY6
unset CROC_PASS
unset SOCKS5_PROXY

###############################################################################
# show script usage
function _help() {
    echo -e "${SCRIPT_NAME}\n"
    echo -e "-v                              enable bash verbosity"
    echo -e "-d                              enable croc debugging"
    echo -e "-g                              \"global\" (don't use only local connections)"
    echo -e "-p value                        relay port(s) (default: \"${PORTS}\")"

    echo -e "\ntransmit mode:"
    echo -e "-t                              enable transmit mode"
    echo -e "-s value                        bind local IP"
    echo -e "<post-options arguments>        file(s) to transfer"

    echo -e "\nreceive mode:"
    echo -e "-s value                        local server IP or hostname"
    echo -e "-r value                        one-time receive token"
    echo -e "-o value                        output folder for file(s) received (default: .)"
    exit 1
}

###################################################################################
# _GitLatestRelease - query the latest version from a github project's releases
function _GitLatestRelease {
  if [[ -n "$1" ]]; then
    (set -o pipefail && curl -sL -f "https://api.github.com/repos/$1/releases/latest" | jq '.tag_name' | sed -e 's/^"//' -e 's/"$//' ) || \
      (set -o pipefail && curl -sL -f "https://api.github.com/repos/$1/releases" | jq '.[0].tag_name' | sed -e 's/^"//' -e 's/"$//' ) || \
      echo unknown
  else
    echo "unknown">&2
  fi
}

###################################################################################
# _InstallTool - install a tool from GitHub
function _InstallTool {
  local repo="$1"
  local bin_name="$2"
  local amd64_pattern="$3"
  local arm64_pattern="$4"
  local strip_components=1

  shift 4
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --strip) strip_components="$2"; shift ;;
    esac
    shift
  done

  for c in curl jq tar gzip find; do command -v "$c" >/dev/null || { echo "Cannot download from ${repo} without ${c}" >&2; return 1; }; done

  local release="$(_GitLatestRelease "$repo")"
  local tmp_dir="$(mktemp -d)"

  local linux_cpu="$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
  local arch_pattern=""
  case "$linux_cpu" in
    amd64) arch_pattern="$amd64_pattern" ;;
    arm64) arch_pattern="$arm64_pattern" ;;
    *) echo "Unsupported architecture: $linux_cpu" >&2; return 1 ;;
  esac

  arch_pattern="${arch_pattern//\{ver\}/$release}"
  local url="https://github.com/${repo}/releases/download/${release}/${arch_pattern}"

  # Default binary name = repo basename if omitted or '-'
  if [[ -z "$bin_name" || "$bin_name" == "-" ]]; then
    bin_name="$(basename "$repo")"
  fi

  echo "Installing $bin_name from $url" >&2

  local is_tarball=false
  [[ "$arch_pattern" =~ \.tar\.gz$|\.tgz$ ]] && is_tarball=true

  if $is_tarball; then
    if [[ "$strip_components" -eq 0 ]]; then
      curl -sSL "$url" | tar xzf - -C "$tmp_dir"
    else
      curl -sSL "$url" | tar xzf - --strip-components "$strip_components" -C "$tmp_dir"
    fi

    # Try to locate binary
    local found_bin
    found_bin="$(find "$tmp_dir" -type f -executable \( -name "$bin_name" -o -printf "%f\n" \) 2>/dev/null | head -n1)"
    if [[ -z "$found_bin" ]]; then
      # fallback: just grab first executable file
      found_bin="$(find "$tmp_dir" -type f -perm -111 | head -n1)"
    fi
    if [[ -z "$found_bin" ]]; then
      echo "Error: could not detect binary in tarball" >&2
      rm -rf "$tmp_dir"
      return 1
    fi

    cp -f "$found_bin" "$SCRIPT_PATH/$bin_name"
  else
    curl -sSL -o "$SCRIPT_PATH/$bin_name" "$url"
  fi

  chmod 755 "$SCRIPT_PATH/$bin_name"
  chown root:root "$SCRIPT_PATH/$bin_name"
  rm -rf "$tmp_dir"
}

###################################################################################
# _InstallCroc - Install croc from GitHub
function _InstallCroc {
  unset CROC_RELEASE
  [[ -n "${MACOS}" ]] && CROC_RELEASE=macOS
  [[ -n "${LINUX}" ]] && CROC_RELEASE=Linux
  if [[ -n "${CROC_RELEASE}" ]]; then
    _InstallTool schollz/croc - \
      "croc_{ver}_${CROC_RELEASE}-64bit.tar.gz" \
      "croc_{ver}_${CROC_RELEASE}-ARM64.tar.gz" --strip 0
    CROC_BIN="$SCRIPT_PATH"/croc
  fi
}


###############################################################################
# parse command-line parameters
while getopts 'vdgo:r:s:tp:' OPTION; do
  case "$OPTION" in

    v)
      VERBOSE_FLAG="-v"
      RELAY_OUTPUT_REDIR=/dev/stderr
      set -x
      ;;

    d)
      DEBUG_FLAG="--debug"
      RELAY_OUTPUT_REDIR=/dev/stderr
      ;;

    g)
      LOCAL_RELAY=
      ;;

    o)
      OUTPUT_ARGS=(--out "$OPTARG")
      ;;

    r)
      MODE=rx
      TOKEN="$OPTARG"
      ;;

    s)
      SERVER="$OPTARG"
      ;;

    t)
      MODE=tx
      ;;

    p)
      PORTS="$OPTARG"
      ;;

    ?)
      _help >&2
      exit 1;
      ;;

  esac
done
shift "$(($OPTIND -1))"

# without croc what are we even doing here
[[ -z "${CROC_BIN}" ]] && _InstallCroc
if [[ -z "${CROC_BIN}" ]]; then
    echo "${SCRIPT_NAME} requires croc (https://github.com/schollz/croc)" >&2
    exit 1
fi

###############################################################################
# _cleanup: kill croc relay process on exit, if we started one
function _cleanup {
    if [[ -n "${RELAY_PID}" ]] && kill -s 0 "${RELAY_PID}" >/dev/null 2>&1; then
        [[ -n "${VERBOSE_FLAG}" ]] && echo "killing relay process ${RELAY_PID}" >&2
        kill "${RELAY_PID}" >/dev/null 2>&1
        sleep 1
        if kill -s 0 "${RELAY_PID}" >/dev/null 2>&1; then
            sleep 5
            [[ -n "${VERBOSE_FLAG}" ]] && echo "killing (-9) relay process ${RELAY_PID}" >&2
            kill -s -9 "${RELAY_PID}" >/dev/null 2>&1
        fi
    fi
}

###############################################################################

trap "_cleanup" EXIT

RELAY_ARGS=()
CURVE_ARGS=(--curve siec)
HASH_ARGS=(--hash xxhash)
FIRST_PORT="$(echo "${PORTS}" | cut -d, -f1)"

if [[ -n "${PORTS}" ]] && [[ "${MODE}" == "tx" ]] && (( $# > 0 )); then
    # we have ports defined, have requested transmit mode, and have been given file(s) to transmit

    if [[ -n "${LOCAL_RELAY}" ]]; then
        # we're using "local-only" mode, which means we need to be the relay ourselves
        if [[ -z "${SERVER}" ]]; then
            SERVER="0.0.0.0"
            command -v ip >/dev/null 2>&1 && SEND_RELAY_IP=$(ip route get 255.255.255.255 2>/dev/null | grep -Po '(?<=src )(\d{1,3}.){4}' | sed "s/ //g")
        else
            SEND_RELAY_IP="${SERVER}"
        fi
        "${CROC_BIN}" ${DEBUG_FLAG} "${CURVE_ARGS[@]}" relay --host "${SERVER}" --ports "${PORTS}" >${RELAY_OUTPUT_REDIR} 2>&1 &
        RELAY_PID=$!
        sleep 5
        if [[ -n "${RELAY_PID}" ]] && kill -s 0 "${RELAY_PID}" >/dev/null 2>&1; then
            [[ -n "${VERBOSE_FLAG}" ]] && echo "relay running at ${RELAY_PID}" >&2
        else
            echo "Failed to start relay process" >&2
            exit 1;
        fi

    elif [[ -n "${SERVER}" ]]; then
        # we're not using local-only mode, they *can* but don't have to define a relay
        SEND_RELAY_IP="${SERVER}"
    fi

    [[ -n "${SEND_RELAY_IP}" ]] && RELAY_ARGS=(--relay "${SEND_RELAY_IP}:${FIRST_PORT}")

    # run croc
    "${CROC_BIN}" --yes --ignore-stdin --overwrite ${DEBUG_FLAG} "${CURVE_ARGS[@]}" "${RELAY_ARGS[@]}" send "${HASH_ARGS[@]}" "$@"

elif [[ -n "${PORTS}" ]] && ( [[ "${MODE}" == "rx" ]] && [[ -n "${TOKEN}" ]] && ( [[ -z "${LOCAL_RELAY}" ]] || [[ -n "${SERVER}" ]] ) ); then
    # we have ports defined, have requested receive mode, have been given a token, and either have a relay IP or are not using a local relay

    [[ -n "${SERVER}" ]] && RELAY_ARGS=(--relay "${SERVER}:${FIRST_PORT}")

    # run croc
    export CROC_SECRET="${TOKEN}"
    "${CROC_BIN}" --yes --ignore-stdin --overwrite ${DEBUG_FLAG} "${CURVE_ARGS[@]}" "${RELAY_ARGS[@]}" "${OUTPUT_ARGS[@]}"

else
    _help >&2
    exit 1;
fi