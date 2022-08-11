#!/usr/bin/env bash

###############################################################################
# fluent-bit-setup.sh
#
# Interactive bash script for Linux and macOS to aid in the installation and
# configuration of fluent-bit (https://fluentbit.io/) for forwarding logs to
# an instance of Malcolm (https://github.com/idaholab/malcolm).
#
# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

###############################################################################
# force bash
if [[ -z "$BASH_VERSION" ]]; then
  echo "Wrong interpreter, please run \"$0\" with bash" >&2
  exit 1
fi

###############################################################################
# determine OS, root user and some other parameters
unset MACOS
unset LINUX
if [[ $(uname -s) = 'Darwin' ]]; then
  export MACOS=0
elif [[ $(uname -s) = 'Linux' ]]; then
  export LINUX=0
else
  echo "Unsupported platform: $(uname -s)"
fi

#
if [[ $EUID -eq 0 ]]; then
  SCRIPT_USER="root"
  SUDO_CMD=""
else
  SCRIPT_USER="$(whoami)"
  SUDO_CMD="sudo"
fi

###############################################################################
# get directory script is executing from
[[ -n $MACOS ]] && REALPATH=grealpath || REALPATH=realpath
[[ -n $MACOS ]] && DIRNAME=gdirname || DIRNAME=dirname
[[ -n $MACOS ]] && SED=gsed || SED=sed
if ! (type "$REALPATH" && type "$DIRNAME" && type "$SED") > /dev/null; then
  echo "$(basename "${BASH_SOURCE[0]}") requires $REALPATH, $DIRNAME and $SED" >&2
  exit 1
fi
SCRIPT_PATH="$($DIRNAME $($REALPATH -e "${BASH_SOURCE[0]}") | head -n 1)"
FULL_PWD="$($REALPATH "$(pwd)" | head -n 1)"

###################################################################################
# _GetConfirmation - get a yes/no confirmation from the user (or accept the default)
function _GetConfirmation {
  PROMPT=${1:-"[y/N]?"}
  DEFAULT_ANSWER=${2:-n}
  unset CONFIRMATION
  echo -n "${PROMPT} " >&2
  read CONFIRMATION
  CONFIRMATION=${CONFIRMATION:-$DEFAULT_ANSWER}
  echo $CONFIRMATION
}

###################################################################################
# _GetString - get a string response from the user (or accept the default)
function _GetString {
  PROMPT=${1:-""}
  DEFAULT_ANSWER=${2:-""}
  unset RESPONSE
  echo -n "${PROMPT} " >&2
  read RESPONSE
  RESPONSE=${RESPONSE:-$DEFAULT_ANSWER}
  echo $RESPONSE
}

###################################################################################
# _in_array - does an array contain an element
function _in_array() {
  local haystack="${1}[@]"
  local needle="${2}"
  for i in "${!haystack}"; do
    if [[ "${i}" == "${needle}" ]]; then
      return 0
    fi
  done
  return 1
}

###############################################################################
# script options
set -o pipefail
ENCODING="utf-8"

###############################################################################
# command-line parameters
# options
# -v        (verbose)
# -i input  (input string)

# parse command-line options
VERBOSE_FLAG=""
INPUT_STR="world"
while getopts 'vi:' OPTION; do
  case "$OPTION" in
    v)
      VERBOSE_FLAG="-v"
      ;;

    i)
      INPUT_STR="$OPTARG"
      ;;

    ?)
      echo "script usage: $(basename $0) [-v] [-i input]" >&2
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"

###############################################################################
# clean-up code
function _clean_up {
  [[ -n $VERBOSE_FLAG ]] && echo "Cleaning up..." >&2
}

###############################################################################
# run fluent-bit bin wherever it's at
function _fluentbit_bin {
  if hash fluent-bit >/dev/null 2>&1; then
    FLUENTBIT_BIN="$(command -v fluent-bit)"
  elif [[ -n "$LINUX" ]]; then
    FLUENTBIT_BIN='/opt/fluent-bit/bin/fluent-bit'
  elif [[ -n "$MACOS" ]]; then
    FLUENTBIT_BIN='/usr/local/bin/fluent-bit'
  else
    FLUENTBIT_BIN='fluent-bit'
  fi
  echo "$FLUENTBIT_BIN"
}

function _fluentbit_parser_cfg {
  if [[ -s /usr/local/etc/fluent-bit/parsers.conf ]]; then
    echo /usr/local/etc/fluent-bit/parsers.conf
  elif [[ -s /etc/fluent-bit/parsers.conf ]]; then
    echo /etc/fluent-bit/parsers.conf
  elif [[ -s /opt/fluent-bit/etc/parsers.conf ]]; then
    echo /opt/fluent-bit/etc/parsers.conf
  else
    echo ""
  fi
}

function _fluentbit_run {
  "$(_fluentbit_bin)" "$@"
}

###############################################################################
# install fluent-bit if it's not already installed
function InstallFluentBit() {
  _fluentbit_run --version >/dev/null 2>&1
  if [[ $? -ne 0 ]]; then

    if [[ -n "$LINUX" ]]; then
      INSTALL_CONFIRM="$(_GetConfirmation "Install fluent-bit via GitHub/fluent install script [Y/n]?" "y")"
      if [[ $INSTALL_CONFIRM =~ ^[Yy] ]]; then
        source <(curl -fsSL https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh)
      else
        echo "Visit https://docs.fluentbit.io/manual/installation/linux" >&2
      fi

    elif [[ -n "$MACOS" ]]; then
      if ! brew info >/dev/null 2>&1; then
        INSTALL_BREW_CONFIRM="$(_GetConfirmation "Install Homebrew for macOS [y/N]?" "n")"
        if [[ $INSTALL_BREW_CONFIRM =~ ^[Yy] ]]; then
          source <(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)
        fi
      fi
      INSTALL_CONFIRM="$(_GetConfirmation "Install fluent-bit via Homebrew [Y/n]?" "y")"
      if [[ $INSTALL_CONFIRM =~ ^[Yy] ]]; then
        brew install fluent-bit
      else
        echo "Visit https://docs.fluentbit.io/manual/installation/macos" >&2
      fi

    else
      echo "Visit https://docs.fluentbit.io/manual/installation/getting-started-with-fluent-bit" >&2
    fi
  else
    echo "fluent-bit is already installed" >&2
  fi

  _fluentbit_run --version >/dev/null 2>&1
}

###############################################################################
# identify malcolm connection information
function GetMalcolmConnInfo() {
  IP=
  PORT=
  FORMAT=
  NEST=
  MODULE=
  CA=
  CERT=
  KEY=

  command -v ip >/dev/null 2>&1 && SUGGESTED_IP=$(ip route get 255.255.255.255 2>/dev/null | grep -Po '(?<=src )(\d{1,3}.){4}' | $SED "s/ //g") || SUGGESTED_IP='127.0.0.1'
  SUGGESTED_PORT=5045
  SUGGESTED_FORMAT=json_lines

  while [[ -z "$IP" ]] || \
        [[ -z "$PORT" ]] || \
        [[ -z "$FORMAT" ]]; do
    IP="$(_GetString "Enter Malcolm host or IP address ($SUGGESTED_IP):" "$SUGGESTED_IP")"
    PORT="$(_GetString "Enter Malcolm Filebeat TCP port ($SUGGESTED_PORT):" "$SUGGESTED_PORT")"
    FORMAT="$(_GetString "Enter fluent-bit output format ($SUGGESTED_FORMAT):" "$SUGGESTED_FORMAT")"
    NEST="$(_GetString "Nest values under field:")"
    MODULE="$(_GetString "Add \"module\" value:")"
  done

  if [[ -r "$SCRIPT_PATH"/ca.crt ]] && \
     [[ -r "$SCRIPT_PATH"/client.crt ]] && \
     [[ -r "$SCRIPT_PATH"/client.key ]]; then
    CA="$SCRIPT_PATH"/ca.crt
    CERT="$SCRIPT_PATH"/client.crt
    KEY="$SCRIPT_PATH"/client.key

  elif [[ -d "$SCRIPT_PATH"/../../filebeat/certs ]] && \
       [[ -r "$SCRIPT_PATH"/../../filebeat/certs/ca.crt ]] && \
       [[ -r "$SCRIPT_PATH"/../../filebeat/certs/client.crt ]] && \
       [[ -r "$SCRIPT_PATH"/../../filebeat/certs/client.key ]]; then
    CA="$($REALPATH -e "$SCRIPT_PATH"/../../filebeat/certs/ca.crt)"
    CERT="$($REALPATH -e "$SCRIPT_PATH"/../../filebeat/certs/client.crt)"
    KEY="$($REALPATH -e "$SCRIPT_PATH"/../../filebeat/certs/client.key)"
  fi

  FIRST_TIME=1
  while [[ -z "$CA" ]] || \
        [[ -z "$CERT" ]] || \
        [[ -z "$KEY" ]] || \
        [[ ! -r "$CA" ]] || \
        [[ ! -r "$CERT" ]] || \
        [[ ! -r "$KEY" ]]; do
    if [[ $FIRST_TIME -eq 1 ]]; then
      echo "Enter paths and filenames of client certificate files" >&2
      echo "  e.g., files generated in Malcolm/filebeat/certs/ directory" >&2
    fi
    FIRST_TIME=0
    CA="$(_GetString "Enter CA certificate file: ")"
    CERT="$(_GetString "Enter client certificate file: ")"
    KEY="$(_GetString "Enter client key file: ")"
  done

  FLUENTBIT_ARGS=()
  FLUENTBIT_ARGS+=( -o )
  FLUENTBIT_ARGS+=( "tcp://$IP:$PORT" )
  FLUENTBIT_ARGS+=( -p )
  FLUENTBIT_ARGS+=( tls=on )
  FLUENTBIT_ARGS+=( -p )
  FLUENTBIT_ARGS+=( tls.verify=off )
  FLUENTBIT_ARGS+=( -p )
  FLUENTBIT_ARGS+=( tls.ca_file="$CA" )
  FLUENTBIT_ARGS+=( -p )
  FLUENTBIT_ARGS+=( tls.crt_file="$CERT" )
  FLUENTBIT_ARGS+=( -p )
  FLUENTBIT_ARGS+=( tls.key_file="$KEY" )
  FLUENTBIT_ARGS+=( -p )
  FLUENTBIT_ARGS+=( format="$FORMAT" )

  if [[ -n "$NEST" ]]; then
    FLUENTBIT_ARGS+=( -F )
    FLUENTBIT_ARGS+=( nest )
    FLUENTBIT_ARGS+=( -p )
    FLUENTBIT_ARGS+=( Operation=nest )
    FLUENTBIT_ARGS+=( -p )
    FLUENTBIT_ARGS+=( "Nested_under=$NEST" )
    FLUENTBIT_ARGS+=( -p )
    FLUENTBIT_ARGS+=( "WildCard='*'" )
    FLUENTBIT_ARGS+=( -m )
    FLUENTBIT_ARGS+=( "'*'" )
  fi
  if [[ -n "$MODULE" ]]; then
    FLUENTBIT_ARGS+=( -F )
    FLUENTBIT_ARGS+=( record_modifier )
    FLUENTBIT_ARGS+=( -p )
    FLUENTBIT_ARGS+=( "'Record=module $MODULE'" )
    FLUENTBIT_ARGS+=( -m )
    FLUENTBIT_ARGS+=( "'*'" )
  fi
  FLUENTBIT_ARGS+=( -f )
  FLUENTBIT_ARGS+=( 1 )

  ( IFS=$'\n'; echo "${FLUENTBIT_ARGS[*]}" )
}

###############################################################################
# identify information for fluent-bit intput/output
function GetFluentBitFormatInfo() {
  INPUT_NAME=
  declare -A PARAMS

  echo "Choose input plugin and enter parameters. Leave parameters blank for defaults." >&2
  echo "  see https://docs.fluentbit.io/manual/pipeline/inputs" >&2
  readarray -t PLUGINS < <(_fluentbit_run --help 2>&1 | $SED 's/\x1B\[[0-9;]\{1,\}[A-Za-z]//g' | $SED -n '/^Inputs$/, /^Filters$/{ /^Inputs$/! { /^Filters$/! p } }' | grep . | awk '{print $1}' | sort)
  if [[ ${#PLUGINS[@]} -eq 0 ]]; then
    # this shouldn't have happened, but we need to have at least one plugin here
    PLUGINS=(
      dummy
    )
  fi
  for i in "${!PLUGINS[@]}"; do
    ((IPLUS=i+1))
    printf "%s\t%s\n" "$IPLUS" "${PLUGINS[$i]}" >&2
  done
  while [[ -z "$INPUT_NAME" ]] || ! _in_array PLUGINS "$INPUT_NAME"; do
    echo -n "Input plugin: " >&2
    read PLUGIN_IDX
    if (( $PLUGIN_IDX > 0 )) && (( $PLUGIN_IDX <= "${#PLUGINS[@]}" )); then
      INPUT_NAME="${PLUGINS[((PLUGIN_IDX-1))]}"
    fi
  done

  case $INPUT_NAME in

    collectd)
      PARAM_NAMES=(
        Listen
        Port
        TypesDB
      )
      ;;

    cpu)
      PARAM_NAMES=(
        Interval_Sec
        Interval_NSec
        PID
      )
      ;;

    disk)
      PARAM_NAMES=(
        Interval_Sec
        Interval_NSec
        Dev_Name
      )
      ;;

    docker)
      PARAM_NAMES=(
        Interval_Sec
        Include
        Exclude
      )
      ;;

    docker_events)
      PARAM_NAMES=(
        Unix_Path
        Buffer_Size
        Parser
        Key
        Reconnect.Retry_limits
        Reconnect.Retry_interval
      )
      ;;

    dummy)
      PARAM_NAMES=(
        Dummy
        Start_time_sec
        Start_time_nsec
        Rate
        Samples
      )
      ;;

    exec)
      PARAM_NAMES=(
        Command
        Parser
        Interval_Sec
        Interval_NSec
        Buf_Size
        Oneshot
      )
      ;;

    head)
      PARAM_NAMES=(
        File
        Buf_Size
        Interval_Sec
        Interval_NSec
        Add_Path
        Key
        Lines
        Split_line
      )
      ;;

    http)
      PARAM_NAMES=(
        host
        port
        buffer_max_size
        buffer_chunk_size
        successful_response_code
      )
      ;;

    health)
      PARAM_NAMES=(
        Host
        Port
        Interval_Sec
        Internal_NSec
        Alert
        Add_Host
        Add_Port
      )
      ;;

    mem)
      PARAM_NAMES=(
        Interval_Sec
        Interval_NSec
        PID
      )
      ;;

    mqtt)
      PARAM_NAMES=(
        Listen
        Port
      )
      ;;

    netif)
      PARAM_NAMES=(
        Interface
        Interval_Sec
        Internal_NSec
        Verbose
        Test_At_Init
      )
      ;;

    proc)
      PARAM_NAMES=(
        Proc_Name
        Interval_Sec
        Internal_NSec
        Alert
        Fd
        Mem
      )
      ;;

    random)
      PARAM_NAMES=(
        Samples
        Interval_Sec
        Internal_NSec
      )
      ;;

    statsd)
      PARAM_NAMES=(
        Listen
        Port
      )
      ;;

    syslog)
      PARAM_NAMES=(
        Mode
        Listen
        Port
        Path
        Unix_Perm
        Parser
        Buffer_Chunk_Size
        Buffer_Max_Size
      )
      ;;

    systemd)
      PARAM_NAMES=(
        Path
        Max_Fields
        Max_Entries
        Systemd_Filter
        Systemd_Filter_Type
        Tag
        DB
        DB.Sync
        Read_From_Tail
        Lowercase
        Strip_Underscores
      )
      ;;

    tail)
      PARAM_NAMES=(
        Buffer_Chunk_Size
        Buffer_Max_Size
        Path
        Path_Key
        Exclude_Path
        Offset_Key
        Read_from_Head
        Refresh_Interval
        Rotate_Wait
        Ignore_Older
        Skip_Long_Lines
        Skip_Empty_Lines
        DB
        DB.sync
        DB.locking
        DB.journal_mode
        Mem_Buf_Limit
        Exit_On_Eof
        Parser
        Key
        Inotify_Watcher
        Tag
        Tag_Regex
        Static_Batch_Size
      )
      ;;

    tcp)
      PARAM_NAMES=(
        Listen
        Port
        Buffer_Size
        Chunk_Size
        Format
        Separator
      )
      ;;

    thermal)
      PARAM_NAMES=(
        Interval_Sec
        Interval_NSec
        name_regex
        type_regex
      )
      ;;

    *)
      PARAM_NAMES=()
      ;;
  esac

  for KEY in ${PARAM_NAMES[@]}; do
    VALUE="$(_GetString "$INPUT_NAME $KEY: ")"
    [[ -n "$VALUE" ]] && PARAMS+=(["$KEY"]="$VALUE")
  done

  FLUENTBIT_ARGS=()
  FLUENTBIT_PARSER_CFG=$(_fluentbit_parser_cfg)
  if [[ -n "$FLUENTBIT_PARSER_CFG" ]]; then
    FLUENTBIT_ARGS+=( -R )
    FLUENTBIT_ARGS+=( "$FLUENTBIT_PARSER_CFG" )
  fi
  FLUENTBIT_ARGS+=( -i )
  FLUENTBIT_ARGS+=( "$INPUT_NAME" )
  for key in "${!PARAMS[@]}"; do
    FLUENTBIT_ARGS+=( -p )
    FLUENTBIT_ARGS+=( $key="${PARAMS[$key]}" )
  done

  ( IFS=$'\n'; echo "${FLUENTBIT_ARGS[*]}" )
}

###############################################################################
# setup systemd (linux) service to run fluentbit as configured
function CreateFluentbitService() {
  COMMAND=("$@")

  SERVICE_CONFIRM="$(_GetConfirmation "Configure service to run fluent-bit [y/N]?" "n")"
  if [[ $SERVICE_CONFIRM =~ ^[Yy] ]]; then

    # linux services via systemd
    if [[ -n "$LINUX" ]]; then
      if systemctl --version >/dev/null 2>&1; then

        # prompt for a valid service name
        SERVICE_NAME=
        while [[ -z "$SERVICE_NAME" ]] || \
              [[ ! "$SERVICE_NAME" =~ ^[A-Za-z0-9_-]*$ ]] || \
              [[ -e "$HOME"/.config/systemd/user/"$SERVICE_NAME".service ]]; do
          SERVICE_NAME="$(_GetString "Enter .service file prefix:")"
        done

        # run as root or a regular user?
        if [[ "$SCRIPT_USER" != "root" ]]; then
          SYSCTL_USER_CONFIRM="$(_GetConfirmation "Configure systemd service as user \"$SCRIPT_USER\" [Y/n]?" "y")"
        else
          SYSCTL_USER_CONFIRM=n
        fi

        if [[ $SYSCTL_USER_CONFIRM =~ ^[Yy] ]]; then
          # running as a regular user, need to enable-linger for service to be able to run
          "$SUDO_CMD" loginctl enable-linger "$SCRIPT_USER" || echo "loginctl enable-linger $SCRIPT_USER failed" >&2

          # create service directory and write .service file
          mkdir -p "$HOME"/.config/systemd/user/ || echo "creating "$HOME"/.config/systemd/user/ failed" >&2
          cat <<EOF > "$HOME"/.config/systemd/user/"$SERVICE_NAME".service
[Unit]
AssertPathExists=$(_fluentbit_bin)
After=network.target

[Service]
ExecStart=$( ( IFS=$' '; echo "${FLUENTBIT_COMMAND[*]}" ) )
Restart=on-failure
PrivateTmp=false
NoNewPrivileges=false

[Install]
WantedBy=default.target
EOF
          systemctl --user daemon-reload
          systemctl --user enable "$SERVICE_NAME".service >&2
          systemctl --user start "$SERVICE_NAME".service >&2
          sleep 5
          systemctl --user status --no-pager "$SERVICE_NAME".service >&2

        else
          # running as root, ensure service directory exists and write .service file
          mkdir -p /etc/systemd/system/ || echo "creating /etc/systemd/system/ failed" >&2
          cat << EOF | "$SUDO_CMD" tee /etc/systemd/system/"$SERVICE_NAME".service >/dev/null 2>&1
[Unit]
AssertPathExists=$(_fluentbit_bin)
After=network.target

[Service]
ExecStart=$( ( IFS=$' '; echo "${FLUENTBIT_COMMAND[*]}" ) )
Restart=on-failure
PrivateTmp=false
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOF
          "$SUDO_CMD" systemctl daemon-reload
          "$SUDO_CMD" systemctl enable "$SERVICE_NAME".service >&2
          "$SUDO_CMD" systemctl start "$SERVICE_NAME".service >&2
          "$SUDO_CMD" sleep 5
          "$SUDO_CMD" systemctl status --no-pager "$SERVICE_NAME".service >&2
        fi # unprivileged vs. root
      else
        echo "systemctl not detected" >&2 && false
      fi # systemctl check

    elif [[ -n "$MACOS" ]]; then
      echo "macOS services not yet implemented" >&2 && false
    fi # os determination
  fi # user prompt
}

################################################################################
# "main" - ask the user what they want to do, and do it (or do it without interaction)
[[ -n $VERBOSE_FLAG ]] && echo "script in \"${SCRIPT_PATH}\" called from \"${FULL_PWD}\"" >&2 && set -x

trap _clean_up EXIT

# get a list of all the "public" functions (not starting with _)
FUNCTIONS=($(declare -F | awk '{print $NF}' | tac | egrep -v "^_"))

# present the menu to our customer and get their selection
printf "%s\t%s\n" "0" "ALL" >&2
for i in "${!FUNCTIONS[@]}"; do
  ((IPLUS=i+1))
  printf "%s\t%s\n" "$IPLUS" "${FUNCTIONS[$i]}" >&2
done

echo -n "Operation: " >&2
read USER_FUNCTION_IDX
if [[ -z "$USER_FUNCTION_IDX" ]] || (( $USER_FUNCTION_IDX == 0 )); then
  # do everything, in order
  if InstallFluentBit; then
    readarray -t FLUENTBIT_INPUT_INFO < <(GetFluentBitFormatInfo)
    if [[ "${#FLUENTBIT_INPUT_INFO[@]}" -ge 2 ]]; then
      readarray -t MALCOLM_CONN_INFO < <(GetMalcolmConnInfo)
      if [[ "${#MALCOLM_CONN_INFO[@]}" -ge 4 ]]; then
        FLUENTBIT_COMMAND=("$(_fluentbit_bin)" "${FLUENTBIT_INPUT_INFO[@]}" "${MALCOLM_CONN_INFO[@]}")
        echo
        ( IFS=$' '; echo "${FLUENTBIT_COMMAND[*]}" )
        echo
        CreateFluentbitService "${FLUENTBIT_COMMAND[@]}"
      else
        echo "Failed to get fluent-bit output parameters" >&2
        exit 1;
      fi
    else
      echo "Failed to get fluent-bit input parameters" >&2
      exit 1;
    fi
  else
    echo "Failed to install fluent-bit" >&2
    exit 1;
  fi

elif (( $USER_FUNCTION_IDX > 0 )) && (( $USER_FUNCTION_IDX <= "${#FUNCTIONS[@]}" )); then
  # execute one function, à la carte
  USER_FUNCTION="${FUNCTIONS[((USER_FUNCTION_IDX-1))]}"
  echo $USER_FUNCTION >&2
  $USER_FUNCTION

else
  # some people just want to watch the world burn
  echo "Invalid operation selected" >&2
  exit 1;
fi
