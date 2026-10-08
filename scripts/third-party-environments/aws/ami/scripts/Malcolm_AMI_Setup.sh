#!/usr/bin/env bash

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

# Configure Amazon Linux 2023 and install Malcolm

###############################################################################
# script options
set -o pipefail
shopt -s nocasematch
ENCODING="utf-8"

###############################################################################
# checks and initialization

if [[ -z "$BASH_VERSION" ]]; then
    echo "Wrong interpreter, please run \"$0\" with bash" >&2
    exit 1
fi

if [[ "$(awk -F= '$1=="PLATFORM_ID" { print $2 ;}' /etc/os-release | tr -d '"')" != "platform:al2023" ]]; then
  echo "This command only targets Amazon Linux 2023" >&2
  exit 1
fi

###############################################################################
# command-line parameters
# options
# -v          (verbose)
# -r repo     (Malcolm repository, e.g., cisagov/Malcolm)
# -t tag      (Malcolm tag, e.g., v23.05.1)
# -u UID      (user UID, e.g., 1000)
VERBOSE_FLAG=
MALCOLM_REPO=${MALCOLM_REPO:-idaholab/Malcolm}
MALCOLM_TAG=${MALCOLM_TAG:-v26.09.0}
[[ -z "$MALCOLM_UID" ]] && ( [[ $EUID -eq 0 ]] && MALCOLM_UID=1000 || MALCOLM_UID="$(id -u)" )
while getopts 'vr:t:u:' OPTION; do
  case "$OPTION" in
    v)
      VERBOSE_FLAG="-v"
      set -x
      ;;

    r)
      MALCOLM_REPO="$OPTARG"
      ;;

    t)
      MALCOLM_TAG="$OPTARG"
      ;;

    u)
      MALCOLM_UID="$OPTARG"
      ;;

    ?)
      echo "script usage: $(basename $0) [-v (verbose)] [-r <repo>] [-t <tag>] [-u <UID>]" >&2
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"

if [[ $EUID -eq 0 ]]; then
    SUDO_CMD=""
else
    SUDO_CMD="sudo"
fi

$SUDO_CMD mkdir -p /etc/sudoers.d/
echo 'Defaults umask = 0022' | ($SUDO_CMD su -c 'EDITOR="tee" visudo -f /etc/sudoers.d/99-default-umask')
echo 'Defaults umask_override' | ($SUDO_CMD su -c 'EDITOR="tee -a" visudo -f /etc/sudoers.d/99-default-umask')
$SUDO_CMD chmod 440 /etc/sudoers.d/99-default-umask
umask 0022

MALCOLM_USER="$(id -nu $MALCOLM_UID)"
MALCOLM_USER_GROUP="$(id -gn $MALCOLM_UID)"
MALCOLM_USER_HOME="$(getent passwd "$MALCOLM_USER" | cut -d: -f6)"
MALCOLM_URL="https://codeload.github.com/$MALCOLM_REPO/tar.gz/$MALCOLM_TAG"
LINUX_CPU=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')
IMAGE_ARCH_SUFFIX="$(uname -m | sed 's/^x86_64$//' | sed 's/^arm64$/-arm64/' | sed 's/^aarch64$/-arm64/')"

###################################################################################
# InstallEssentialPackages
function InstallEssentialPackages {
    echo "Installing essential packages..." >&2

    # install the package(s) from yum
    $SUDO_CMD yum install -y \
        cronie \
        curl-minimal \
        dialog \
        git \
        httpd-tools \
        jq \
        make \
        openssl \
        tmux \
        xz
}

################################################################################
# InstallPythonPackages - install specific python packages
function InstallPythonPackages {
    echo "Installing Python 3 and pip packages..." >&2

    [[ $EUID -eq 0 ]] && USERFLAG="" || USERFLAG="--user"

    $SUDO_CMD yum install -y \
        python3-pip \
        python3-setuptools \
        python3-wheel \
        python3-ruamel-yaml \
        python3-requests+security

    $SUDO_CMD /usr/bin/python3 -m pip install $USERFLAG -U \
        dateparser==1.2.2 \
        kubernetes==34.1.0 \
        python-dotenv==1.2.1 \
        pythondialog==3.5.3
}

################################################################################
# InstallDocker - install Docker and enable it as a service, and install docker-compose
function InstallDocker {
    echo "Installing Docker and docker-compose..." >&2

    # install docker, if needed
    if ! command -v docker >/dev/null 2>&1 ; then

        $SUDO_CMD yum update -y >/dev/null 2>&1 && \
            $SUDO_CMD yum install -y docker

        $SUDO_CMD systemctl enable docker
        $SUDO_CMD systemctl start docker

        if [[ -n "$MALCOLM_USER" ]]; then
            echo "Adding \"$MALCOLM_USER\" to group \"docker\"..." >&2
            $SUDO_CMD usermod -a -G docker "$MALCOLM_USER"
            echo "$MALCOLM_USER will need to log out and log back in for this to take effect" >&2
        fi

    else
        echo "\"docker\" is already installed!" >&2
    fi # docker install check

    # install docker-compose, if needed
    if ! command -v docker-compose >/dev/null 2>&1 ; then
        echo "Installing Docker Compose via curl to /usr/bin..." >&2

        $SUDO_CMD curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/bin/docker-compose
        $SUDO_CMD chmod 755 /usr/bin/docker-compose
        if ! /usr/bin/docker-compose version >/dev/null 2>&1 ; then
            echo "Installing docker-compose failed" >&2
            exit 1
        fi
    else
        echo "\"docker-compose\" is already installed!" >&2
    fi # docker-compose install check
}


################################################################################
# SystemConfig - configure sysctl parameters, kernel parameters, and limits
function SystemConfig {
    echo "Configuring system settings..." >&2

    if [[ -d /etc/sysctl.d ]] && ! grep -q swappiness /etc/sysctl.d/*.conf; then

        $SUDO_CMD tee -a /etc/sysctl.d/99-sysctl-performance.conf > /dev/null <<'EOT'

# allow dmg reading
kernel.dmesg_restrict=0

# the maximum number of open file handles
fs.file-max=2097152

# the maximum number of user inotify watches
fs.inotify.max_user_watches=131072

# the maximum number of incoming connections
net.core.somaxconn=65535

# the maximum number of memory map areas a process may have
vm.max_map_count=524288

# decrease "swappiness" (swapping out runtime memory vs. dropping pages)
vm.swappiness=1

# the % of system memory fillable with "dirty" pages before flushing
vm.dirty_background_ratio=5

# maximum % of dirty system memory before committing everything
vm.dirty_ratio=10

# virtual memory accounting mode: always overcommit, never check
vm.overcommit_memory=1
EOT
    fi # sysctl check

    if [[ ! -f /etc/security/limits.d/limits.conf ]]; then
        $SUDO_CMD mkdir -p /etc/security/limits.d/
        $SUDO_CMD tee /etc/security/limits.d/limits.conf > /dev/null <<'EOT'
* soft nofile 65535
* hard nofile 65535
* soft memlock unlimited
* hard memlock unlimited
* soft nproc 262144
* hard nproc 524288
* soft core 0
* hard core 0
EOT
    fi # limits.conf check

    if [[ -f /etc/default/grub ]] && ! grep -q cgroup /etc/default/grub; then
        $SUDO_CMD sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="[^"]*/& systemd.unified_cgroup_hierarchy=1 cgroup_enable=memory swapaccount=1 cgroup.memory=nokmem random.trust_cpu=on preempt=voluntary/' /etc/default/grub
        $SUDO_CMD grub2-mkconfig -o /boot/grub2/grub.cfg
    fi # grub check
}

################################################################################
# _InstallTool - install only repository-pinned and SHA-256-verified releases.
# These setup scripts are intentionally standalone, so the pinned checksums
# live here rather than in a manifest that may not be copied onto the AMI.
function _PinnedToolReleaseAndSha256 {
  case "$1:$2" in
    schollz/croc:amd64) printf '%s %s\n' 'v11.5.4' '577f2c4170fac3f8ab244e325cdeea5644788e1cd7620f592a5d365ee349d556' ;;
    schollz/croc:arm64) printf '%s %s\n' 'v11.5.4' '532646fdc82e51b524aa99fa52024e8d9ddf8b67622f574b5ae7943dc9ffce55' ;;
    mikefarah/yq:amd64) printf '%s %s\n' 'v4.54.1' '8e34fc298390875de416e6a4afcb8cabeceb25d9aa8506c1a2f9353cf702ea5f' ;;
    mikefarah/yq:arm64) printf '%s %s\n' 'v4.54.1' '189088da0c6429ec5178dfaab1a114805f6cab0b61b165ab236efedf1d57a71b' ;;
    boringproxy/boringproxy:amd64) printf '%s %s\n' 'v0.10.0' 'f5b42d933cea4d53aa975039de0cb1053287fac5ce4377d2afb663e26a5d22dd' ;;
    boringproxy/boringproxy:arm64) printf '%s %s\n' 'v0.10.0' '7a778797dd640eb51defe912e8b6872df92241927193106590a2ccb92a5dc926' ;;
    sharkdp/bat:amd64) printf '%s %s\n' 'v0.26.1' '0dcd8ac79732c0d5b136f11f4ee00e581440e16a44eab5b3105b611bbf2cf191' ;;
    sharkdp/bat:arm64) printf '%s %s\n' 'v0.26.1' '6369242c584065f195fb20cb36fbd7cb63ae690605bbe89868a7596b596c2c23' ;;
    eza-community/eza:amd64) printf '%s %s\n' 'v0.23.5' 'e06eebab74b73d6b7d51a796a353824b001bea82df077706382e100815d28904' ;;
    eza-community/eza:arm64) printf '%s %s\n' 'v0.23.5' '1c01b578b5bd3f23b7de5a4b41936cde20fb16ff16a03e63266317ac1eb821e0' ;;
    *) echo "No pinned tool release/checksum for $1 ($2)" >&2; return 1 ;;
  esac
}

# Usage: _InstallTool <repo> <binary_name> <amd64_asset> <arm64_asset> [--strip N]
function _InstallTool {
  local repo="$1" bin_name="$2" amd64_pattern="$3" arm64_pattern="$4"
  local strip_components=1
  shift 4
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --strip)
        [[ $# -ge 2 ]] || { echo "Missing --strip argument" >&2; return 1; }
        strip_components="$2"; shift 2 ;;
      *) echo "Unknown _InstallTool option: $1" >&2; return 1 ;;
    esac
  done

  local cpu release expected_sha asset_pattern asset_url dest_dir pinned
  cpu="$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
  case "$cpu" in
    amd64) asset_pattern="$amd64_pattern" ;;
    arm64) asset_pattern="$arm64_pattern" ;;
    *) echo "Unsupported architecture: $cpu" >&2; return 1 ;;
  esac
  if [[ -z "$bin_name" || "$bin_name" == "-" ]]; then
    bin_name="$(basename "$repo")"
  fi
  [[ "$bin_name" =~ ^[a-zA-Z0-9_-]+$ ]] || return 1
  pinned="$(_PinnedToolReleaseAndSha256 "$repo" "$cpu")" || return 1
  read -r release expected_sha <<< "$pinned"
  [[ "$release" == v* && "$expected_sha" =~ ^[a-f0-9]{64}$ ]] || return 1
  asset_pattern="$(printf %s "$asset_pattern" | sed "s/{ver}/$release/g")"
  asset_url="https://github.com/$repo/releases/download/$release/$asset_pattern"
  dest_dir="/usr/bin"
  echo "Installing verified $bin_name ($release) from $asset_url" >&2

  (
    set -e
    local temp_dir artifact selected_bin
    temp_dir="$(mktemp -d)"
    trap 'rm -rf "$temp_dir"' EXIT
    artifact="$temp_dir/$asset_pattern"
    curl -fsSL --retry 3 -o "$artifact" "$asset_url"
    printf '%s  %s\n' "$expected_sha" "$artifact" | sha256sum -c - >&2

    if [[ "$asset_pattern" == *.tar.gz || "$asset_pattern" == *.tgz ]]; then
      mkdir -p "$temp_dir/unpacked"
      tar -xzf "$artifact" -C "$temp_dir/unpacked" --strip-components="$strip_components"
      selected_bin="$temp_dir/unpacked/$bin_name"
    else
      selected_bin="$artifact"
    fi
    if [[ ! -f "$selected_bin" ]]; then
      echo "Pinned archive does not contain expected executable: $bin_name" >&2
      exit 1
    fi
    # Verification and exact file selection both precede privileged writes.
    $SUDO_CMD mkdir -p "$dest_dir"
    $SUDO_CMD install -m 755 "$selected_bin" "$dest_dir/$bin_name"
    $SUDO_CMD chown root:root "$dest_dir/$bin_name"
  )
}

function _InstallCroc {
  _InstallTool schollz/croc - \
    "croc_{ver}_Linux-64bit.tar.gz" \
    "croc_{ver}_Linux-ARM64.tar.gz" --strip 0
}
function _InstallYQ {
  _InstallTool mikefarah/yq - \
    "yq_linux_amd64" "yq_linux_arm64"
}

function _InstallBoringProxy {
  _InstallTool boringproxy/boringproxy - \
    "boringproxy-linux-x86_64" "boringproxy-linux-arm64"
}

function _InstallBat {
  _InstallTool sharkdp/bat - \
    "bat-{ver}-x86_64-unknown-linux-musl.tar.gz" \
    "bat-{ver}-aarch64-unknown-linux-musl.tar.gz" --strip 1 || return 1
  $SUDO_CMD ln -s -r /usr/bin/bat /usr/bin/batcat
}

function _InstallEza {
  _InstallTool eza-community/eza - \
    "eza_x86_64-unknown-linux-musl.tar.gz" \
    "eza_aarch64-unknown-linux-gnu_no_libgit.tar.gz" --strip 1
}

################################################################################
# InstallUserLocalBinaries - install various tools to LOCAL_BIN_PATH
function InstallUserLocalBinaries {
    [[ -f /usr/bin/croc ]] || _InstallCroc || return 1
    [[ -f /usr/bin/yq ]] || _InstallYQ || return 1
    [[ -f /usr/bin/boringproxy ]] || _InstallBoringProxy || return 1
    [[ -f /usr/bin/bat ]] || _InstallBat || return 1
    [[ -f /usr/bin/eza ]] || _InstallEza || return 1
}

################################################################################
# InstallMalcolm - clone and configure Malcolm and grab some sample PCAP
function InstallMalcolm {
    echo "Downloading and unpacking Malcolm..." >&2

    pushd "$MALCOLM_USER_HOME" >/dev/null 2>&1
    mkdir -p ./Malcolm
    curl -fsSL "$MALCOLM_URL" | tar xzf - -C ./Malcolm --strip-components 1
    if [[ -s ./Malcolm/docker-compose.yml ]]; then
        pushd ./Malcolm >/dev/null 2>&1
        for ENVEXAMPLE in ./config/*.example; do ENVFILE="${ENVEXAMPLE%.*}"; cp "$ENVEXAMPLE" "$ENVFILE"; done
        sed -i "s@\(/malcolm/.*\):\(.*\)@\1:\2${IMAGE_ARCH_SUFFIX}@g" docker-compose.yml
        echo "Pulling Docker images..." >&2
        grep 'image:' docker-compose.yml | awk '{print $2}' | xargs -r -l docker pull
        rm -f ./config/*.env
        docker images
        popd >/dev/null 2>&1
    fi
    popd >/dev/null 2>&1
    mkdir -p "$MALCOLM_USER_HOME"/.local/bin \
             "$MALCOLM_USER_HOME"/.config
    rm -f "$MALCOLM_USER_HOME"/.bashrc \
          "$MALCOLM_USER_HOME"/.bash_aliases \
          "$MALCOLM_USER_HOME"/.bash_functions \
          "$MALCOLM_USER_HOME"/.vimrc \
          "$MALCOLM_USER_HOME"/.tmux.conf
    cp "$MALCOLM_USER_HOME"/Malcolm/malcolm-iso/config/includes.chroot/etc/bash.bash_aliases \
       "$MALCOLM_USER_HOME"/.bash_aliases
    cp "$MALCOLM_USER_HOME"/Malcolm/malcolm-iso/config/includes.chroot/etc/bash.bash_functions \
       "$MALCOLM_USER_HOME"/.bash_functions
    cp "$MALCOLM_USER_HOME"/Malcolm/malcolm-iso/config/includes.chroot/etc/skel/.bashrc \
       "$MALCOLM_USER_HOME"/.bashrc
    cp "$MALCOLM_USER_HOME"/Malcolm/malcolm-iso/config/includes.chroot/etc/skel/.tmux.conf \
       "$MALCOLM_USER_HOME"/.tmux.conf
    cp "$MALCOLM_USER_HOME"/Malcolm/malcolm-iso/config/includes.chroot/etc/skel/.vimrc \
       "$MALCOLM_USER_HOME"/.vimrc

    cat << 'EOF' >> "$MALCOLM_USER_HOME"/.bashrc

# Configure Malcolm on first login
if [[ $- == *i* ]] && [[ -d ~/Malcolm ]] &&  [[ ! -f ~/Malcolm/.configured ]]; then
    pushd ~/Malcolm >/dev/null 2>&1
    ./scripts/install.py --configure
    ./scripts/auth_setup
    popd >/dev/null 2>&1
    clear
    cat << 'EOT'

To start, stop, restart, etc. Malcolm:
  Use the control scripts in the "~/Malcolm/scripts/" directory:
   - start         (start Malcolm)
   - stop          (stop Malcolm)
   - restart       (restart Malcolm)
   - logs          (monitor Malcolm logs)
   - wipe          (stop Malcolm and clear its database)
   - auth_setup    (change authentication-related settings)

Malcolm services can be accessed at https://<IP or hostname>/

EOT
fi
EOF

    $SUDO_CMD chown -R $MALCOLM_USER:$MALCOLM_USER_GROUP "$MALCOLM_USER_HOME"
}

################################################################################
# "main"

SystemConfig
InstallEssentialPackages
InstallUserLocalBinaries || exit 1
InstallPythonPackages
InstallDocker
InstallMalcolm
