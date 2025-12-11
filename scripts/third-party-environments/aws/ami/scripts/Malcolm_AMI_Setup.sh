#!/usr/bin/env bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

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
MALCOLM_TAG=${MALCOLM_TAG:-v25.12.1}
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
fs.file-max=518144

# the maximum number of user inotify watches
fs.inotify.max_user_watches=131072

# the maximum number of memory map areas a process may have
vm.max_map_count=262144

# the maximum number of incoming connections
net.core.somaxconn=65535

# decrease "swappiness" (swapping out runtime memory vs. dropping pages)
vm.swappiness=1

# the % of system memory fillable with "dirty" pages before flushing
vm.dirty_background_ratio=40

# maximum % of dirty system memory before committing everything
vm.dirty_ratio=80

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

################################################################################
# _InstallTool - generalized GitHub binary installer
# Usage:
#   _InstallTool <repo> <binary_name> <asset_pattern_amd64> <asset_pattern_arm64> [--strip N]
#
# Examples:
#   _InstallTool schollz/croc croc \
#     "croc_{ver}_Linux-64bit.tar.gz" "croc_{ver}_Linux-ARM64.tar.gz" --strip 0
#
#   _InstallTool mikefarah/yq yq \
#     "yq_linux_amd64" "yq_linux_arm64"
################################################################################
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

  local release="$(_GitLatestRelease "$repo")"
  local dest_dir=/usr/bin
  $SUDO_CMD mkdir -p "$dest_dir"
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

    $SUDO_CMD cp -f "$found_bin" "$dest_dir/$bin_name"
  else
    $SUDO_CMD curl -sSL -o "$dest_dir/$bin_name" "$url"
  fi

  $SUDO_CMD chmod 755 "$dest_dir/$bin_name"
  $SUDO_CMD chown root:root "$dest_dir/$bin_name"
  rm -rf "$tmp_dir"
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
    "bat-{ver}-aarch64-unknown-linux-musl.tar.gz" --strip 1
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
    [[ ! -f /usr/bin/croc ]] && _InstallCroc
    [[ ! -f /usr/bin/yq ]] && _InstallYQ
    [[ ! -f /usr/bin/boringproxy ]] && _InstallBoringProxy
    [[ ! -f /usr/bin/bat ]] && _InstallBat
    [[ ! -f /usr/bin/exa ]] && _InstallEza
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
InstallUserLocalBinaries
InstallPythonPackages
InstallDocker
InstallMalcolm
