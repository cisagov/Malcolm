#!/usr/bin/env bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

###################################################################################
# for setting up a Malcolm demo instance on an Amazon Linux 2023 instance from scratch
#
# I've used:
# - for x86-64 instances `c4.4xlarge`, `t2.2xlarge`, and `t3a.2xlarge`
# - for arm64 instances `m6gd.2xlarge`, `m6g.2xlarge`, `m7g.2xlarge`, and `t4g.2xlarge`
#
###################################################################################
# initialize

if [[ -z "$BASH_VERSION" ]]; then
  echo "Wrong interpreter, please run \"$0\" with bash" >&2
  exit 1
fi

if [[ "$(awk -F= '$1=="PLATFORM_ID" { print $2 ;}' /etc/os-release | tr -d '"')" != "platform:al2023" ]]; then
  echo "This command only targets Amazon Linux 2023" >&2
  exit 1
fi

REALPATH=realpath
DIRNAME=dirname
if ! (type "$REALPATH" && type "$DIRNAME") > /dev/null; then
  echo "$(basename "${BASH_SOURCE[0]}") requires $REALPATH and $DIRNAME" >&2
  exit 1
fi
SCRIPT_PATH="$($DIRNAME $($REALPATH -e "${BASH_SOURCE[0]}"))"
SCRIPT_NAME="$(basename $($REALPATH -e "${BASH_SOURCE[0]}"))"

if [[ $EUID -eq 0 ]]; then
  SCRIPT_USER="root"
  SUDO_CMD=""
else
  SCRIPT_USER="$(whoami)"
  SUDO_CMD="sudo"
fi

$SUDO_CMD mkdir -p /etc/sudoers.d/
echo 'Defaults umask = 0022' | ($SUDO_CMD su -c 'EDITOR="tee" visudo -f /etc/sudoers.d/99-default-umask')
echo 'Defaults umask_override' | ($SUDO_CMD su -c 'EDITOR="tee -a" visudo -f /etc/sudoers.d/99-default-umask')
$SUDO_CMD chmod 440 /etc/sudoers.d/99-default-umask
umask 0022

LINUX_CPU=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')

# default user paths
LOCAL_DATA_PATH=${XDG_DATA_HOME:-$HOME/.local/share}
LOCAL_BIN_PATH=$HOME/.local/bin
LOCAL_CONFIG_PATH=${XDG_CONFIG_HOME:-$HOME/.config}

# set MALCOLM_SETUP_NONINTERACTIVE=1 to accept defaults without interaction
MALCOLM_SETUP_NONINTERACTIVE=${MALCOLM_SETUP_NONINTERACTIVE:-0}

###################################################################################
# variables for env development environments and tools
ENV_LIST=(
  age
  bat
  direnv
  eza
  fd
  fzf
  jq
  peco
  ripgrep
  viddy
)

###################################################################################
# _GetConfirmation - get a yes/no confirmation from the user (or accept the default)
function _GetConfirmation {
  PROMPT=${1:-"[y/N]?"}
  DEFAULT_ANSWER=${2:-n}
  unset CONFIRMATION
  if (( $MALCOLM_SETUP_NONINTERACTIVE == 1 )); then
    echo "${PROMPT} ${DEFAULT_ANSWER}" >&2
  else
    echo -n "${PROMPT} " >&2
    read CONFIRMATION
  fi
  CONFIRMATION=${CONFIRMATION:-$DEFAULT_ANSWER}
  echo $CONFIRMATION
}

###################################################################################
# _GetString - get a string response from the user (or accept the default)
function _GetString {
  PROMPT=${1:-""}
  DEFAULT_ANSWER=${2:-""}
  unset RESPONSE
  if (( $MALCOLM_SETUP_NONINTERACTIVE == 1 )); then
    echo "${PROMPT} ${DEFAULT_ANSWER}" >&2
  else
    echo -n "${PROMPT} " >&2
    read RESPONSE
  fi
  RESPONSE=${RESPONSE:-$DEFAULT_ANSWER}
  echo $RESPONSE
}

###################################################################################
# InstallEssentialPackages - installing curl, git and jq which are required
function InstallEssentialPackages {
  if curl -V >/dev/null 2>&1 && \
     git --version >/dev/null 2>&1 && \
     jq --version >/dev/null 2>&1; then
    echo "\"curl\", \"git\" and \"jq\" are already installed!" >&2
  else
    echo "Installing curl, git, and jq..." >&2
    $SUDO_CMD yum update -y >/dev/null 2>&1 && \
      $SUDO_CMD yum install -y curl-minimal git jq
  fi
}

###################################################################################
# _GitClone - glone a git repository (recursing submodules) without history
function _GitClone {
  git clone --depth=1 --single-branch --recurse-submodules --shallow-submodules --no-tags "$@"
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
# _EnvSetup - asdf path/variable initialization
function _EnvSetup {
  export ASDF_DATA_DIR="$HOME/.asdf"

  if ! command -v asdf >/dev/null 2>&1 && [[ -x "$LOCAL_BIN_PATH"/asdf ]]; then
    export PATH="$LOCAL_BIN_PATH:$PATH"
  fi
  if command -v asdf >/dev/null 2>&1 && [[ -d "${ASDF_DATA_DIR}" ]]; then
    export PATH="${ASDF_DATA_DIR}/shims:$PATH"
    [[ -n $BASH_VERSION ]] && . <(asdf completion bash)
    for i in ${ENV_LIST[@]}; do
      asdf reshim "$i" >/dev/null 2>&1 || true
    done
  fi
}

################################################################################
# InstallEnvs - install asdf environments
function InstallEnvs {
  declare -A ENVS_INSTALLED
  for i in ${ENV_LIST[@]}; do
    ENVS_INSTALLED[$i]=false
  done

  ASDF_PLATFORM=linux
  if [[ $LINUX_ARCH =~ ^arm ]]; then
    if [[ $LINUX_CPU == aarch64 ]]; then
      ASDF_ARCH=arm64
    else
      ASDF_ARCH=
    fi
  else
    ASDF_ARCH=amd64
  fi

  if [[ -n "$ASDF_PLATFORM" ]] && [[ -n "$ASDF_ARCH" ]] && ! command -v asdf >/dev/null 2>&1; then
    export ASDF_DATA_DIR="$HOME/.asdf"
    CONFIRMATION=$(_GetConfirmation "\"asdf\" is not installed, attempt to install it [Y/n]?" Y)
    if [[ $CONFIRMATION =~ ^[Yy] ]]; then
      InstallEssentialPackages
      mkdir -p "${LOCAL_BIN_PATH}" "${ASDF_DATA_DIR}"
      ASDF_RELEASE="$(_GitLatestRelease asdf-vm/asdf)"
      ASDF_URL="https://github.com/asdf-vm/asdf/releases/download/${ASDF_RELEASE}/asdf-${ASDF_RELEASE}-${ASDF_PLATFORM}-${ASDF_ARCH}.tar.gz"
      curl -sSL "$ASDF_URL" | tar xzf - -C "${LOCAL_BIN_PATH}"
      [[ -f "${LOCAL_BIN_PATH}"/asdf ]] && chmod 755 "${LOCAL_BIN_PATH}"/asdf
    fi
  fi

  if command -v asdf >/dev/null 2>&1 || [[ -x "${LOCAL_BIN_PATH}"/asdf ]] ; then
    _EnvSetup
    if [[ -n $ASDF_DATA_DIR ]]; then
      for i in ${ENV_LIST[@]}; do
        if ! ( asdf plugin list | grep -q "$i" ) >/dev/null 2>&1 ; then
          CONFIRMATION=$(_GetConfirmation "\"$i\" is not installed, attempt to install it [Y/n]?" Y)
          if [[ $CONFIRMATION =~ ^[Yy] ]]; then
            asdf plugin add "$i" && ENVS_INSTALLED[$i]=true
          fi
        else
          CONFIRMATION=$(_GetConfirmation "\"$i\" is already installed, attempt to update it [Y/n]?" Y)
          if [[ $CONFIRMATION =~ ^[Yy] ]]; then
            ENVS_INSTALLED[$i]=true
          fi
        fi
      done
    fi
    _EnvSetup
  fi # .asdf check

  # install versions of the tools and plugins
  for i in ${ENV_LIST[@]}; do
    if [[ ${ENVS_INSTALLED[$i]} = 'true' ]]; then
      asdf plugin update $i
      asdf install $i latest
      asdf set -u $i latest
      asdf reshim $i
    fi
  done
  _EnvSetup
}

################################################################################
# InstallEnvPackages - install specific env. packages (e.g., pip)
function InstallEnvPackages {
  CONFIRMATION=$(_GetConfirmation "Install common pip, etc. packages [Y/n]?" Y)
  if [[ $CONFIRMATION =~ ^[Yy] ]]; then
    _EnvSetup

    if python3 -m pip -V >/dev/null 2>&1; then
      python3 -m pip install --user -U \
        dateparser==1.2.1 \
        kubernetes==32.0.1 \
        python-dotenv==1.1.0 \
        pythondialog==3.5.3 \
        mmguero==1.3.4
    fi
  fi

  _EnvSetup
}

################################################################################
# InstallDocker - install Docker and enable it as a service, and install docker compose
function InstallDocker {

  # install docker-ce, if needed
  if ! $SUDO_CMD docker info >/dev/null 2>&1 ; then
    CONFIRMATION=$(_GetConfirmation "\"docker info\" failed, attempt to install docker [Y/n]?" Y)
    if [[ $CONFIRMATION =~ ^[Yy] ]]; then

      InstallEssentialPackages

      $SUDO_CMD yum update -y >/dev/null 2>&1 && \
        $SUDO_CMD yum install -y docker

      $SUDO_CMD systemctl enable docker
      $SUDO_CMD systemctl start docker

      if [[ "$SCRIPT_USER" != "root" ]]; then
        echo "Adding \"$SCRIPT_USER\" to group \"docker\"..." >&2
        $SUDO_CMD usermod -a -G docker "$SCRIPT_USER"
        echo "You will need to log out and log back in for this to take effect" >&2
      fi
    fi # docker install confirmation check

  else
    echo "\"docker\" is already installed!" >&2
  fi # docker install check

  # install docker-compose, if needed
  if ! docker-compose version >/dev/null 2>&1 ; then
    CONFIRMATION=$(_GetConfirmation "\"docker-compose version\" failed, attempt to install docker-compose [Y/n]?" Y)
    if [[ $CONFIRMATION =~ ^[Yy] ]]; then
      echo "Installing Docker Compose via curl to /usr/bin..." >&2
      InstallEssentialPackages
      $SUDO_CMD curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/bin/docker-compose
      $SUDO_CMD chmod +x /usr/bin/docker-compose
      if ! /usr/bin/docker-compose version >/dev/null 2>&1 ; then
        echo "Installing docker-compose failed" >&2
        exit 1
      fi
    fi # docker-compose install confirmation check
  else
    echo "\"docker-compose\" is already installed!" >&2
  fi # docker-compose install check
}

################################################################################
# InstallCommonPackages - install packages from yum
function InstallCommonPackages {

  CONFIRMATION=$(_GetConfirmation "Install common packages [Y/n]?" Y)
  if [[ $CONFIRMATION =~ ^[Yy] ]]; then

    $SUDO_CMD yum update -y >/dev/null 2>&1

    PACKAGE_LIST=(
      cronie
      dialog
      httpd-tools
      openssl
      python3-pip
      python3-requests+security
      python3-ruamel-yaml
      python3-setuptools
      python3-wheel
      tmux
      wireshark-cli
      xz
    )
    # install the packages from yum
    for i in ${PACKAGE_LIST[@]}; do
      $SUDO_CMD yum install -y "$i"
    done

  fi # install common packages confirmation
}

################################################################################
# _InstallCroc - schollz/croc: easily and securely send things from one computer to another
function _InstallCroc {
  mkdir -p "$LOCAL_BIN_PATH"

  CROC_RELEASE="$(_GitLatestRelease schollz/croc)"
  TMP_CLONE_DIR="$(mktemp -d)"
  if [[ "$LINUX_CPU" == "arm64" ]]; then
    CROC_URL="https://github.com/schollz/croc/releases/download/${CROC_RELEASE}/croc_${CROC_RELEASE}_Linux-ARM64.tar.gz"
  elif [[ "$LINUX_CPU" == "amd64" ]]; then
    CROC_URL="https://github.com/schollz/croc/releases/download/${CROC_RELEASE}/croc_${CROC_RELEASE}_Linux-64bit.tar.gz"
  else
    CROC_URL=
  fi
  if [[ -n "$CROC_URL" ]]; then
    curl -sSL "$CROC_URL" | tar xvzf - -C "${TMP_CLONE_DIR}"
    cp -f "${TMP_CLONE_DIR}"/croc "$LOCAL_BIN_PATH"/croc
    chmod 755 "$LOCAL_BIN_PATH"/croc
  fi
  rm -rf "$TMP_CLONE_DIR"
}

################################################################################
# _InstallYQ - mikefarah/yq: YAML command-line utility
function _InstallYQ {
  mkdir -p "$LOCAL_BIN_PATH"
  YQ_RELEASE="$(_GitLatestRelease mikefarah/yq)"
  if [[ "$LINUX_CPU" == "arm64" ]]; then
    YQ_URL="https://github.com/mikefarah/yq/releases/download/${YQ_RELEASE}/yq_linux_arm64"
  elif [[ "$LINUX_CPU" == "amd64" ]]; then
    YQ_URL="https://github.com/mikefarah/yq/releases/download/${YQ_RELEASE}/yq_linux_amd64"
  else
    YQ_URL=
  fi
  if [[ -n "$YQ_URL" ]]; then
    curl -sSL -o "$LOCAL_BIN_PATH"/yq "$YQ_URL"
    chmod 755 "$LOCAL_BIN_PATH"/yq
  fi
}

################################################################################
# _InstallBoringProxy - boringproxy/boringproxy: a reverse proxy and tunnel manager
function _InstallBoringProxy {
  mkdir -p "$LOCAL_BIN_PATH"

  BORING_RELEASE="$(_GitLatestRelease boringproxy/boringproxy)"
  if [[ "$LINUX_CPU" == "arm64" ]]; then
    BORING_URL="https://github.com/boringproxy/boringproxy/releases/download/${BORING_RELEASE}/boringproxy-linux-arm64"
  elif [[ "$LINUX_CPU" == "amd64" ]]; then
    BORING_URL="https://github.com/boringproxy/boringproxy/releases/download/${BORING_RELEASE}/boringproxy-linux-x86_64"
  else
    BORING_URL=
  fi
  if [[ -n "$BORING_URL" ]]; then
    curl -sSL -o "${LOCAL_BIN_PATH}"/boringproxy.new "$BORING_URL"
    chmod 755 "${LOCAL_BIN_PATH}"/boringproxy.new
    [[ -f "$LOCAL_BIN_PATH"/boringproxy ]] && rm -f "$LOCAL_BIN_PATH"/boringproxy
    mv "$LOCAL_BIN_PATH"/boringproxy.new "$LOCAL_BIN_PATH"/boringproxy
  fi
}

################################################################################
# InstallUserLocalBinaries - install various tools to LOCAL_BIN_PATH
function InstallUserLocalBinaries {
  CONFIRMATION=$(_GetConfirmation "Install user-local binaries/packages [Y/n]?" Y)
  if [[ $CONFIRMATION =~ ^[Yy] ]]; then
    [[ ! -f "${LOCAL_BIN_PATH}"/croc ]] && _InstallCroc
    [[ ! -f "${LOCAL_BIN_PATH}"/yq ]] && _InstallYQ
    [[ ! -f "${LOCAL_BIN_PATH}"/boringproxy ]] && _InstallBoringProxy
  fi
}

################################################################################
# CreateCommonLinuxConfig - tweak a few things in $HOME (.vimrc, local paths, .ssh, etc.)
function CreateCommonLinuxConfig {

  CONFIRMATION=$(_GetConfirmation "Create missing common local config in home [Y/n]?" Y)
  if [[ $CONFIRMATION =~ ^[Yy] ]]; then

    touch ~/.hushlogin

    mkdir -p "$HOME/tmp" \
             "$HOME/devel" \
             "$LOCAL_BIN_PATH"

    [[ ! -f ~/.vimrc ]] && echo "set nocompatible" > ~/.vimrc

    if [[ ! -d ~/.ssh ]]; then
      mkdir ~/.ssh
      chmod 700 ~/.ssh
    fi
  fi
}

################################################################################
# SystemConfig - configure sysctl parameters, kernel parameters, and limits
function SystemConfig {

  if [[ -r /etc/sysctl.conf ]] && ! grep -q swappiness /etc/sysctl.conf; then
    CONFIRMATION=$(_GetConfirmation "Tweak sysctl.conf (swap, NIC buffers, handles, etc.) [Y/n]?" Y)
    if [[ $CONFIRMATION =~ ^[Yy] ]]; then
      $SUDO_CMD tee -a /etc/sysctl.conf > /dev/null <<'EOT'

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
EOT
    fi # sysctl confirmation
  fi # sysctl check

  if [[ ! -f /etc/security/limits.d/limits.conf ]]; then
    CONFIRMATION=$(_GetConfirmation "Increase limits for file handles and memlock [Y/n]?" Y)
    if [[ $CONFIRMATION =~ ^[Yy] ]]; then
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
    fi # limits.conf confirmation
  fi # limits.conf check

  if [[ -f /etc/default/grub ]] && ! grep -q cgroup /etc/default/grub; then
    CONFIRMATION=$(_GetConfirmation "Tweak kernel parameters in grub (cgroup, etc.) [Y/n]?" Y)
    if [[ $CONFIRMATION =~ ^[Yy] ]]; then
      $SUDO_CMD sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="[^"]*/& systemd.unified_cgroup_hierarchy=1 cgroup_enable=memory swapaccount=1 cgroup.memory=nokmem random.trust_cpu=on preempt=voluntary/' /etc/default/grub
      $SUDO_CMD grub2-mkconfig -o /boot/grub2/grub.cfg
    fi # grub confirmation
  fi # grub check
}

################################################################################
# SGroverDotfiles - download the author's dotfiles for convenience
function SGroverDotfiles {
  CONFIRMATION=$(_GetConfirmation "Clone and setup symlinks for Seth Grover's dotfiles [y/N]?" N)
  if [[ $CONFIRMATION =~ ^[Yy] ]]; then

    mkdir -p "$LOCAL_BIN_PATH" "$LOCAL_CONFIG_PATH"

    SGROVER_GITHUB_PATH="$LOCAL_CONFIG_PATH"/sgrover.dotfiles
    _GitClone https://github.com/mmguero/dotfiles "$SGROVER_GITHUB_PATH"

    [[ -r "$SGROVER_GITHUB_PATH"/bash/"$SCRIPT_NAME" ]] && rm -vf "$LOCAL_BIN_PATH"/"$SCRIPT_NAME" && \
      ln -vrs "$SGROVER_GITHUB_PATH"/bash/"$SCRIPT_NAME" "$LOCAL_BIN_PATH"/"$SCRIPT_NAME"

    [[ -r "$SGROVER_GITHUB_PATH"/bash/rc ]] && rm -vf ~/.bashrc && \
      ln -vrs "$SGROVER_GITHUB_PATH"/bash/rc ~/.bashrc

    [[ -r "$SGROVER_GITHUB_PATH"/bash/aliases ]] && rm -vf ~/.bash_aliases && \
      ln -vrs "$SGROVER_GITHUB_PATH"/bash/aliases ~/.bash_aliases

    [[ -r "$SGROVER_GITHUB_PATH"/bash/functions ]] && rm -vf ~/.bash_functions && \
      ln -vrs "$SGROVER_GITHUB_PATH"/bash/functions ~/.bash_functions

    [[ -d "$SGROVER_GITHUB_PATH"/bash/rc.d ]] && rm -vf ~/.bashrc.d && \
      ln -vrs "$SGROVER_GITHUB_PATH"/bash/rc.d ~/.bashrc.d

    [[ -r "$SGROVER_GITHUB_PATH"/git/gitconfig ]] && rm -vf ~/.gitconfig && \
      ln -vrs "$SGROVER_GITHUB_PATH"/git/gitconfig ~/.gitconfig

    [[ -r "$SGROVER_GITHUB_PATH"/git/gitignore_global ]] && rm -vf ~/.gitignore_global && \
      ln -vrs "$SGROVER_GITHUB_PATH"/git/gitignore_global ~/.gitignore_global

    [[ -r "$SGROVER_GITHUB_PATH"/linux/tmux/tmux.conf ]] && rm -vf ~/.tmux.conf && \
      ln -vrs "$SGROVER_GITHUB_PATH"/linux/tmux/tmux.conf ~/.tmux.conf

    LINKED_SCRIPTS=(
      self_signed_key_gen.sh
    )
    for i in ${LINKED_SCRIPTS[@]}; do
      rm -vf "$LOCAL_BIN_PATH"/"$i" && ln -vrs "$SGROVER_GITHUB_PATH"/scripts/"$i" "$LOCAL_BIN_PATH"/
    done

    [[ -r "$SGROVER_GITHUB_PATH"/bash/context-color/context-color ]] && rm -vf "$LOCAL_BIN_PATH"/context-color && \
      ln -vrs "$SGROVER_GITHUB_PATH"/bash/context-color/context-color "$LOCAL_BIN_PATH"/context-color

  fi # dotfiles setup confirmation
}

################################################################################
# InstallMalcolm - clone and configure Malcolm and grab some sample PCAP
function InstallMalcolm {

  MALCOLM_PATH="$HOME"/Malcolm
  ARTIFACTS_PATH="$HOME"/artifacts

  CONFIRMATION=$(_GetConfirmation "Clone and setup Malcolm [Y/n]?" Y)
  if [[ $CONFIRMATION =~ ^[Yy] ]]; then
    if _GitClone https://github.com/cisagov/Malcolm "$MALCOLM_PATH"; then
      pushd "$MALCOLM_PATH" >/dev/null 2>&1
      python3 ./scripts/configure \
          --defaults \
          --runtime docker \
          --malcolm-profile \
          --restart-malcolm \
          --auto-arkime \
          --auto-suricata \
          --auto-zeek \
          --zeek-ics \
          --zeek-ics-best-guess \
          --auto-oui \
          --auto-freq \
          --file-extraction notcommtxt \
          --file-preservation quarantined \
          --extracted-file-server \
          --extracted-file-server-password infected \
          --extracted-file-server-zip \
          --extracted-file-capa \
          --extracted-file-clamav \
          --extracted-file-yara \
          --netbox local \
          --netbox-enrich \
          --netbox-autopopulate \
          --netbox-auto-prefixes \
          --netbox-site-name "$(hostname -s)"

      grep image: docker-compose.yml | awk '{print $2}' | sort -u | xargs -l -r $SUDO_CMD docker pull
      echo "Please run $MALCOLM_PATH/scripts/auth_setup to complete configuration" >&2
      popd >/dev/null 2>&1
    fi

    pushd "$LOCAL_BIN_PATH" >/dev/null 2>&1
    ln -f -s -r "$MALCOLM_PATH"/scripts/reset_and_auto_populate.sh ./reset_and_auto_populate.sh
    curl -sSL -J -O https://raw.githubusercontent.com/idaholab/Malcolm-Test-Artifacts/refs/heads/main/tools/pcap_time_shift.py
    chmod 755 pcap_time_shift.py
    popd >/dev/null 2>&1

    CONFIRMATION=$(_GetConfirmation "Set up crontab for starting/resetting Malcolm? [y/N]?" N)
    if [[ $CONFIRMATION =~ ^[Yy] ]]; then
      ((echo 'SHELL=/bin/bash') ; \
       (( crontab -l | grep . | grep -v ^SHELL= ; \
          echo "@reboot sleep 60 && /bin/bash --login $LOCAL_BIN_PATH/reset_and_auto_populate.sh -r -o -n -m $MALCOLM_PATH/docker-compose.yml" ; \
          echo "15 8 * * * /bin/bash --login $LOCAL_BIN_PATH/reset_and_auto_populate.sh -w -o -n -m $MALCOLM_PATH/docker-compose.yml -d yesterday $ARTIFACTS_PATH/*.pcap" ) \
          | sort | uniq )) | crontab -
    fi
  fi

  CONFIRMATION=$(_GetConfirmation "Download a sample PCAP (SANS Cyberville ICS CTF) [Y/n]?" Y)
  if [[ $CONFIRMATION =~ ^[Yy] ]]; then
    mkdir -p "$ARTIFACTS_PATH"
    pushd "$ARTIFACTS_PATH" >/dev/null 2>&1
    curl -sSL -J -O https://malcolm.fyi/examples/Cyberville.pcap
    popd >/dev/null 2>&1
  fi
}

################################################################################
# SetupConnectivity - configure dynamic DNS and/or reverse tunnel for easier connectivity
function SetupConnectivity {

  # dynamic DNS
  if ! ( crontab -l | grep -q curl ); then
    CONFIRMATION=$(_GetConfirmation "Specify @reboot crontab command for DDNS [y/N]?" N)
    if [[ $CONFIRMATION =~ ^[Yy] ]]; then
      COMMAND=$(_GetString "Command:" "")
      if [[ -n "$COMMAND" ]]; then
        ((echo 'SHELL=/bin/bash') ; \
         (( crontab -l | grep . | grep -v ^SHELL= ; \
            echo "@reboot ${COMMAND}" ) \
            | sort | uniq )) | crontab -
      fi
    fi
  fi

  # boringproxy
  if ! ( crontab -l | grep -q boringproxy ); then
    CONFIRMATION=$(_GetConfirmation "Configure boringproxy [y/N]?" N)
    if [[ $CONFIRMATION =~ ^[Yy] ]]; then
      [[ ! -f "${LOCAL_BIN_PATH}"/boringproxy ]] && _InstallBoringProxy
      SERVER=$(_GetString "boringproxy server:" "")
      CLIENT=$(_GetString "boringproxy client name:" "")
      USER=$(_GetString "boringproxy user:" "")
      TOKEN=$(_GetString "boringproxy token (will be stored in plaintext in crontab):" "")
      if [[ -n "$SERVER" ]] && [[ -n "$CLIENT" ]] && [[ -n "$USER" ]] && [[ -n "$TOKEN" ]]; then
        mkdir -p "${LOCAL_CONFIG_PATH}"/boringproxy/certs
        ((echo 'SHELL=/bin/bash') ; \
         (( crontab -l | grep . | grep -v ^SHELL= ; \
            echo "@reboot sleep 120 && ( nohup ${LOCAL_BIN_PATH}/boringproxy client -client-name ${CLIENT} -acme-email example@example.com -cert-dir ${LOCAL_CONFIG_PATH}/boringproxy/certs -user ${USER} -token ${TOKEN} -server ${SERVER} >/dev/null 2>&1 </dev/null & )" ) \
            | sort | uniq )) | crontab -
      fi
    fi
  fi


}

################################################################################
# "main" - ask the user what they want to do, and do it (or do it without interaction)

# in case we've already got some envs set up to use
_EnvSetup

# get a list of all the "public" functions (not starting with _)
FUNCTIONS=($(declare -F | awk '{print $NF}' | sort | egrep -v "^_"))

# present the menu to our customer and get their selection
printf "%s\t%s\n" "0" "ALL"
for i in "${!FUNCTIONS[@]}"; do
  ((IPLUS=i+1))
  printf "%s\t%s\n" "$IPLUS" "${FUNCTIONS[$i]}"
done

if (( $MALCOLM_SETUP_NONINTERACTIVE == 1 )); then
  echo "Operation: ALL (non-interactive)"
  USER_FUNCTION_IDX=0
else
  echo -n "Operation:"
  read USER_FUNCTION_IDX
fi

if (( $USER_FUNCTION_IDX == 0 )); then
  # ALL: do everything, in order
  InstallEnvs
  InstallEssentialPackages
  InstallCommonPackages
  InstallDocker
  SystemConfig
  InstallUserLocalBinaries
  InstallEnvPackages
  CreateCommonLinuxConfig
  SGroverDotfiles
  InstallMalcolm
  SetupConnectivity

elif (( $USER_FUNCTION_IDX > 0 )) && (( $USER_FUNCTION_IDX <= "${#FUNCTIONS[@]}" )); then
  # execute one function, à la carte
  USER_FUNCTION="${FUNCTIONS[((USER_FUNCTION_IDX-1))]}"
  echo $USER_FUNCTION
  $USER_FUNCTION

else
  # some people just want to watch the world burn
  echo "Invalid operation selected" >&2
  exit 1;
fi
