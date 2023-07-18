#!/usr/bin/env bash

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

# Configure Amazon Linux 2 and install Malcolm

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

if ! command -v amazon-linux-extras >/dev/null 2>&1; then
    echo "This script only targets Amazon Linux 2" >&2
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
MALCOLM_TAG=${MALCOLM_TAG:-v23.05.1}
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
MALCOLM_USER="$(id -nu $MALCOLM_UID)"
MALCOLM_USER_GROUP="$(id -gn $MALCOLM_UID)"
MALCOLM_USER_HOME="$(getent passwd "$MALCOLM_USER" | cut -d: -f6)"
MALCOLM_URL="https://codeload.github.com/$MALCOLM_REPO/tar.gz/$MALCOLM_TAG"

###################################################################################
# InstallEssentialPackages
function InstallEssentialPackages {
    echo "Installing essential packages..." >&2

    # install the package(s) from yum
    $SUDO_CMD yum install -y \
        curl \
        dialog \
        httpd-tools \
        make \
        openssl \
        tmux \
        xz

}

################################################################################
# InstallPythonPackages - install specific python packages
function InstallPythonPackages {
    echo "Installing Python 3.8 and pip packages..." >&2

    [[ $EUID -eq 0 ]] && USERFLAG="" || USERFLAG="--user"

    # install the package(s) from amazon-linux-extras
    $SUDO_CMD amazon-linux-extras install -y \
        python3.8

    $SUDO_CMD ln -s -r -f /usr/bin/python3.8 /usr/bin/python3
    $SUDO_CMD ln -s -r -f /usr/bin/pip3.8 /usr/bin/pip3

    $SUDO_CMD /usr/bin/python3.8 -m pip install $USERFLAG -U \
        python-dotenv \
        pythondialog \
        pyyaml \
        requests \
        urllib3==1.26.16
}

################################################################################
# InstallDocker - install Docker and enable it as a service, and install docker-compose
function InstallDocker {
    echo "Installing Docker and docker-compose..." >&2

    # install docker, if needed
    if ! command -v docker >/dev/null 2>&1 ; then

        $SUDO_CMD amazon-linux-extras install -y docker

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

    if [[ -r /etc/sysctl.conf ]] && ! grep -q swappiness /etc/sysctl.conf; then

        $SUDO_CMD tee -a /etc/sysctl.conf > /dev/null <<'EOT'

# allow dmg reading
kernel.dmesg_restrict=0

# the maximum number of open file handles
fs.file-max=65536

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
        $SUDO_CMD sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="[^"]*/& random.trust_cpu=on cgroup_enable=memory swapaccount=1 cgroup.memory=nokmem/' /etc/default/grub
        $SUDO_CMD grub2-mkconfig -o /boot/grub2/grub.cfg
    fi # grub check
}

################################################################################
# InstallMalcolm - clone and configure Malcolm and grab some sample PCAP
function InstallMalcolm {
    echo "Downloading and unpacking Malcolm..." >&2

    pushd "$MALCOLM_USER_HOME" >/dev/null 2>&1
    mkdir -p ./Malcolm
    curl -fsSL "$MALCOLM_URL" | tar xzf - -C ./Malcolm --strip-components 1
    if [[ -s ./Malcolm/docker-compose-standalone.yml ]]; then
        pushd ./Malcolm >/dev/null 2>&1
        mv docker-compose-standalone.yml docker-compose.yml
        for ENVEXAMPLE in ./config/*.example; do ENVFILE="${ENVEXAMPLE%.*}"; cp "$ENVEXAMPLE" "$ENVFILE"; done
        echo "Pulling Docker images..." >&2
        docker-compose pull >/dev/null 2>&1
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
    ./scripts/configure
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

A minute or so after starting Malcolm, the following services will be accessible:
  - Arkime: https://<IP or hostname>/
  - OpenSearch Dashboards: https://<IP or hostname>/dashboards/
  - PCAP upload (web): https://<IP or hostname>/upload/
  - NetBox: https://<IP or hostname>/netbox/
  - Account management: https://<IP or hostname>/auth/
  - Documentation: https://<IP or hostname>/readme/

EOT
fi
EOF

    chown -R $MALCOLM_USER:$MALCOLM_USER_GROUP "$MALCOLM_USER_HOME"
}

################################################################################
# "main"

SystemConfig
InstallEssentialPackages
InstallPythonPackages
InstallDocker
InstallMalcolm
