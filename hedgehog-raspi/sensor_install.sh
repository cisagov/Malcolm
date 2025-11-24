#!/bin/bash -e
# This script is copied into a chroot'd environment
# Paths will be absolute and will reflect the path on the RPI Sensor

PATH='/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin'
umask 0022

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit $BUILD_ERROR_CODE
fi

IMAGE_NAME=hedgehog
IMAGE_PUBLISHER=idaholab
IMAGE_VERSION=1.0.0
IMAGE_DISTRIBUTION=trixie

SENSOR_USER=sensor
SENSOR_GROUP=sensor
SENSOR_HOME=/home/$SENSOR_USER

# Determine number of proc cores available
# Use caution messing with this value; build process may trigger OOM and fail!!
PROC_CNT=$(nproc)
ARCH="$(dpkg --print-architecture)"
export DEBIAN_FRONTEND=noninteractive

# Used to build RPI without graphical features
# Changing to 1 is mostly unimplemented
BUILD_GUI=0

RUN_PATH="(pwd)"
DEBS_DIR="${HOME}/debs"
DEPS_DIR='/opt/deps'
SHARED_DIR='/opt/buildshared'
WORK_DIR="$(mktemp -d -p "$HOME" -t hedgehog-XXXXXX)"

# Build time dependencies for arkime, htpdate, capa, and yara
BUILD_DEPS='automake checkinstall libjansson-dev libmagic-dev libnl-genl-3-dev libtool '
BUILD_DEPS+='meson ninja-build python3-dev re2c ruby ruby-dev ruby-rubygems '

# Build dependencies we're leaving in place after installation (for building new Zeek plugins in the wild, mostly)
BUILD_DEPS_KEEP='build-essential ccache cmake flex gcc g++ git libfl-dev libgoogle-perftools-dev '
BUILD_DEPS_KEEP+='libgoogle-perftools4 libkrb5-3 libkrb5-dev libmaxminddb-dev libpcap-dev libssl-dev libtcmalloc-minimal4 '
BUILD_DEPS_KEEP+='make patch pkg-config python3-git python3-pip python3-semantic-version python3-setuptools swig wget zlib1g-dev '

BUILD_ERROR_CODE=1

################################
######### Functions ############
################################

build_htpdate() {

    # Htpdate in Debian repos doesn't compile https functionality

    htpdate_url='https://github.com/twekkel/htpdate'
    htpdate_vers="$(curl -sqI $htpdate_url/releases/latest | awk -F '/' '/^location/ {print substr($NF,2,length($NF)-2)}')"
    htpdate_release=1

    apt-get update
    apt-get install $BUILD_DEPS $BUILD_DEPS_KEEP -y --no-install-suggests

    mkdir -p "${WORK_DIR}"/htpdate && cd "$_"
    curl -sSL "$htpdate_url/tarball/v$htpdate_vers" | tar xzf - --strip-components=1

    sed -i '/.*man8.*/d' Makefile
    rm -f scripts/*

    make https

    checkinstall -y -D --nodoc --strip=yes --stripso=yes --install=no --fstrans=no \
    --pkgname=htpdate --pkgversion=$htpdate_vers --pkgarch="$ARCH" --pkgsource="$htpdate_url" \
    --pkgrelease="$htpdate_release" --pakdir "$DEBS_DIR"

    # htpdate is installed outside of dpkg with checkinstall
    make uninstall

    cd "${WORK_DIR}"

    dpkg -i "${DEBS_DIR}/htpdate_${htpdate_vers}-${htpdate_release}_${ARCH}.deb"
}

clean_up() {

    # Remove ethernet interface files left by installation
    # TODO: how will the user configure interfaces now on hedgehog-raspi?
    rm -f /etc/network/interfaces.d/eth0

    # Remove this script and any debugging files
    # Comment this out in order to troubleshoot the build process in a chroot
    # Build process writes to /root/sensor_install_debug by default
    rm -f /root/sensor_install*

    # Remove extra installation files
    rm -rf $WORK_DIR \
           $SHARED_DIR \
		   /opt/deps \
		   /opt/hooks \
		   /opt/patches \
           /root/.bash_history \
           /root/.wget-hsts \
           /root/.cache \
           /root/.local/share/gem \
           /root/.npm \
           "${DEBS_DIR}" \
		   /tmp/*
    find /var/log/ -type f -print0 2>/dev/null | \
        xargs -0 -r -I XXX bash -c "file 'XXX' | grep -q text && > 'XXX'"

    # Remove unnecessary build components
    apt-get remove $BUILD_DEPS -y
    apt-get autoremove -y
    apt-get clean

    # Ensure locale and console are setup correctly
    locale-gen en_US.UTF-8 en.UTF-8
    update-locale LANG=en_US.UTF-8 LANGUAGE=en.UTF-8
    sed -i -e 's/CHARMAP=.*/CHARMAP="UTF-8"/' -e 's/CODESET=.*/CODESET="Lat15"/' /etc/default/console-setup
    dpkg-reconfigure console-setup

    umount -A -f /dev/pts /run /dev /proc /sys
}

clean_up_gui_files() {
    rm -rf /etc/skel/.config/autostart \
           /etc/skel/.config/xfce4 \
           /etc/skel/.local/share/xfce4 \
           /etc/skel/.config/gtk-3.0 \
           /etc/skel/.config/*dconf*
}

create_user() {

    # Set defaults but it is STRONGLY recommended that these be changed before deploying Sensor
    local pass='Hedgehog_Linux'
    local root_pass='Hedgehog_Linux_Root'

    groupadd "$SENSOR_GROUP"
    useradd -m -g "$SENSOR_GROUP" -u 1000 -s /bin/bash -d "$SENSOR_HOME" "$SENSOR_USER"
    usermod -a -G netdev "$SENSOR_USER"

    echo -n "${SENSOR_USER}:${pass}" | chpasswd --crypt-method YESCRYPT
    echo -n "root:${root_pass}" | chpasswd --crypt-method YESCRYPT
}

install_deps() {

    local deps=''

    if [ $BUILD_GUI -eq 0 ]; then
        rm -f "${DEPS_DIR}/"{desktopmanager,live,virtualguest}.list.chroot
        rm -f "${DEPS_DIR}/grub.list.binary"
    fi

    for file in "${DEPS_DIR}/"*.chroot; do
        sed -i '$a\' "$file"
        deps+=$(tr '\n' ' ' < "$file")
    done

    # Remove packages not relevant to RPI
    # Rar is excluded because Debian doesn't have an ARM package
    # htpdate removed because repo version doesn't support https
    # aide is removed as we're not applying the same hardening requirements ot the rpi image
    declare -a graphical_deps=( aide aide-common efibootmgr fonts-dejavu fuseext2 fusefat fuseiso gdb )
    graphical_deps+=( gparted gdebi  google-perftools gvfs gvfs-daemons gvfs-fuse ghostscript ghostscript-x )
    graphical_deps+=( hfsplus hfsprogs htpdate libgtk2.0-bin menu pmount rar )
    graphical_deps+=( ssh-askpass udisks2 upower user-setup xbitmaps zenity zenity-common )
    graphical_deps+=( libsmbclient samba-common samba-common-bin samba-dsdb-modules samba-libs smbclient )

    deps=$(echo ${deps} ${graphical_deps[@]} | tr ' ' '\n' | sort | uniq -u | tr '\n' ' ')

    apt-get update
    # Hedgehog conf files are copied into env before this runs; keep those config files by default
    apt-get -o Dpkg::Options::="--force-confold" install -q $deps -y --no-install-suggests
    apt-get clean
}

install_files() {

    MALCOLM_SRC=/opt/Malcolm

    cp -r "$MALCOLM_SRC/malcolm-iso/config/requirements.txt" "/opt/requirements.txt"
    cp -r "$MALCOLM_SRC/shared/bin/"* "/usr/local/bin"
    cp "$MALCOLM_SRC/scripts/malcolm_utils.py" "/usr/local/bin/"
    cp "$MALCOLM_SRC/scripts/malcolm_constants.py" "/usr/local/bin/"
    cp "$MALCOLM_SRC/malcolm-iso/config/archives/fluentbit.list.chroot" "/etc/apt/sources.list.d/fluentbit.list"
    cp "$MALCOLM_SRC/malcolm-iso/config/archives/fluentbit.key.chroot" "/etc/apt/keyrings/"
    cp "$MALCOLM_SRC/malcolm-iso/config/archives/docker.list.chroot" "/etc/apt/sources.list.d/docker.list"
    cp "$MALCOLM_SRC/malcolm-iso/config/archives/docker.key.chroot" "/etc/apt/keyrings/"
    cp -r "$MALCOLM_SRC/malcolm-iso/config/includes.chroot/"* "/"
    rm -r "/etc/live"
    cp -r "$MALCOLM_SRC/malcolm-iso/config/hooks/normal/"* "/opt/hooks/"
    cp -r "$MALCOLM_SRC/malcolm-iso/config/package-lists/"* "/opt/deps/"

    pushd "$SENSOR_HOME" >/dev/null 2>&1
    mkdir -p Malcolm .malcolm-install
    pushd .malcolm-install >/dev/null 2>&1
    echo 'N' | bash "$MALCOLM_SRC/scripts/malcolm_appliance_packager.sh" >/dev/null 2>&1
    ls malcolm_*.tar.gz
    tar xzf malcolm_*.tar.gz -C "$SENSOR_HOME"/Malcolm --strip-components 2
    popd >/dev/null 2>&1
    rm -rf .malcolm-install
    popd >/dev/null 2>&1
    rm -rf "$MALCOLM_SRC"

    # Setup OS information
    sensor_ver_file="$SENSOR_HOME/Malcolm/.os-info"

    if [[ -f "$SHARED_DIR/version.txt" ]]; then
      SHARED_IMAGE_VERSION="$(cat "$SHARED_DIR/version.txt" | head -n 1)"
      [[ -n $SHARED_IMAGE_VERSION ]] && IMAGE_VERSION="$SHARED_IMAGE_VERSION"
    fi

    echo "BUILD_ID=\"$(date +\'%Y-%m-%d\')-${IMAGE_VERSION}\""   > "$sensor_ver_file"
    echo "VARIANT=\"Hedgehog Linux (Minihog Sensor) v${IMAGE_VERSION}\"" >> "$sensor_ver_file"
    echo "VARIANT_ID=\"hedgehog-minihog-sensor\"" >> "$sensor_ver_file"
    echo "ID_LIKE=\"debian\"" >> "$sensor_ver_file"
    echo "HOME_URL=\"https://${IMAGE_PUBLISHER}.github.io/Malcolm\"" >> "$sensor_ver_file"
    echo "DOCUMENTATION_URL=\"https://${IMAGE_PUBLISHER}.github.io/Malcolm/docs/hedgehog.html\"" >> "$sensor_ver_file"
    echo "SUPPORT_URL=\"https://github.com/${IMAGE_PUBLISHER}\"" >> "$sensor_ver_file"
    echo "BUG_REPORT_URL=\"https://github.com/cisagov/malcolm/issues\"" >> "$sensor_ver_file"

    chown -R "$SENSOR_USER:$SENSOR_GROUP" "$SENSOR_HOME/Malcolm"

    # Prepare Fluentbit and Beats repo GPG keys
    local apt_lists='/etc/apt/sources.list.d'
    local apt_keys='/etc/apt/keyrings'
    local fluentbit_key="${apt_keys}/fluentbit.gpg"
    local docker_key="${apt_keys}/docker.gpg"

    gpg --dearmor --batch --yes -o "$fluentbit_key" "${apt_keys}/fluentbit.key.chroot"
    gpg --dearmor --batch --yes -o "$docker_key" "${apt_keys}/docker.key.chroot"

    rm "${apt_keys}/fluentbit.key.chroot"
    rm "${apt_keys}/docker.key.chroot"

    sed -i -e "s|deb |deb [signed-by=${fluentbit_key}] |" "${apt_lists}/fluentbit.list"
    sed -i -e "s|deb |deb [signed-by=${docker_key}] |" "${apt_lists}/docker.list"

    # Prepare debs directory for other packages
    mkdir -p "${DEBS_DIR}"

    # Disable ipv6
    echo 'ipv6.disable=1' > /etc/default/raspi-extra-cmdline

    # Add RPI hostname to /etc/hosts
    echo "127.0.1.1 $(head -n 1 /etc/hostname)" >> /etc/hosts

    # mark as first run
}

install_hooks() {

    set -e

    local hooks_dir='/opt/hooks'

    if [[ $BUILD_GUI -eq 0 ]]; then
        rm -f "${hooks_dir}"/*login.hook.chroot
        rm -f "${hooks_dir}"/*stig-scripts.hook.chroot
    fi

    # create hooks for installing Python packages
    HOOK_COUNTER=168
    if [ -f "/opt/requirements.txt" ]; then
      echo "#!/bin/sh" >> ${hooks_dir}/0${HOOK_COUNTER}-pip-sensor-$SUBDIR-installs.hook.chroot
      echo "export LC_ALL=C.UTF-8" >> ${hooks_dir}/0${HOOK_COUNTER}-pip-sensor-$SUBDIR-installs.hook.chroot
      echo "export LANG=C.UTF-8" >> ${hooks_dir}/0${HOOK_COUNTER}-pip-sensor-$SUBDIR-installs.hook.chroot
      echo "PYTHONDONTWRITEBYTECODE=1" >> ${hooks_dir}/0${HOOK_COUNTER}-pip-sensor-$SUBDIR-installs.hook.chroot
      echo "PYTHONUNBUFFERED=1" >> ${hooks_dir}/0${HOOK_COUNTER}-pip-sensor-$SUBDIR-installs.hook.chroot
      echo -n "python3 -m pip install --ignore-installed --break-system-packages --no-compile --no-cache-dir --force-reinstall --upgrade" >> ${hooks_dir}/0${HOOK_COUNTER}-pip-sensor-$SUBDIR-installs.hook.chroot
      while read LINE; do
        echo -n -e " \\\\\n  $LINE" >> ${hooks_dir}/0${HOOK_COUNTER}-pip-sensor-$SUBDIR-installs.hook.chroot
      done <"/opt/requirements.txt"
      echo "" >> ${hooks_dir}/0${HOOK_COUNTER}-pip-sensor-$SUBDIR-installs.hook.chroot
      chmod +x ${hooks_dir}/0${HOOK_COUNTER}-pip-sensor-$SUBDIR-installs.hook.chroot
    fi

    for file in ${hooks_dir}/*.hook.chroot; do
        /bin/bash "$file"
    done

}

################################
########## Main ################
################################

# Make sure necessary virtual filesystems available in chroot
mount -t proc /proc /proc
mount -t devtmpfs /dev /dev
mount -t devpts /dev/pts /dev/pts
mount -t sysfs /sys /sys
mount -t tmpfs /run /run


[[ -f "$SHARED_DIR/environment.chroot" ]] && \
  . "$SHARED_DIR/environment.chroot"

build_htpdate
create_user
install_files
install_deps

# Remove GUI related files if not building RPI with a DE
# See comment above about BUILD_GUI usage
if [[ $BUILD_GUI -eq 0 ]]; then
    clean_up_gui_files
fi

install_hooks
clean_up

exit 0
