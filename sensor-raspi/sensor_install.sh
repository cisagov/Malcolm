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
IMAGE_DISTRIBUTION=bookworm

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
WORK_DIR="$(mktemp -d -t hedgehog-XXXXXX)"
SENSOR_DIR='/opt/sensor'

BEATS_VER="8.12.0"
BEATS_OSS="-oss"

# Option to build from sources if desired
# Building from source will increase build time A LOT (especially Zeek)!
BUILD_ARKIME_FROM_SOURCE=1
BUILD_YARA_FROM_SOURCE=1
BUILD_ZEEK_FROM_SOURCE=0

# Build time dependencies for arkime, htpdate, capa, and yara
BUILD_DEPS='build-essential meson ninja-build patch python3-dev python3-pip python3-setuptools '
BUILD_DEPS+='ruby ruby-dev ruby-rubygems wget automake checkinstall flex gcc libjansson-dev '
BUILD_DEPS+='libmagic-dev libssl-dev libtool make pkg-config libnl-genl-3-dev python3-venv '

# Build time dependencies for zeek when built from source
if [ $BUILD_ZEEK_FROM_SOURCE -ne 0 ]; then
	BUILD_DEPS+='ccache clang cmake git libc++-dev libc++abi-dev libfl-dev libgoogle-perftools-dev '
	BUILD_DEPS+='libgoogle-perftools4 libkrb5-3 libkrb5-dev libmaxminddb-dev libpcap-dev '
	BUILD_DEPS+='libtcmalloc-minimal4 python3-git python3-semantic-version swig zlib1g-dev '
fi

BUILD_ERROR_CODE=1

################################
######### Functions ############
################################

build_arkime_src(){

	arkime_repo='https://github.com/arkime/arkime.git'
	arkime_ver='4.6.0'
	arkime_dir='/opt/arkime'
	build_jobs=$((PROC_CNT/2))

	apt install $BUILD_DEPS -y --no-install-suggests

	gem install --no-document fpm

	mkdir -p "${WORK_DIR}/arkime" && cd "$_"
	git clone --recurse-submodules --branch="v${arkime_ver}" "$arkime_repo" ./

	for patch_file in /opt/patches/*; do
		patch -p 1 -r - --no-backup-if-mismatch < $patch_file || true
	done

	export PATH="${arkime_dir}/bin:${WORK_DIR}/arkime/node_modules/.bin:${PATH}"

	sed -i "s/MAKE=make/MAKE='make -j${build_jobs}'/" easybutton-build.sh
	./easybutton-build.sh --dir "$arkime_dir"

	npm -g config set user root

	make install -j${build_jobs}

	cp -r ./capture/plugins/lua/samples "${arkime_dir}"/lua

	npm install license-checker
	release/notice.txt.pl "${arkime_dir}/" NOTICE release/CAPTURENOTICE > "${arkime_dir}/NOTICE.txt"

	rm -f $arkime_dir/etc/*.systemd.service

	fpm -s dir -t deb -n arkime -x opt/arkime/logs -x opt/arkime/raw \
	  -v "$arkime_ver" --iteration 1 --template-scripts --after-install "release/afterinstall.sh" \
	  --url "https://arkime.com" --description "Arkime Full Packet System" \
	  -d libwww-perl -d libjson-perl -d ethtool -d libyaml-dev \
	  -p "${DEBS_DIR}/arkime_${arkime_ver}_${ARCH}.deb" "$arkime_dir"

	cd "${WORK_DIR}"
	rm -rf "${WORK_DIR}/arkime" "$arkime_dir"

	dpkg -i "${DEBS_DIR}/arkime_${arkime_ver}_${ARCH}.deb"
}

build_htpdate() {

	# Htpdate in Debian repos doesn't compile https functionality

	htpdate_url='https://github.com/twekkel/htpdate'
	htpdate_vers="$(curl -sqI $htpdate_url/releases/latest | awk -F '/' '/^location/ {print substr($NF,2,length($NF)-2)}')"
	htpdate_release=1

	apt install $BUILD_DEPS -y --no-install-suggests

	mkdir -p "${WORK_DIR}"/htpdate && cd "$_"
	curl -sSL "$htpdate_url/tarball/v$htpdate_vers" | tar xzf - --strip-components=1

	sed -i '/.*man8.*/d' Makefile

	make https

	checkinstall -y -D --nodoc --strip=yes --stripso=yes --install=no --fstrans=no \
	 --pkgname=htpdate --pkgversion=$htpdate_vers --pkgarch="$ARCH" --pkgsource="$htpdate_url" \
	 --pkgrelease="$htpdate_release" --pakdir "$DEBS_DIR"

	# htpdate is installed outside of dpkg with checkinstall
	make uninstall

	cd "${WORK_DIR}"

	dpkg -i "${DEBS_DIR}/htpdate_${htpdate_vers}-${htpdate_release}_${ARCH}.deb"
}

build_interface() {

	interface_dir="${SENSOR_DIR}"
	cd "$interface_dir"

	if [[ $BUILD_GUI -eq 1 ]]; then
		# Items below required for GUI interface. Requires graphical DE to be useful
		sed -i "s@/home/sensor/sensor_interface@${SENSOR_DIR}@g" "${interface_dir}/kiosk.service"
		python3 -m pip install --break-system-packages --no-compile --no-cache-dir --force-reinstall \
		 --upgrade -r requirements.txt
		rm -rf "${interface_dir}/.git" "${interface_dir}/requirements.txt"
	else
		cd "${interface_dir}"
		rm -rf .git requirements.txt init.sh kiosk.service sensor_interface/
		cd "$OLDPWD"
	fi

	sed -i 's/CAPTURE_INTERFACE=.*/CAPTURE_INTERFACE=xxxx/g' "${interface_dir}/sensor_ctl/control_vars.conf"

}

build_yara_src() {

	# Build Yara from source code

	apt install $BUILD_DEPS -y --no-install-suggests

	yara_url="https://github.com/VirusTotal/YARA"
	yara_ver="$(curl -sqI ${yara_url}/releases/latest | awk -F '/' '/^location/ {print substr($NF,2,length($NF)-2)}')"
	yara_release=1

	mkdir -p "${WORK_DIR}/yara" && cd "$_"
	curl -sSL "${yara_url}/tarball/v${yara_ver}" | tar xzf - --strip-components=1
	./bootstrap.sh
	./configure --prefix=/usr --with-crypto --enable-magic --enable-cuckoo
	make -j $PROC_CNT

	checkinstall -y -D --strip=yes --stripso=yes --nodoc --install=no --fstrans=no --pkgname="yara" \
	 --pkgversion="$yara_ver" --pkgrelease="$yara_release" --pkgarch="$ARCH" --pkgsource="$yara_url" --pakdir="$DEBS_DIR"

	# Files are installed by checkinstall outside of DPKG
	# Remove them since a deb has been created for later installation
	make uninstall

	cd "${WORK_DIR}"
	rm -rf "${WORK_DIR}/yara"

	dpkg -i "${DEBS_DIR}/yara_${yara_ver}-${yara_release}_${ARCH}.deb"
}

build_zeek() {

	# Build zeek from lts debs from OpenSUSE

	zeek_repo='https://download.opensuse.org/repositories/security:/zeek/Debian_12/'
	zeek_gpg_key=/etc/apt/keyrings/zeek-lts.gpg
	zeek_apt_file=/etc/apt/sources.list.d/zeek.list
	zeek_ver='lts'
	zeek_dir=/opt/zeek

	curl -L "${zeek_repo}/Release.key" | gpg --dearmor --batch --yes -o "$zeek_gpg_key"

	echo "#This is an unofficial build of Zeek LTS" > "$zeek_apt_file"
	echo "deb [signed-by=${zeek_gpg_key}] $zeek_repo ./" >> "$zeek_apt_file"

	apt update
	apt install zeek-${zeek_ver} -y --no-install-suggests

}

build_zeek_src() {

	# Build Zeek from source code
	# Leaving this code here for future use if needed

	export CCACHE_DIR=/var/spool/ccache
	export CCACHE_COMPRESS=1
	export PYTHONDONTWRITEBYTECODE=1
	export PYTHONUNBUFFERED=1

	zeek_url=https://github.com/zeek/zeek.git
	zeek_version=6.1.0
	zeek_release=1
	zeek_dir=/opt/zeek
	# Zeek's build eats a ton of resources; prevent OOM from the killing build process
	build_jobs=$((PROC_CNT/2))
	# Testing was done on a 8 cpu host with 16GB of ram.
	# Successful Zeek from source build alone took: 6.5 hours
	output_dir=/tmp
	unset VERBOSE

	mkdir -p "${WORK_DIR}/zeek" && cd "$_"
	curl -sSL "https://download.zeek.org/zeek-${zeek_version}.tar.gz" | tar xzf - --strip-components=1

	mkdir -p "${CCACHE_DIR}"
	./configure --prefix="${zeek_dir}" --disable-broker-tests --disable-cpp-tests \
	  --disable-btest-pcaps --disable-btest  --generator=Ninja --ccache --enable-perftools

	mkdir -p build && cd "$_"
	ninja -j "$build_jobs"

	checkinstall -y -D --strip=yes --stripso=yes --nodoc --install=no --fstrans=no \
	  --pkgname="zeek" --pkgversion="$zeek_version" --pkgarch="$ARCH" --pkgsource="$zeek_url" \
	   --pkgrelease="$zeek_release" --pakdir="$DEBS_DIR" ninja install

	# Files are installed by checkinstall outside of DPKG
	# Remove them since a deb has been created for later installation
	ninja uninstall

	cd "${WORK_DIR}"
	rm -rf "${WORK_DIR}/zeek"

	dpkg -i "${DEBS_DIR}/zeek_${zeek_ver}-${zeek_release}_${ARCH}.deb"

}

clean_up() {

	# Set Hedgehog banner
	mv /root/hedgehog-ascii-text.txt /etc/issue

	# Remove network interface files left by installation
	# Sensor setup will create necessary files when user runs setup
	rm -f /etc/network/interfaces.d/*

	# Ensure user network conf goes into proper file
	touch /etc/network/interfaces.d/sensor

	# Remove this script and any debugging files
	# Comment this out in order to troubleshoot the build process in a chroot
	# Build process writes to /root/sensor_install_debug by default
	rm -f /root/sensor_install*

	# Remove extra installation files
	rm -rf /opt/hooks /opt/patches $WORK_DIR /tmp/* /opt/deps /root/.wget-hsts /root/.bash_history

	# Remove unnecessary build components
	apt remove $BUILD_DEPS -y
	apt autoremove -y
	apt clean

	# Ensure locale and term are set
	echo 'TERM=xterm-256color' > /etc/environment
	locale-gen en_US.UTF-8 en.UTF-8
	update-locale LANG=en_US.UTF-8 LANGUAGE=en.UTF-8

	umount -A -f /dev/pts /run /dev /proc /sys

}

clean_up_gui_files() {

	rm -rf /etc/skel/.config/autostart/*
}

create_user() {

	# Set defaults but it is STRONGLY recommended that these be changed before deploying Sensor
	local user='sensor'
	local pass='Hedgehog_Linux'
	local root_pass='Hedgehog_Linux_Root'

	groupadd "$user"
	useradd -m -g sensor -u 1000 -s /bin/bash "$user"

	echo -n "${user}:${pass}" | chpasswd --crypt-method YESCRYPT
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

	# Remove Sensor-ISO packages not relevant to RPI
	# Rar is excluded because Debian doesn't have an ARM package
	# htpdate removed because repo version doesn't support https
	declare -a graphical_deps=( efibootmgr fonts-dejavu fuseext2 fusefat fuseiso gdb gparted gdebi )
	graphical_deps+=( google-perftools gvfs gvfs-daemons gvfs-fuse ghostscript ghostscript-x hfsplus )
	graphical_deps+=( hfsprogs hfsutils htpdate libgtk2.0-bin menu neofetch pmount rar samba-libs )
	graphical_deps+=( ssh-askpass tmux udisks2 upower user-setup xbitmaps zenity zenity-common )

	deps=$(echo ${deps} ${graphical_deps[@]} | tr ' ' '\n' | sort | uniq -u | tr '\n' ' ')

	apt update
	# Hedgehog conf files are copied into env before this runs; keep those config files by default
	apt -o Dpkg::Options::="--force-confold" install -q $deps -y --no-install-suggests
	apt clean

}

install_files() {

	sensor_ver_file="${SENSOR_DIR}/.os-info"

	# Shared Scripts setup
	ln -s /usr/local/bin/malcolm_utils.py "/opt/zeek/bin/"
	mv /usr/local/bin/zeekdeploy.sh "/opt/zeek/bin/"

	# Setup OS information
	echo "BUILD_ID=\"$(date +\'%Y-%m-%d\')-${IMAGE_VERSION}\""   > "$sensor_ver_file"
	echo "VARIANT=\"Hedgehog Linux (Sensor) v${IMAGE_VERSION}\"" >> "$sensor_ver_file"
	echo "VARIANT_ID=\"hedgehog-sensor\"" >> "$sensor_ver_file"
	echo "ID_LIKE=\"debian\"" >> "$sensor_ver_file"
	echo "HOME_URL=\"https://malcolm.fyi\"" >> "$sensor_ver_file"
	echo "DOCUMENTATION_URL=\"https://malcolm.fyi/hedgehog/\"" >> "$sensor_ver_file"
	echo "SUPPORT_URL=\"https://github.com/${IMAGE_PUBLISHER}\"" >> "$sensor_ver_file"
	echo "BUG_REPORT_URL=\"https://github.com/${IMAGE_PUBLISHER}/malcolm/issues\"" >> "$sensor_ver_file"

#####################################################
# NEED TO FIND OUT WHERE THE MM FILE COMES FROM!!!! #
#####################################################

	# Setup MaxMind Geo IP info
	MAXMIND_GEOIP_DB_LICENSE_KEY=""

	if [[ -f "$SCRIPT_PATH/shared/maxmind_license.txt" ]]; then
	MAXMIND_GEOIP_DB_LICENSE_KEY="$(cat "$SCRIPT_PATH/shared/maxmind_license.txt" | head -n 1)"
		if [[ ${#MAXMIND_GEOIP_DB_LICENSE_KEY} -gt 1 ]]; then
			for DB in ASN Country City; do
			curl -s -S -L -o "/opt/arkime/GeoLite2-$DB.mmdb.tar.gz" "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-$DB&license_key=$MAXMIND_GEOIP_DB_LICENSE_KEY&suffix=tar.gz"
			tar xvf "GeoLite2-$DB.mmdb.tar.gz" --wildcards --no-anchored '*.mmdb' --strip=1 --no-same-owner
			rm -f "GeoLite2-$DB.mmdb.tar.gz"
		done
		fi
	fi
	curl -s -S -L -o /opt/arkime/etc/ipv4-address-space.csv "https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv"
	curl -s -S -L -o /opt/arkime/etc/oui.txt "https://www.wireshark.org/download/automated/data/manuf"


	# Prepare Fluentbit and Beats repo GPG keys
	local apt_lists='/etc/apt/sources.list.d'
	local apt_keys='/etc/apt/keyrings'
	local beats_key="${apt_keys}/beats.gpg"
	local fluentbit_key="${apt_keys}/fluentbit.gpg"

	gpg --dearmor --batch --yes -o "$beats_key" "${apt_keys}/beats.key.chroot"
	gpg --dearmor --batch --yes -o "$fluentbit_key" "${apt_keys}/fluentbit.key.chroot"

	rm "${apt_keys}/beats.key.chroot" "${apt_keys}/fluentbit.key.chroot"

	sed -i -e "s|deb |deb [signed-by=${beats_key}] |" "${apt_lists}/beats.list"
	sed -i -e "s|deb |deb [signed-by=${fluentbit_key}] |" "${apt_lists}/fluentbit.list"

	# Prepare debs directory for other packages
	mkdir -p "${DEBS_DIR}"

	# Disable ipv6
	echo 'ipv6.disable=1' > /etc/default/raspi-extra-cmdline

	# Add RPI hostname to /etc/hosts
	echo "127.0.0.1 $(hostname)" >> /etc/hosts

}

install_hooks() {

	set -e

	local hooks_dir='/opt/hooks'

	if [[ $BUILD_GUI -eq 0 ]]; then
		rm -f "${hooks_dir}"/*firefox-install.hook.chroot
		rm -f "${hooks_dir}"/*login.hook.chroot
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

install_files
install_deps
build_interface

# Remove GUI related files if not building RPI with a DE
# See comment above about BUILD_GUI usage
if [[ $BUILD_GUI -eq 0 ]]; then
	clean_up_gui_files
fi

if [ $BUILD_ARKIME_FROM_SOURCE -eq 1 ]; then
	build_arkime_src
else
	# Not implemented currently
	#build_arkime
	build_arkime_src
fi

if [ $BUILD_YARA_FROM_SOURCE -eq 1 ]; then
	build_yara_src
else
	# Not implemented currently
	#build_yara
	build_yara_src
fi

if [ $BUILD_ZEEK_FROM_SOURCE -eq 1 ]; then
	build_zeek_src
else
	build_zeek
fi

install_hooks
build_htpdate
create_user
clean_up

exit 0
