#!/bin/bash

IMAGE_NAME=hedgehog
IMAGE_PUBLISHER=idaholab
IMAGE_VERSION=1.0.0
IMAGE_DISTRIBUTION=bullseye

BUILD_ERROR_CODE=1

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit $BUILD_ERROR_CODE
fi

set -e

RUN_PATH="$(pwd)"
SCRIPT_PATH="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd "$SCRIPT_PATH" >/dev/null 2>&1

WORKDIR="$(mktemp -d -t hedgehog-XXXXXX)"

function cleanup {
  # unmount any chroot stuff left behind after an error
  (umount -f $(mount | grep chroot | cut -d ' ' -f 3) >/dev/null 2>&1) && sleep 5

  # clean up the temporary build directory
  if ! rm -rf "$WORKDIR"; then
    echo "Failed to remove temporary directory '$WORKDIR'"
    exit $BUILD_ERROR_CODE
  fi
}

if [ -d "$WORKDIR" ]; then
  # ensure that if we "grabbed a lock", we release it (works for clean exit, SIGTERM, and SIGINT/Ctrl-C)
  trap "cleanup" EXIT

  pushd "$WORKDIR" >/dev/null 2>&1
  mkdir -p ./output "./work/$IMAGE_NAME-Live-Build"
  pushd "./work/$IMAGE_NAME-Live-Build" >/dev/null 2>&1
  rsync -a "$SCRIPT_PATH/config" .

  mkdir -p ./config/packages.chroot/

  chown -R root:root *

  if [[ -f "$SCRIPT_PATH/shared/version.txt" ]]; then
    SHARED_IMAGE_VERSION="$(cat "$SCRIPT_PATH/shared/version.txt" | head -n 1)"
    [[ -n $SHARED_IMAGE_VERSION ]] && IMAGE_VERSION="$SHARED_IMAGE_VERSION"
  fi

  # configure installation options
  sed -i "s@^\(title-text[[:space:]]*:\).*@\1 \"Hedgehog Linux $IMAGE_VERSION $(date +'%Y-%m-%d %H:%M:%S')\"@g" ./config/bootloaders/grub-pc/live-theme/theme.txt
  cp ./config/includes.binary/install/preseed_multipar.cfg ./config/includes.binary/install/preseed_multipar_crypto.cfg
  cp ./config/includes.binary/install/preseed_base.cfg ./config/includes.binary/install/preseed_minimal.cfg
  sed -i "s@\(partman-auto/method[[:space:]]*string[[:space:]]*\)lvm@\1crypto@g" ./config/includes.binary/install/preseed_multipar_crypto.cfg
  sed -i "s@\(/etc/capture_storage_format\)@\1.crypt@g" ./config/includes.binary/install/preseed_multipar_crypto.cfg
  sed -i "s@\(/etc/capture_storage_format\)@\1.none@g" ./config/includes.binary/install/preseed_minimal.cfg

  # create a hook for installing Python packages required by interface
  if [ -f "$SCRIPT_PATH/interface/requirements.txt" ]; then
    echo "#!/bin/sh" >> ./config/hooks/normal/0168-pip-sensor-interface-installs.hook.chroot
    echo "export LC_ALL=C.UTF-8" >> ./config/hooks/normal/0168-pip-sensor-interface-installs.hook.chroot
    echo "export LANG=C.UTF-8" >> ./config/hooks/normal/0168-pip-sensor-interface-installs.hook.chroot
    echo -n "pip3 install --system --no-compile --no-cache-dir --force-reinstall --upgrade" >> ./config/hooks/normal/0168-pip-sensor-interface-installs.hook.chroot
    while read LINE; do
      echo -n -e " \\\\\n  $LINE" >> ./config/hooks/normal/0168-pip-sensor-interface-installs.hook.chroot
    done <"$SCRIPT_PATH/interface/requirements.txt"
    echo "" >> ./config/hooks/normal/0168-pip-sensor-interface-installs.hook.chroot
    chmod +x ./config/hooks/normal/0168-pip-sensor-interface-installs.hook.chroot
  fi

  # make sure we install the firmwares, etc.
  for PKG in firmware-linux \
             firmware-linux-free \
             firmware-linux-nonfree \
             firmware-misc-nonfree \
             firmware-amd-graphics \
             firmware-iwlwifi \
             firmware-atheros \
             linux-headers-amd64; do
    echo "$PKG" >> ./config/package-lists/firmwares.list.chroot
  done

  mkdir -p ./config/includes.chroot/opt/hedgehog_install_artifacts

  # copy the interface code into place for the resultant image
  mkdir -p ./config/includes.chroot/opt
  rsync -a "$SCRIPT_PATH/interface/" ./config/includes.chroot/opt/sensor/
  chown -R root:root ./config/includes.chroot/opt/sensor/
  rm -rf ./config/includes.chroot/opt/sensor/.git ./config/includes.chroot/opt/sensor/HedgehogLinux.md ./config/includes.chroot/opt/sensor/requirements.txt ./config/includes.chroot/opt/sensor/setup.py
  sed -i "s@/home/sensor/sensor_interface@/opt/sensor@g" ./config/includes.chroot/opt/sensor/kiosk.service
  # replace capture interface for now, it'll need to be automatically detected/configured on boot
  sed -i "s/CAPTURE_INTERFACE=.*/CAPTURE_INTERFACE=xxxx/g" ./config/includes.chroot/opt/sensor/sensor_ctl/control_vars.conf

  # copy shared scripts
  rsync -a "$SCRIPT_PATH/shared/bin/" ./config/includes.chroot/usr/local/bin/
  chown -R root:root ./config/includes.chroot/usr/local/bin/

  # write out some version stuff specific to this installation version
  echo "BUILD_ID=\"$(date +'%Y-%m-%d')-${IMAGE_VERSION}\""                         > ./config/includes.chroot/opt/sensor/.os-info
  echo "VARIANT=\"Hedgehog Linux (Sensor) v${IMAGE_VERSION}\""                    >> ./config/includes.chroot/opt/sensor/.os-info
  echo "VARIANT_ID=\"hedgehog-sensor\""                                           >> ./config/includes.chroot/opt/sensor/.os-info
  echo "ID_LIKE=\"debian\""                                                       >> ./config/includes.chroot/opt/sensor/.os-info
  echo "HOME_URL=\"https://malcolm.fyi\""                                         >> ./config/includes.chroot/opt/sensor/.os-info
  echo "DOCUMENTATION_URL=\"https://malcolm.fyi/hedgehog/\""                      >> ./config/includes.chroot/opt/sensor/.os-info
  echo "SUPPORT_URL=\"https://github.com/${IMAGE_PUBLISHER}\""                    >> ./config/includes.chroot/opt/sensor/.os-info
  echo "BUG_REPORT_URL=\"https://github.com/${IMAGE_PUBLISHER}/malcolm/issues\""  >> ./config/includes.chroot/opt/sensor/.os-info

  # grab maxmind geoip database files, iana ipv4 address ranges, wireshark oui lists, etc.
  mkdir -p "$SCRIPT_PATH/arkime/etc"
  pushd "$SCRIPT_PATH/arkime/etc"
  MAXMIND_GEOIP_DB_LICENSE_KEY=""
  if [[ -f "$SCRIPT_PATH/shared/maxmind_license.txt" ]]; then
    MAXMIND_GEOIP_DB_LICENSE_KEY="$(cat "$SCRIPT_PATH/shared/maxmind_license.txt" | head -n 1)"
    if [[ ${#MAXMIND_GEOIP_DB_LICENSE_KEY} -gt 1 ]]; then
      for DB in ASN Country City; do
        curl -s -S -L -o "GeoLite2-$DB.mmdb.tar.gz" "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-$DB&license_key=$MAXMIND_GEOIP_DB_LICENSE_KEY&suffix=tar.gz"
        tar xvf "GeoLite2-$DB.mmdb.tar.gz" --wildcards --no-anchored '*.mmdb' --strip=1 --no-same-owner
        rm -f "GeoLite2-$DB.mmdb.tar.gz"
      done
    fi
  fi
  curl -s -S -L -o ipv4-address-space.csv "https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv"
  curl -s -S -L -o oui.txt "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf"
  popd >/dev/null 2>&1

  # clone and build Arkime .deb package in its own clean environment (rather than in hooks/)
  rsync -a "$SCRIPT_PATH"/shared/arkime_patch "$SCRIPT_PATH"/arkime/arkime_patch
  bash "$SCRIPT_PATH/arkime/build-docker-image.sh"
  docker run --rm -v "$SCRIPT_PATH"/arkime:/build arkime-build:latest -o /build
  cp "$SCRIPT_PATH/arkime"/*.deb ./config/includes.chroot/opt/hedgehog_install_artifacts/
  mv "$SCRIPT_PATH/arkime"/*.deb ./config/packages.chroot/

  # clone and build custom protologbeat from github for logging temperature, etc.
  mkdir -p ./config/includes.chroot/usr/local/bin/
  bash "$SCRIPT_PATH/beats/build-docker-image.sh"
  bash "$SCRIPT_PATH/beats/beat-build.sh" -b "https://github.com/mmguero-dev/protologbeat" -t "main"
  cp github.com_mmguero-dev_protologbeat/protologbeat ./config/includes.chroot/opt/hedgehog_install_artifacts/
  mv github.com_mmguero-dev_protologbeat/protologbeat ./config/includes.chroot/usr/local/bin

  # format and copy documentation
  pushd "$SCRIPT_PATH/"
  pushd ./docs/images
  ls -1 *.png | xargs -n 1 bash -c 'convert "$0" "${0%.*}.jpg"'
  popd >/dev/null 2>&1
  cp README.md HedgehogLinux.jpg.md
  sed -i "s/.png/.jpg/g" HedgehogLinux.jpg.md
  sed -i "s@/docs/logo/@/docs/images/@g" HedgehogLinux.jpg.md
  sed -i "s/^# Hedgehog Linux$//" HedgehogLinux.jpg.md
  sed -i 's/\!\[.*\](.*\/badge.svg)//g' HedgehogLinux.jpg.md
  pandoc -s --self-contained --metadata title="Hedgehog Linux" --css doc.css -o HedgehogLinux.html HedgehogLinux.jpg.md
  rm -f HedgehogLinux.jpg.md
  popd >/dev/null 2>&1
  mkdir -p ./config/includes.chroot/usr/share/doc/hedgehog
  cp "$SCRIPT_PATH/"*.html ./config/includes.chroot/usr/share/doc/hedgehog/
  mkdir -p ./config/includes.chroot/usr/share/fonts/truetype/ubuntu/ ./config/includes.chroot/usr/share/images/hedgehog/ ./config/includes.chroot/usr/share/images/desktop-base/
  cp "$SCRIPT_PATH/docs/logo/"*.png ./config/includes.chroot/usr/share/images/hedgehog/
  ln -r -s ./config/includes.chroot/usr/share/images/hedgehog/*wallpaper*.png ./config/includes.chroot/usr/share/images/desktop-base/
  find "$SCRIPT_PATH/docs/logo/font" -type f -name "*.ttf" -exec cp "{}" ./config/includes.chroot/usr/share/fonts/truetype/ubuntu/ \;

  mkdir -p ./config/includes.installer
  cp -v ./config/includes.binary/install/* ./config/includes.installer/
  cp -v ./config/includes.chroot/usr/local/bin/preseed_partman_determine_disk.sh ./config/includes.installer/

  lb config \
    --apt-indices false \
    --apt-options "--yes --allow-downgrades --allow-remove-essential --allow-change-held-packages -oAcquire::Check-Valid-Until=false" \
    --apt-secure true \
    --apt-source-archives false \
    --architectures amd64 \
    --archive-areas 'main contrib non-free' \
    --backports true \
    --binary-images iso-hybrid \
    --bootappend-install "auto=true locales=en_US.UTF-8 keyboard-layouts=us" \
    --bootappend-live "boot=live components username=sensor nosplash random.trust_cpu=on elevator=deadline cgroup_enable=memory swapaccount=1 cgroup.memory=nokmem systemd.unified_cgroup_hierarchy=1" \
    --chroot-filesystem squashfs \
    --debian-installer live \
    --debian-installer-distribution $IMAGE_DISTRIBUTION \
    --debian-installer-gui false \
    --debootstrap-options "--include=apt-transport-https,bc,ca-certificates,gnupg,debian-archive-keyring,fasttrack-archive-keyring,jq,openssl --no-merged-usr" \
    --distribution $IMAGE_DISTRIBUTION \
    --image-name "$IMAGE_NAME" \
    --iso-application "$IMAGE_NAME" \
    --iso-publisher "$IMAGE_PUBLISHER" \
    --iso-volume "$IMAGE_NAME $(date +'%Y-%m-%d %H:%M:%S')" \
    --linux-flavours "amd64:amd64" \
    --linux-packages "linux-image linux-headers" \
    --memtest none \
    --parent-archive-areas 'main contrib non-free' \
    --parent-debian-installer-distribution $IMAGE_DISTRIBUTION \
    --parent-distribution $IMAGE_DISTRIBUTION \
    --security true \
    --source false \
    --updates true

  lb build 2>&1 | tee "$WORKDIR/output/$IMAGE_NAME-$IMAGE_VERSION-build.log"
  if [ -f "$IMAGE_NAME-amd64.hybrid.iso" ]; then
    mv "$IMAGE_NAME-amd64.hybrid.iso" "$RUN_PATH/$IMAGE_NAME-$IMAGE_VERSION.iso" && \
      echo "Finished, created \"$RUN_PATH/$IMAGE_NAME-$IMAGE_VERSION.iso\""
    BUILD_ERROR_CODE=0
  else
    echo "Error creating ISO, see log file"
    BUILD_ERROR_CODE=2
  fi
  mv "$WORKDIR/output/$IMAGE_NAME-$IMAGE_VERSION-build.log" "$RUN_PATH/"

  popd >/dev/null 2>&1
  popd >/dev/null 2>&1

else
  echo "Unable to create temporary directory \"$WORKDIR\""
fi

popd  >/dev/null 2>&1

exit $BUILD_ERROR_CODE
