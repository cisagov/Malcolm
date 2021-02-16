#!/bin/bash

IMAGE_NAME=hedgehog
IMAGE_VERSION=1.0.0
IMAGE_DISTRIBUTION=buster

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

  mkdir -p ./config/hooks/live
  pushd ./config/hooks/live
  ln -v -s -f /usr/share/live/build/hooks/live/* ./
  popd >/dev/null 2>&1

  mkdir -p ./config/hooks/normal
  pushd ./config/hooks/normal
  ln -v -s -f /usr/share/live/build/hooks/normal/* ./
  rm -f ./0910-remove-apt-sources-lists
  popd >/dev/null 2>&1

  chown -R root:root *

  # put the date in the grub.cfg entries and configure installation options
  sed -i "s/\(Install Hedgehog Linux\)/\1 $(date +'%Y-%m-%d %H:%M:%S')/g" ./config/includes.binary/boot/grub/grub.cfg
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

  # make sure we install the newer kernel, firmwares, and kernel headers
  echo "linux-image-$(uname -r)" > ./config/package-lists/kernel.list.chroot
  echo "linux-headers-$(uname -r)" >> ./config/package-lists/kernel.list.chroot
  echo "linux-compiler-gcc-8-x86=$(dpkg -s linux-compiler-gcc-8-x86 | grep ^Version: | cut -d' ' -f2)" >> ./config/package-lists/kernel.list.chroot
  echo "linux-kbuild-5.9=$(dpkg -s linux-kbuild-5.9 | grep ^Version: | cut -d' ' -f2)" >> ./config/package-lists/kernel.list.chroot
  echo "firmware-linux=$(dpkg -s firmware-linux | grep ^Version: | cut -d' ' -f2)" >> ./config/package-lists/kernel.list.chroot
  echo "firmware-linux-nonfree=$(dpkg -s firmware-linux-nonfree | grep ^Version: | cut -d' ' -f2)" >> ./config/package-lists/kernel.list.chroot
  echo "firmware-misc-nonfree=$(dpkg -s firmware-misc-nonfree | grep ^Version: | cut -d' ' -f2)" >> ./config/package-lists/kernel.list.chroot
  echo "firmware-amd-graphics=$(dpkg -s firmware-amd-graphics | grep ^Version: | cut -d' ' -f2)" >> ./config/package-lists/kernel.list.chroot

  # and make sure we remove the old stuff when it's all over
  echo "#!/bin/sh" > ./config/hooks/normal/9999-remove-old-kernel-artifacts.hook.chroot
  echo "export LC_ALL=C.UTF-8" >> ./config/hooks/normal/9999-remove-old-kernel-artifacts.hook.chroot
  echo "export LANG=C.UTF-8" >> ./config/hooks/normal/9999-remove-old-kernel-artifacts.hook.chroot
  echo "apt-get -y --purge remove *4.19* || true" >> ./config/hooks/normal/9999-remove-old-kernel-artifacts.hook.chroot
  echo "apt-get -y autoremove" >> ./config/hooks/normal/9999-remove-old-kernel-artifacts.hook.chroot
  echo "apt-get clean" >> ./config/hooks/normal/9999-remove-old-kernel-artifacts.hook.chroot
  chmod +x ./config/hooks/normal/9999-remove-old-kernel-artifacts.hook.chroot

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

  if [[ -f "$SCRIPT_PATH/shared/version.txt" ]]; then
    SHARED_IMAGE_VERSION="$(cat "$SCRIPT_PATH/shared/version.txt" | head -n 1)"
    [[ -n $SHARED_IMAGE_VERSION ]] && IMAGE_VERSION="$SHARED_IMAGE_VERSION"
  fi

  # grab maxmind geoip database files, iana ipv4 address ranges, wireshark oui lists, etc.
  mkdir -p "$SCRIPT_PATH/moloch/etc"
  pushd "$SCRIPT_PATH/moloch/etc"
  MAXMIND_GEOIP_DB_LICENSE_KEY=""
  if [[ -f "$SCRIPT_PATH/shared/maxmind_license.txt" ]]; then
    MAXMIND_GEOIP_DB_LICENSE_KEY="$(cat "$SCRIPT_PATH/shared/maxmind_license.txt" | head -n 1)"
    if [[ ${#MAXMIND_GEOIP_DB_LICENSE_KEY} -gt 1 ]]; then
      for DB in ASN Country City; do
        curl -s -S -L -o "GeoLite2-$DB.mmdb.tar.gz" "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-$DB&license_key=$MAXMIND_GEOIP_DB_LICENSE_KEY&suffix=tar.gz"
        tar xvf "GeoLite2-$DB.mmdb.tar.gz" --wildcards --no-anchored '*.mmdb' --strip=1
        rm -f "GeoLite2-$DB.mmdb.tar.gz"
      done
    fi
  fi
  curl -s -S -L -o ipv4-address-space.csv "https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv"
  curl -s -S -L -o oui.txt "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf"
  popd >/dev/null 2>&1

  # clone and build Arkime .deb package in its own clean environment (rather than in hooks/)
  bash "$SCRIPT_PATH/moloch/build-docker-image.sh"
  docker run --rm -v "$SCRIPT_PATH"/moloch:/build arkime-build:latest -o /build
  cp "$SCRIPT_PATH/moloch"/*.deb ./config/includes.chroot/opt/hedgehog_install_artifacts/
  mv "$SCRIPT_PATH/moloch"/*.deb ./config/packages.chroot/

  # clone and build custom protologbeat from github for logging temperature, etc.
  mkdir -p ./config/includes.chroot/usr/local/bin/
  bash "$SCRIPT_PATH/beats/build-docker-image.sh"
  bash "$SCRIPT_PATH/beats/beat-build.sh" -b "https://github.com/mmguero-dev/protologbeat" -t "es_7_10_0_compat"
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
    --image-name "$IMAGE_NAME" \
    --debian-installer live \
    --debian-installer-gui false \
    --debian-installer-distribution $IMAGE_DISTRIBUTION \
    --distribution $IMAGE_DISTRIBUTION \
    --linux-packages "linux-image-$(uname -r | sed 's/-amd64$//')" \
    --architectures amd64 \
    --binary-images iso-hybrid \
    --bootloaders "syslinux,grub-efi" \
    --memtest none \
    --chroot-filesystem squashfs \
    --backports true \
    --security true \
    --updates true \
    --source false \
    --apt-indices none \
    --apt-source-archives false \
    --archive-areas 'main contrib non-free' \
    --debootstrap-options "--include=apt-transport-https,gnupg,ca-certificates,openssl" \
    --apt-options "--yes --allow-downgrades --allow-remove-essential --allow-change-held-packages -oAPT::Default-Release=buster"

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
