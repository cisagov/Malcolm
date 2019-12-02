#!/bin/bash

IMAGE_NAME=hedgehog
IMAGE_VERSION=1.7.2
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
  cp ./config/includes.binary/install/preseed.cfg ./config/includes.binary/install/preseed_crypto.cfg
  cp ./config/includes.binary/install/preseed_base.cfg ./config/includes.binary/install/preseed_minimal.cfg
  sed -i "s@\(partman-auto/method[[:space:]]*string[[:space:]]*\)lvm@\1crypto@g" ./config/includes.binary/install/preseed_crypto.cfg
  sed -i "s@\(/etc/capture_storage_format\)@\1.crypt@g" ./config/includes.binary/install/preseed_crypto.cfg
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
  echo "linux-kbuild-4.19=$(dpkg -s linux-kbuild-4.19 | grep ^Version: | cut -d' ' -f2)" >> ./config/package-lists/kernel.list.chroot
  echo "firmware-linux=$(dpkg -s firmware-linux | grep ^Version: | cut -d' ' -f2)" >> ./config/package-lists/kernel.list.chroot
  echo "firmware-linux-nonfree=$(dpkg -s firmware-linux-nonfree | grep ^Version: | cut -d' ' -f2)" >> ./config/package-lists/kernel.list.chroot
  echo "firmware-misc-nonfree=$(dpkg -s firmware-misc-nonfree | grep ^Version: | cut -d' ' -f2)" >> ./config/package-lists/kernel.list.chroot
  echo "firmware-amd-graphics=$(dpkg -s firmware-amd-graphics | grep ^Version: | cut -d' ' -f2)" >> ./config/package-lists/kernel.list.chroot

  # copy the interface code into place for the resultant image
  mkdir -p ./config/includes.chroot/opt
  rsync -a "$SCRIPT_PATH/interface/" ./config/includes.chroot/opt/sensor/
  chown -R root:root ./config/includes.chroot/opt/sensor/
  rm -rf ./config/includes.chroot/opt/sensor/.git ./config/includes.chroot/opt/sensor/HedgehogLinux.md ./config/includes.chroot/opt/sensor/requirements.txt ./config/includes.chroot/opt/sensor/setup.py
  sed -i "s@/home/sensor/sensor_interface@/opt/sensor@g" ./config/includes.chroot/opt/sensor/kiosk.service
  # replace capture interface for now, it'll need to be automatically detected/configured on boot
  sed -i "s/CAPTURE_INTERFACE=.*/CAPTURE_INTERFACE=xxxx/g" ./config/includes.chroot/opt/sensor/sensor_ctl/control_vars.conf

  # clone and build custom protologbeat from github for logging temperature, etc.
  mkdir -p ./config/includes.chroot/usr/local/bin/
  bash "$SCRIPT_PATH/beats/build-docker-image.sh"
  bash "$SCRIPT_PATH/beats/beat-build.sh" -b "https://github.com/mmguero/protologbeat"
  mv github.com_mmguero_protologbeat/protologbeat ./config/includes.chroot/usr/local/bin

  # clone and build Moloch .deb package in its own clean environment (rather than in hooks/)
  mkdir -p ./config/packages.chroot/
  bash "$SCRIPT_PATH/moloch/build-docker-image.sh"
  docker run --rm -v "$SCRIPT_PATH"/moloch:/build moloch-build:latest -o /build
  mv "$SCRIPT_PATH/moloch"/*.deb ./config/packages.chroot/

  # copy shared scripts from parent (Malcolm) directory
  rsync -a "$SCRIPT_PATH/../shared/bin/" ./config/includes.chroot/usr/local/bin/
  chown -R root:root ./config/includes.chroot/usr/local/bin/

  # format and copy documentation
  pushd "$SCRIPT_PATH/docs/"
  pushd ./images
  ls -1 *.png | xargs -n 1 bash -c 'convert "$0" "${0%.*}.jpg"'
  popd >/dev/null 2>&1
  cp HedgehogLinux.md HedgehogLinux.jpg.md
  sed -i "s/.png/.jpg/g" HedgehogLinux.jpg.md
  sed -i "s/^# Hedgehog Linux$//" HedgehogLinux.jpg.md
  pandoc -s --self-contained --metadata title="Hedgehog Linux" --css doc.css -o HedgehogLinux.html HedgehogLinux.jpg.md
  rm -f HedgehogLinux.jpg.md
  popd >/dev/null 2>&1
  mkdir -p ./config/includes.chroot/usr/share/doc/hedgehog
  cp "$SCRIPT_PATH/docs/"*.html ./config/includes.chroot/usr/share/doc/hedgehog/
  mkdir -p ./config/includes.chroot/usr/share/fonts/truetype/ubuntu/ ./config/includes.chroot/usr/share/images/hedgehog/ ./config/includes.chroot/usr/share/images/desktop-base/
  cp "$SCRIPT_PATH/docs/logo/"*.png ./config/includes.chroot/usr/share/images/hedgehog/
  ln -r -s ./config/includes.chroot/usr/share/images/hedgehog/*wallpaper*.png ./config/includes.chroot/usr/share/images/desktop-base/
  find "$SCRIPT_PATH/docs/logo/font" -type f -name "*.ttf" -exec cp "{}" ./config/includes.chroot/usr/share/fonts/truetype/ubuntu/ \;

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
    --apt-options "--allow-downgrades --allow-remove-essential --allow-change-held-packages --yes"

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
