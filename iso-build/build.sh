#!/bin/bash

IMAGE_NAME=malcolm
IMAGE_VERSION=1.0.0
IMAGE_DISTRIBUTION=buster

BUILD_ERROR_CODE=1

DOCKER_IMAGES_TGZ=""
while getopts d: opts; do
   case ${opts} in
      d) DOCKER_IMAGES_TGZ=${OPTARG} ;;
   esac
done

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit $BUILD_ERROR_CODE
fi

if [[ -n "$DOCKER_IMAGES_TGZ" ]] && [[ ! -r "$DOCKER_IMAGES_TGZ" ]]; then
  echo "\"$DOCKER_IMAGES_TGZ\" was specified but does not exist or cannot be accessed" 1>&2
  exit $BUILD_ERROR_CODE
fi

set -e

RUN_PATH="$(pwd)"
SCRIPT_PATH="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd "$SCRIPT_PATH" >/dev/null 2>&1

WORKDIR="$(mktemp -d -t malcolm-XXXXXX)"

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
  sed -i "s/\(Install Malcolm Base\)/\1 $(date +'%Y-%m-%d %H:%M:%S')/g" ./config/includes.binary/boot/grub/grub.cfg
  cp ./config/includes.binary/install/preseed.cfg ./config/includes.binary/install/preseed_crypto.cfg
  cp ./config/includes.binary/install/preseed_base.cfg ./config/includes.binary/install/preseed_minimal.cfg
  sed -i "s@\(partman-auto/method[[:space:]]*string[[:space:]]*\)lvm@\1crypto@g" ./config/includes.binary/install/preseed_crypto.cfg

  # make sure we install the newer kernel, firmwares, and kernel headers
  echo "linux-image-$(uname -r)" > ./config/package-lists/kernel.list.chroot
  echo "linux-headers-$(uname -r)" >> ./config/package-lists/kernel.list.chroot
  echo "linux-compiler-gcc-8-x86=$(dpkg -s linux-compiler-gcc-8-x86 | grep ^Version: | cut -d' ' -f2)" >> ./config/package-lists/kernel.list.chroot
  echo "linux-kbuild-4.19=$(dpkg -s linux-kbuild-4.19 | grep ^Version: | cut -d' ' -f2)" >> ./config/package-lists/kernel.list.chroot
  echo "firmware-linux=$(dpkg -s firmware-linux | grep ^Version: | cut -d' ' -f2)" >> ./config/package-lists/kernel.list.chroot
  echo "firmware-linux-nonfree=$(dpkg -s firmware-linux-nonfree | grep ^Version: | cut -d' ' -f2)" >> ./config/package-lists/kernel.list.chroot
  echo "firmware-misc-nonfree=$(dpkg -s firmware-misc-nonfree | grep ^Version: | cut -d' ' -f2)" >> ./config/package-lists/kernel.list.chroot
  echo "firmware-amd-graphics=$(dpkg -s firmware-amd-graphics | grep ^Version: | cut -d' ' -f2)" >> ./config/package-lists/kernel.list.chroot

  # grab things from the Malcolm parent directory into /etc/skel so the user's got it set up in their home/Malcolm dir
  pushd "$SCRIPT_PATH/.." >/dev/null 2>&1
  MALCOLM_DEST_DIR="$WORKDIR/work/$IMAGE_NAME-Live-Build/config/includes.chroot/etc/skel/Malcolm"
  mkdir -p "$MALCOLM_DEST_DIR"
  mkdir -p "$MALCOLM_DEST_DIR/nginx/certs/"
  mkdir -p "$MALCOLM_DEST_DIR/logstash/certs/"
  mkdir -p "$MALCOLM_DEST_DIR/filebeat/certs/"
  mkdir -p "$MALCOLM_DEST_DIR/elasticsearch/nodes/"
  mkdir -p "$MALCOLM_DEST_DIR/elasticsearch-backup/"
  mkdir -p "$MALCOLM_DEST_DIR/elastalert/config/"
  mkdir -p "$MALCOLM_DEST_DIR/elastalert/rules/"
  mkdir -p "$MALCOLM_DEST_DIR/elastalert/sample-rules/"
  mkdir -p "$MALCOLM_DEST_DIR/moloch-raw/"
  mkdir -p "$MALCOLM_DEST_DIR/moloch-logs/"
  mkdir -p "$MALCOLM_DEST_DIR/pcap/upload/"
  mkdir -p "$MALCOLM_DEST_DIR/pcap/processed/"
  mkdir -p "$MALCOLM_DEST_DIR/pcap/autozeek/"
  mkdir -p "$MALCOLM_DEST_DIR/scripts/"
  mkdir -p "$MALCOLM_DEST_DIR/zeek-logs/current/"
  mkdir -p "$MALCOLM_DEST_DIR/zeek-logs/upload/"
  mkdir -p "$MALCOLM_DEST_DIR/zeek-logs/processed/"
  cp ./docker-compose-standalone.yml "$MALCOLM_DEST_DIR/docker-compose.yml"
  cp ./docker-compose-standalone-zeek-live.yml "$MALCOLM_DEST_DIR/docker-compose-zeek-live.yml"
  cp ./cidr-map.txt "$MALCOLM_DEST_DIR/"
  cp ./host-map.txt "$MALCOLM_DEST_DIR/"
  cp ./scripts/auth_setup.sh "$MALCOLM_DEST_DIR/scripts/"
  cp ./scripts/start.sh "$MALCOLM_DEST_DIR/scripts/"
  cp ./scripts/stop.sh "$MALCOLM_DEST_DIR/scripts/"
  cp ./scripts/restart.sh "$MALCOLM_DEST_DIR/scripts/"
  cp ./scripts/wipe.sh "$MALCOLM_DEST_DIR/scripts/"
  cp ./scripts/logs.sh "$MALCOLM_DEST_DIR/scripts/"
  cp ./scripts/install.py "$MALCOLM_DEST_DIR/scripts/"
  cp ./README.md "$MALCOLM_DEST_DIR/"
  cp ./nginx/certs/*.sh "$MALCOLM_DEST_DIR/nginx/certs/"
  cp ./logstash/certs/Makefile ./logstash/certs/*.conf "$MALCOLM_DEST_DIR/logstash/certs/"
  cp ./elastalert/config/* "$MALCOLM_DEST_DIR/elastalert/config/"
  cp ./elastalert/rules/* "$MALCOLM_DEST_DIR/elastalert/rules/" 2>/dev/null || true
  touch "$MALCOLM_DEST_DIR"/firstrun
  popd >/dev/null 2>&1

  # if there are prebuilt malcolm images to load into the ISO, provide them
  if [[ -r "$DOCKER_IMAGES_TGZ" ]]; then
    cp "$DOCKER_IMAGES_TGZ" ./config/includes.chroot/malcolm_images.tar.gz
    chown root:root ./config/includes.chroot/malcolm_images.tar.gz
  fi

  # copy shared scripts and some branding stuff
  mkdir -p ./config/includes.chroot/usr/local/bin/
  rsync -a "$SCRIPT_PATH/../shared/bin/" ./config/includes.chroot/usr/local/bin/
  chown -R root:root ./config/includes.chroot/usr/local/bin/

  mkdir -p ./config/includes.chroot/usr/share/images/desktop-base/
  mkdir -p ./config/includes.chroot/usr/share/icons/hicolor/{64x64,48x48,32x32,24x24,16x16}
  cp "$SCRIPT_PATH"/../docs/images/logo/Malcolm_background.png ./config/includes.chroot/usr/share/images/desktop-base/
  cp "$SCRIPT_PATH"/../docs/images/favicon/favicon64.png ./config/includes.chroot/usr/share/icons/hicolor/64x64/malcolm.png
  cp "$SCRIPT_PATH"/../docs/images/favicon/favicon48.png ./config/includes.chroot/usr/share/icons/hicolor/48x48/malcolm.png
  cp "$SCRIPT_PATH"/../docs/images/favicon/favicon32.png ./config/includes.chroot/usr/share/icons/hicolor/32x32/malcolm.png
  cp "$SCRIPT_PATH"/../docs/images/favicon/favicon24.png ./config/includes.chroot/usr/share/icons/hicolor/24x24/malcolm.png
  cp "$SCRIPT_PATH"/../docs/images/favicon/favicon16.png ./config/includes.chroot/usr/share/icons/hicolor/16x16/malcolm.png
  chown -R root:root ./config/includes.chroot/usr/share/images ./config/includes.chroot/usr/share/icons

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
    --chroot-filesystem squashfs \
    --backports false \
    --security true \
    --updates true \
    --source false \
    --apt-indices none \
    --apt-source-archives false \
    --archive-areas 'main contrib non-free' \
    --parent-mirror-bootstrap http://ftp.us.debian.org/debian/ \
    --parent-mirror-binary http://httpredir.debian.org/debian/ \
    --mirror-bootstrap http://ftp.us.debian.org/debian/ \
    --mirror-binary http://httpredir.debian.org/debian/ \
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
