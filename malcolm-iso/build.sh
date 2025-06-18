#!/bin/bash

IMAGE_NAME=malcolm
IMAGE_PUBLISHER=idaholab
IMAGE_VERSION=1.0.0
IMAGE_DISTRIBUTION=bookworm

BUILD_ERROR_CODE=1

DOCKER_IMAGES_TXZ=""
DOCKER_IMAGES_TXZ_RM=0
while getopts rd: opts; do
   case ${opts} in
      d) DOCKER_IMAGES_TXZ=${OPTARG} ;;
      r) DOCKER_IMAGES_TXZ_RM=1 ;;
   esac
done

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit $BUILD_ERROR_CODE
fi

if [[ -n "$DOCKER_IMAGES_TXZ" ]] && [[ ! -r "$DOCKER_IMAGES_TXZ" ]]; then
  echo "\"$DOCKER_IMAGES_TXZ\" was specified but does not exist or cannot be accessed" 1>&2
  exit $BUILD_ERROR_CODE
fi

set -e

RUN_PATH="$(pwd)"
SCRIPT_PATH="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd "$SCRIPT_PATH" >/dev/null 2>&1

WORKDIR="$(mktemp -d -t malcolm-XXXXXX)"

function cleanup {
  echo "Cleaning up..." 1>&2

  # unmount any chroot stuff left behind after an error
  (umount -f $(mount | grep chroot | cut -d ' ' -f 3) >/dev/null 2>&1) && sleep 5

  # if there are any "Immutable" chattr'd files, unset them before trying to do the delete.
  # this is a little slow but lsattr is unreliable with strange or long path names
  find "$WORKDIR" -xdev -exec sh -c '
    for i do
       attrs=$(lsattr -d "$i" 2>/dev/null); attrs=${attrs%% *}
       case $attrs in
         *i*) printf "%s\0" "$i";;
       esac
    done' sh {} + | xargs -r -0 -l chattr -i

  # clean up the temporary build directory
  if ! rm -rf "$WORKDIR"; then
    echo "Failed to remove temporary directory '$WORKDIR'" 1>&2
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

  # configure installation options
  YML_IMAGE_VERSION="$(grep -P "^\s+image:.*/malcolm/" "$SCRIPT_PATH"/../docker-compose.yml | awk '{print $2}' | cut -d':' -f2 | uniq -c | sort -nr | awk '{print $2}' | head -n 1)"
  [[ -n $YML_IMAGE_VERSION ]] && IMAGE_VERSION="$YML_IMAGE_VERSION"
  sed -i "s@^\(title-text[[:space:]]*:\).*@\1 \"Malcolm $IMAGE_VERSION $(date +'%Y-%m-%d %H:%M:%S')\"@g" ./config/bootloaders/grub-pc/live-theme/theme.txt
  cp ./config/includes.binary/install/preseed_multipar.cfg ./config/includes.binary/install/preseed_multipar_crypto.cfg
  cp ./config/includes.binary/install/preseed_base.cfg ./config/includes.binary/install/preseed_minimal.cfg
  sed -i "s@\(partman-auto/method[[:space:]]*string[[:space:]]*\)lvm@\1crypto@g" ./config/includes.binary/install/preseed_multipar_crypto.cfg
  sed -i "s@\(/etc/capture_storage_format\)@\1.crypt@g" ./config/includes.binary/install/preseed_multipar_crypto.cfg
  sed -i "s@\(/etc/capture_storage_format\)@\1.none@g" ./config/includes.binary/install/preseed_minimal.cfg

  # create hooks for installing Python packages
  HOOK_COUNTER=168
  for SUBDIR in config; do
    if [ -f "$SCRIPT_PATH/$SUBDIR/requirements.txt" ]; then
      echo "#!/bin/sh" >> ./config/hooks/normal/0${HOOK_COUNTER}-pip-$SUBDIR-installs.hook.chroot
      echo "export LC_ALL=C.UTF-8" >> ./config/hooks/normal/0${HOOK_COUNTER}-pip-$SUBDIR-installs.hook.chroot
      echo "export LANG=C.UTF-8" >> ./config/hooks/normal/0${HOOK_COUNTER}-pip-$SUBDIR-installs.hook.chroot
      echo "PYTHONDONTWRITEBYTECODE=1" >> ./config/hooks/normal/0${HOOK_COUNTER}-pip-$SUBDIR-installs.hook.chroot
      echo "PYTHONUNBUFFERED=1" >> ./config/hooks/normal/0${HOOK_COUNTER}-pip-$SUBDIR-installs.hook.chroot
      echo -n "python3 -m pip install --break-system-packages --no-compile --no-cache-dir --force-reinstall --upgrade" >> ./config/hooks/normal/0${HOOK_COUNTER}-pip-$SUBDIR-installs.hook.chroot
      while read LINE; do
        echo -n -e " \\\\\n  $LINE" >> ./config/hooks/normal/0${HOOK_COUNTER}-pip-$SUBDIR-installs.hook.chroot
      done <"$SCRIPT_PATH/$SUBDIR/requirements.txt"
      echo "" >> ./config/hooks/normal/0${HOOK_COUNTER}-pip-$SUBDIR-installs.hook.chroot
      chmod +x ./config/hooks/normal/0${HOOK_COUNTER}-pip-$SUBDIR-installs.hook.chroot
    fi
    ((HOOK_COUNTER++))
  done

  # make sure we install the firmwares, etc.
  for PKG in firmware-linux \
             firmware-linux-free \
             firmware-linux-nonfree \
             firmware-misc-nonfree \
             firmware-amd-graphics \
             firmware-iwlwifi \
             firmware-atheros; do
    echo "$PKG" >> ./config/package-lists/firmwares.list.chroot
  done

  # grab things from the Malcolm parent directory into /etc/skel so the user's got it set up in their home/Malcolm dir
  pushd "$SCRIPT_PATH/.." >/dev/null 2>&1
  MALCOLM_DEST_DIR="$WORKDIR/work/$IMAGE_NAME-Live-Build/config/includes.chroot/etc/skel/Malcolm"
  mkdir -p "$MALCOLM_DEST_DIR/arkime/lua/"
  mkdir -p "$MALCOLM_DEST_DIR/arkime/rules/"
  mkdir -p "$MALCOLM_DEST_DIR/config/"
  mkdir -p "$MALCOLM_DEST_DIR/filebeat/certs/"
  mkdir -p "$MALCOLM_DEST_DIR/htadmin/"
  mkdir -p "$MALCOLM_DEST_DIR/logstash/certs/"
  mkdir -p "$MALCOLM_DEST_DIR/logstash/maps/"
  mkdir -p "$MALCOLM_DEST_DIR/netbox/custom-plugins/requirements/"
  mkdir -p "$MALCOLM_DEST_DIR/netbox/media/"
  mkdir -p "$MALCOLM_DEST_DIR/postgres/"
  mkdir -p "$MALCOLM_DEST_DIR/redis/"
  mkdir -p "$MALCOLM_DEST_DIR/netbox/preload/"
  mkdir -p "$MALCOLM_DEST_DIR/nginx/ca-trust/"
  mkdir -p "$MALCOLM_DEST_DIR/nginx/certs/"
  mkdir -p "$MALCOLM_DEST_DIR/kubernetes/"
  mkdir -p "$MALCOLM_DEST_DIR/opensearch-backup/"
  mkdir -p "$MALCOLM_DEST_DIR/opensearch/nodes/"
  mkdir -p "$MALCOLM_DEST_DIR/pcap/arkime-live/"
  mkdir -p "$MALCOLM_DEST_DIR/pcap/processed/"
  mkdir -p "$MALCOLM_DEST_DIR/pcap/upload/tmp/spool/"
  mkdir -p "$MALCOLM_DEST_DIR/pcap/upload/variants/"
  mkdir -p "$MALCOLM_DEST_DIR/scripts/"
  mkdir -p "$MALCOLM_DEST_DIR/suricata-logs/live/"
  mkdir -p "$MALCOLM_DEST_DIR/suricata/rules/"
  mkdir -p "$MALCOLM_DEST_DIR/suricata/include-configs/"
  mkdir -p "$MALCOLM_DEST_DIR/yara/rules/"
  mkdir -p "$MALCOLM_DEST_DIR/zeek-logs/current/"
  mkdir -p "$MALCOLM_DEST_DIR/zeek-logs/extract_files/preserved/"
  mkdir -p "$MALCOLM_DEST_DIR/zeek-logs/extract_files/quarantine/"
  mkdir -p "$MALCOLM_DEST_DIR/zeek-logs/live/"
  mkdir -p "$MALCOLM_DEST_DIR/zeek-logs/processed/"
  mkdir -p "$MALCOLM_DEST_DIR/zeek-logs/upload/"
  mkdir -p "$MALCOLM_DEST_DIR/zeek/custom/"
  mkdir -p "$MALCOLM_DEST_DIR/zeek/intel/Mandiant/"
  mkdir -p "$MALCOLM_DEST_DIR/zeek/intel/MISP/"
  mkdir -p "$MALCOLM_DEST_DIR/zeek/intel/STIX/"
  cp ./docker-compose.yml "$MALCOLM_DEST_DIR/docker-compose.yml"
  cp ./justfile "$MALCOLM_DEST_DIR/justfile"
  cp ./scripts/install.py "$MALCOLM_DEST_DIR/scripts/"
  cp ./scripts/control.py "$MALCOLM_DEST_DIR/scripts/"
  pushd "$MALCOLM_DEST_DIR/scripts/" >/dev/null 2>&1
  ln -s ./control.py auth_setup
  ln -s ./control.py logs
  ln -s ./control.py netbox-backup
  ln -s ./control.py netbox-restore
  ln -s ./control.py restart
  ln -s ./control.py start
  ln -s ./control.py status
  ln -s ./control.py stop
  ln -s ./control.py wipe
  ln -s ./install.py configure
  popd >/dev/null 2>&1
  cp ./config/*.example "$MALCOLM_DEST_DIR/config/"
  cp ./config/*.yml "$MALCOLM_DEST_DIR/config/"
  cp ./scripts/malcolm_common.py "$MALCOLM_DEST_DIR/scripts/"
  cp ./scripts/malcolm_kubernetes.py "$MALCOLM_DEST_DIR/scripts/"
  cp ./scripts/malcolm_utils.py "$MALCOLM_DEST_DIR/scripts/"
  cp ./kubernetes/*.* "$MALCOLM_DEST_DIR/kubernetes/"
  grep -v "^#" ./kubernetes/.gitignore | xargs -r -I XXX rm -f "$MALCOLM_DEST_DIR/kubernetes/XXX"
  cp ./arkime/rules/*.yml "$MALCOLM_DEST_DIR/arkime/rules/"
  cp ./logstash/certs/*.conf "$MALCOLM_DEST_DIR/logstash/certs/"
  cp ./logstash/maps/malcolm_severity.yaml "$MALCOLM_DEST_DIR/logstash/maps/"
  cp -r ./netbox/config/ "$MALCOLM_DEST_DIR/netbox/"
  cp ./netbox/preload/*.yml "$MALCOLM_DEST_DIR/netbox/preload/"

  touch "$MALCOLM_DEST_DIR"/firstrun
  popd >/dev/null 2>&1

  # if there are prebuilt malcolm images to load into the ISO, provide them
  if [[ -r "$DOCKER_IMAGES_TXZ" ]]; then
    cp "$DOCKER_IMAGES_TXZ" ./config/includes.chroot/malcolm_images.tar.xz
    chown root:root ./config/includes.chroot/malcolm_images.tar.xz
    [[ "$DOCKER_IMAGES_TXZ_RM" == "1" ]] && rm -f "$DOCKER_IMAGES_TXZ"
  fi

  # write out some version stuff specific to this installation version
  echo "BUILD_ID=\"$(date +'%Y-%m-%d')-${IMAGE_VERSION}\""                         > "$MALCOLM_DEST_DIR"/.os-info
  echo "VARIANT=\"Hedgehog Linux (Malcolm) v${IMAGE_VERSION}\""                   >> "$MALCOLM_DEST_DIR"/.os-info
  echo "VARIANT_ID=\"hedgehog-malcolm\""                                          >> "$MALCOLM_DEST_DIR"/.os-info
  echo "ID_LIKE=\"debian\""                                                       >> "$MALCOLM_DEST_DIR"/.os-info
  echo "HOME_URL=\"https://${IMAGE_PUBLISHER}.github.io/Malcolm\""                >> "$MALCOLM_DEST_DIR"/.os-info
  echo "DOCUMENTATION_URL=\"https://${IMAGE_PUBLISHER}.github.io/Malcolm\""       >> "$MALCOLM_DEST_DIR"/.os-info
  echo "SUPPORT_URL=\"https://github.com/${IMAGE_PUBLISHER}\""                    >> "$MALCOLM_DEST_DIR"/.os-info
  echo "BUG_REPORT_URL=\"https://github.com/cisagov/malcolm/issues\""             >> "$MALCOLM_DEST_DIR"/.os-info

  # environment variables to pass into chroot
  [[ -f "$SCRIPT_PATH/shared/environment.chroot" ]] && \
    cat "$SCRIPT_PATH/shared/environment.chroot" >> ./config/environment.chroot
  echo "PYTHONDONTWRITEBYTECODE=1" >> ./config/environment.chroot

  # clone and build htpdate .deb package in its own clean environment (rather than in hooks/)
  bash "$SCRIPT_PATH/htpdate/build-docker-image.sh"
  docker run --rm -v "$SCRIPT_PATH"/htpdate:/build htpdate-build:latest -o /build
  mv "$SCRIPT_PATH/htpdate"/*.deb ./config/packages.chroot/
  docker rmi -f htpdate-build:latest

  # copy shared scripts and some branding stuff
  mkdir -p ./config/includes.chroot/usr/local/bin/
  rsync -a "$SCRIPT_PATH/../shared/bin/" ./config/includes.chroot/usr/local/bin/
  cp "$SCRIPT_PATH/../scripts/malcolm_utils.py" ./config/includes.chroot/usr/local/bin/
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

  mkdir -p ./config/includes.installer
  cp -v ./config/includes.binary/install/* ./config/includes.installer/
  cp -v ./config/includes.chroot/usr/local/bin/preseed_partman_determine_disk.sh ./config/includes.installer/

  lb config \
    --apt-indices false \
    --apt-options "--yes --allow-downgrades --allow-remove-essential --allow-change-held-packages -oAcquire::Check-Valid-Until=false" \
    --apt-secure true \
    --apt-source-archives false \
    --architectures amd64 \
    --archive-areas 'main contrib non-free non-free-firmware' \
    --backports false \
    --binary-images iso-hybrid \
    --bootappend-install "auto=true locales=en_US.UTF-8 keyboard-layouts=us" \
    --bootappend-live "boot=live components username=analyst nosplash random.trust_cpu=on elevator=deadline cgroup_enable=memory swapaccount=1 cgroup.memory=nokmem systemd.unified_cgroup_hierarchy=1" \
    --chroot-filesystem squashfs \
    --debian-installer live \
    --debian-installer-distribution $IMAGE_DISTRIBUTION \
    --debian-installer-gui false \
    --debootstrap-options "--include=apt-transport-https,bc,ca-certificates,gnupg,debian-archive-keyring,jq,openssl --no-merged-usr" \
    --distribution $IMAGE_DISTRIBUTION \
    --image-name "$IMAGE_NAME" \
    --iso-application "$IMAGE_NAME" \
    --iso-publisher "$IMAGE_PUBLISHER" \
    --iso-volume "$IMAGE_NAME $(date +'%Y-%m-%d %H:%M:%S')" \
    --linux-flavours "amd64:amd64" \
    --linux-packages "linux-image linux-headers" \
    --memtest none \
    --parent-archive-areas 'main contrib non-free non-free-firmware' \
    --parent-debian-installer-distribution $IMAGE_DISTRIBUTION \
    --parent-distribution $IMAGE_DISTRIBUTION \
    --security true \
    --source false \
    --updates true

  lb build 2>&1 | tee "$WORKDIR/output/$IMAGE_NAME-$IMAGE_VERSION-build.log"
  if [ -f "$IMAGE_NAME-amd64.hybrid.iso" ]; then
    mv "$IMAGE_NAME-amd64.hybrid.iso" "$RUN_PATH/$IMAGE_NAME-$IMAGE_VERSION.iso" && \
      echo "Finished, created \"$RUN_PATH/$IMAGE_NAME-$IMAGE_VERSION.iso\"" 1>&2
    BUILD_ERROR_CODE=0
  else
    echo "Error creating ISO, see log file" 1>&2
    BUILD_ERROR_CODE=2
  fi
  mv "$WORKDIR/output/$IMAGE_NAME-$IMAGE_VERSION-build.log" "$RUN_PATH/"

  popd >/dev/null 2>&1
  popd >/dev/null 2>&1

else
  echo "Unable to create temporary directory \"$WORKDIR\"" 1>&2
fi

popd  >/dev/null 2>&1

exit $BUILD_ERROR_CODE
