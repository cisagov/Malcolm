#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

if [ -z "$BASH_VERSION" ]; then
  echo "Wrong interpreter, please run \"$0\" with bash"
  exit 1
fi

set -e

DESTDIR="$(mktemp -d -t malcolm-XXXXXX)"
VERBOSE="-v"

function cleanup {
  if ! rm -rf "$DESTDIR"; then
    echo "Failed to remove temporary directory '$DESTDIR'"
    exit 1
  fi
}

# force-navigate to Malcolm base directory (parent of scripts/ directory)
RUN_PATH="$(pwd)"
[[ "$(uname -s)" = 'Darwin' ]] && REALPATH=grealpath || REALPATH=realpath
[[ "$(uname -s)" = 'Darwin' ]] && DIRNAME=gdirname || DIRNAME=dirname
if ! (type "$REALPATH" && type "$DIRNAME") > /dev/null; then
  echo "$(basename "${BASH_SOURCE[0]}") requires $REALPATH and $DIRNAME"
  exit 1
fi
SCRIPT_PATH="$($DIRNAME $($REALPATH -e "${BASH_SOURCE[0]}"))"
pushd "$SCRIPT_PATH/.." >/dev/null 2>&1
MALCOLM_CONTAINER_RUNTIME="${MALCOLM_CONTAINER_RUNTIME:-docker}"

CURRENT_REV_SHA="$(git rev-parse --short --verify HEAD)"
if [ -z "$CURRENT_REV_SHA" ]; then
  CURRENT_REV_TAG="$(date +%Y.%m.%d_%H:%M:%S)"
else
  if [[ "$(uname -s)" == 'Darwin' ]]; then
    CURRENT_REV_DATE="$(git log -1 --format="%at" | xargs -I{} date -r {} +%Y%m%d_%H%M%S)"
  else
    CURRENT_REV_DATE="$(git log -1 --format="%at" | xargs -I{} date -d @{} +%Y%m%d_%H%M%S)"
  fi
  if [ -z "$CURRENT_REV_DATE" ]; then
    CURRENT_REV_TAG="$(date +%Y.%m.%d_%H:%M:%S)"
  fi
  CURRENT_REV_TAG="${CURRENT_REV_DATE}_${CURRENT_REV_SHA}"
fi

DESTDIR="/tmp/malcolm_${CURRENT_REV_TAG}"
if [ -d "$DESTDIR" ]; then
  unset CONFIRMATION
  echo ""
  read -p "Temporary directory \"$DESTDIR\" exists, delete before proceeding? [y/N]? " CONFIRMATION
  CONFIRMATION=${CONFIRMATION:-N}
  if [[ $CONFIRMATION =~ ^[Yy]$ ]]; then
    rm -rf "$DESTDIR"
  else
    echo "Aborting"
    popd  >/dev/null 2>&1
    popd  >/dev/null 2>&1
    exit 1
  fi
fi

if mkdir "$DESTDIR"; then
  # ensure that if we "grabbed a lock", we release it (works for clean exit, SIGTERM, and SIGINT/Ctrl-C)
  trap "cleanup" EXIT

  mkdir $VERBOSE -p "$DESTDIR/arkime/lua/"
  mkdir $VERBOSE -p "$DESTDIR/arkime/rules/"
  mkdir $VERBOSE -p "$DESTDIR/filebeat/certs/"
  mkdir $VERBOSE -p "$DESTDIR/htadmin/"
  mkdir $VERBOSE -p "$DESTDIR/logstash/certs/"
  mkdir $VERBOSE -p "$DESTDIR/logstash/maps/"
  mkdir $VERBOSE -p "$DESTDIR/netbox/custom-plugins/requirements/"
  mkdir $VERBOSE -p "$DESTDIR/netbox/media/"
  mkdir $VERBOSE -p "$DESTDIR/postgres/"
  mkdir $VERBOSE -p "$DESTDIR/redis/"
  mkdir $VERBOSE -p "$DESTDIR/netbox/preload/"
  mkdir $VERBOSE -p "$DESTDIR/nginx/ca-trust/"
  mkdir $VERBOSE -p "$DESTDIR/nginx/certs/"
  mkdir $VERBOSE -p "$DESTDIR/opensearch-backup/"
  mkdir $VERBOSE -p "$DESTDIR/opensearch/nodes/"
  mkdir $VERBOSE -p "$DESTDIR/pcap/arkime-live/"
  mkdir $VERBOSE -p "$DESTDIR/pcap/processed/"
  mkdir $VERBOSE -p "$DESTDIR/pcap/upload/tmp/spool"
  mkdir $VERBOSE -p "$DESTDIR/pcap/upload/variants/"
  mkdir $VERBOSE -p "$DESTDIR/config/"
  mkdir $VERBOSE -p "$DESTDIR/scripts/"
  mkdir $VERBOSE -p "$DESTDIR/suricata-logs/live/"
  mkdir $VERBOSE -p "$DESTDIR/suricata/rules/"
  mkdir $VERBOSE -p "$DESTDIR/suricata/include-configs/"
  mkdir $VERBOSE -p "$DESTDIR/yara/rules/"
  mkdir $VERBOSE -p "$DESTDIR/zeek-logs/current/"
  mkdir $VERBOSE -p "$DESTDIR/zeek-logs/extract_files/preserved/"
  mkdir $VERBOSE -p "$DESTDIR/zeek-logs/extract_files/quarantine/"
  mkdir $VERBOSE -p "$DESTDIR/zeek-logs/live/"
  mkdir $VERBOSE -p "$DESTDIR/zeek-logs/processed/"
  mkdir $VERBOSE -p "$DESTDIR/zeek-logs/upload/"
  mkdir $VERBOSE -p "$DESTDIR/zeek/custom/"
  mkdir $VERBOSE -p "$DESTDIR/zeek/intel/Mandiant/"
  mkdir $VERBOSE -p "$DESTDIR/zeek/intel/MISP/"
  mkdir $VERBOSE -p "$DESTDIR/zeek/intel/STIX/"

  cp $VERBOSE ./config/*.example "$DESTDIR/config/"
  cp $VERBOSE ./config/*.yml "$DESTDIR/config/"
  cp $VERBOSE ./docker-compose.yml "$DESTDIR/docker-compose.yml"
  cp $VERBOSE ./justfile "$DESTDIR/justfile"
  cp $VERBOSE ./scripts/install.py "$DESTDIR/scripts/"
  cp $VERBOSE ./scripts/control.py "$DESTDIR/scripts/"
  cp $VERBOSE ./scripts/malcolm_common.py "$DESTDIR/scripts/"
  cp $VERBOSE ./scripts/malcolm_kubernetes.py "$DESTDIR/scripts/"
  cp $VERBOSE ./scripts/malcolm_utils.py "$DESTDIR/scripts/"
  cp $VERBOSE ./README.md "$DESTDIR/"
  cp $VERBOSE ./arkime/rules/*.yml "$DESTDIR/arkime/rules/"
  cp $VERBOSE ./logstash/certs/*.conf "$DESTDIR/logstash/certs/"
  cp $VERBOSE ./logstash/maps/malcolm_severity.yaml "$DESTDIR/logstash/maps/"
  cp $VERBOSE -r ./netbox/config/ "$DESTDIR/netbox/"
  cp $VERBOSE ./netbox/preload/*.yml "$DESTDIR/netbox/preload/"

  mkdir $VERBOSE -p "$DESTDIR/kubernetes/"
  cp $VERBOSE ./kubernetes/*.* "$DESTDIR/kubernetes/"
  grep -v '^#' ./kubernetes/.gitignore | xargs -r -I XXX rm -f "$DESTDIR/kubernetes/XXX"

  pushd "$DESTDIR" >/dev/null 2>&1
  touch ./.opensearch.primary.curlrc ./.opensearch.secondary.curlrc
  chmod 600 ./.opensearch.primary.curlrc ./.opensearch.secondary.curlrc
  pushd "./scripts" >/dev/null 2>&1
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
  popd  >/dev/null 2>&1
  pushd .. >/dev/null 2>&1
  DESTNAME="$RUN_PATH/$(basename $DESTDIR).tar.gz"
  README="$RUN_PATH/$(basename $DESTDIR).README.txt"
  cp $VERBOSE "$SCRIPT_PATH/install.py" "$RUN_PATH/"
  cp $VERBOSE "$SCRIPT_PATH/malcolm_common.py" "$RUN_PATH/"
  cp $VERBOSE "$SCRIPT_PATH/malcolm_kubernetes.py" "$RUN_PATH/"
  cp $VERBOSE "$SCRIPT_PATH/malcolm_utils.py" "$RUN_PATH/"

  if [[ "$(uname -s)" == "Darwin" ]]; then
      tar $VERBOSE -czf "$DESTNAME" "./$(basename $DESTDIR)/"
  else
      tar $VERBOSE --numeric-owner --owner=0 --group=0 -czf "$DESTNAME" "./$(basename $DESTDIR)/"
  fi
  echo "Packaged Malcolm to \"$DESTNAME\""

  unset CONFIRMATION
  echo ""
  read -p "Do you need to package container images also [y/N]? " CONFIRMATION
  CONFIRMATION=${CONFIRMATION:-N}
  if [[ $CONFIRMATION =~ ^[Yy]$ ]]; then
    echo "This might take a few minutes..."
    DESTNAMEIMAGES="$RUN_PATH/$(basename $DESTDIR)_images.tar.xz"
    IMAGES=( $(grep image: $DESTDIR/docker-compose.yml | awk '{print $2}' | sort -u) )
    if [[ "$MALCOLM_CONTAINER_RUNTIME" == "podman" ]]; then
      $MALCOLM_CONTAINER_RUNTIME save --multi-image-archive --format docker-archive "${IMAGES[@]}" | xz -1 > "$DESTNAMEIMAGES"
    else
      $MALCOLM_CONTAINER_RUNTIME save "${IMAGES[@]}" | xz -1 > "$DESTNAMEIMAGES"
    fi
    echo "Packaged Malcolm container images to \"$DESTNAMEIMAGES\""
    echo ""
  fi
  echo ""
  echo "To install Malcolm:" | tee -a "$README"
  echo "  1. Run install.py" | tee -a "$README"
  echo "  2. Follow the prompts" | tee -a "$README"
  echo "" | tee -a "$README"
  echo "To start, stop, restart, etc. Malcolm:" | tee -a "$README"
  echo "  Use the control scripts in the \"scripts/\" directory:" | tee -a "$README"
  echo "   - start       (start Malcolm)" | tee -a "$README"
  echo "   - stop        (stop Malcolm)" | tee -a "$README"
  echo "   - restart     (restart Malcolm)" | tee -a "$README"
  echo "   - logs        (monitor Malcolm logs)" | tee -a "$README"
  echo "   - wipe        (stop Malcolm and clear its database)" | tee -a "$README"
  echo "   - auth_setup  (change authentication-related settings)" | tee -a "$README"
  echo "" | tee -a "$README"
  echo "Malcolm services can be accessed at https://<IP or hostname>/" | tee -a "$README"
  popd  >/dev/null 2>&1
  popd  >/dev/null 2>&1
  popd  >/dev/null 2>&1
  popd  >/dev/null 2>&1
else
  echo "Unable to create temporary directory \"$DESTDIR\""
  popd  >/dev/null 2>&1
  popd  >/dev/null 2>&1
  exit 1
fi
