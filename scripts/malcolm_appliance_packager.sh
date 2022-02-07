#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

if [ -z "$BASH_VERSION" ]; then
  echo "Wrong interpreter, please run \"$0\" with bash"
  exit 1
fi

set -e

DESTDIR="$(mktemp -d -t malcolm-XXXXXX)"
VERBOSE=""

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

CURRENT_REV_SHA="$(git rev-parse --short --verify HEAD)"
if [ -z "$CURRENT_REV_SHA" ]; then
  CURRENT_REV_TAG="$(date +%Y.%m.%d_%H:%M:%S)"
else
  CURRENT_REV_DATE="$(git log -1 --format="%at" | xargs -I{} date -d @{} +%Y%m%d_%H%M%S)"
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

  mkdir $VERBOSE -p "$DESTDIR/nginx/certs/"
  mkdir $VERBOSE -p "$DESTDIR/nginx/ca-trust/"
  mkdir $VERBOSE -p "$DESTDIR/htadmin/"
  mkdir $VERBOSE -p "$DESTDIR/logstash/certs/"
  mkdir $VERBOSE -p "$DESTDIR/logstash/maps/"
  mkdir $VERBOSE -p "$DESTDIR/filebeat/certs/"
  mkdir $VERBOSE -p "$DESTDIR/opensearch/nodes/"
  mkdir $VERBOSE -p "$DESTDIR/opensearch-backup/"
  mkdir $VERBOSE -p "$DESTDIR/arkime-raw/"
  mkdir $VERBOSE -p "$DESTDIR/arkime-logs/"
  mkdir $VERBOSE -p "$DESTDIR/pcap/upload/"
  mkdir $VERBOSE -p "$DESTDIR/pcap/processed/"
  mkdir $VERBOSE -p "$DESTDIR/yara/rules/"
  mkdir $VERBOSE -p "$DESTDIR/zeek/intel/STIX"
  mkdir $VERBOSE -p "$DESTDIR/zeek-logs/current/"
  mkdir $VERBOSE -p "$DESTDIR/zeek-logs/upload/"
  mkdir $VERBOSE -p "$DESTDIR/zeek-logs/processed/"
  mkdir $VERBOSE -p "$DESTDIR/zeek-logs/extract_files/"
  mkdir $VERBOSE -p "$DESTDIR/scripts/"
  cp $VERBOSE ./docker-compose-standalone.yml "$DESTDIR/docker-compose.yml"
  cp $VERBOSE ./auth.env "$DESTDIR/"
  cp $VERBOSE ./cidr-map.txt "$DESTDIR/"
  cp $VERBOSE ./host-map.txt "$DESTDIR/"
  cp $VERBOSE ./net-map.json "$DESTDIR/"
  cp $VERBOSE ./index-management-policy.json "$DESTDIR/"
  cp $VERBOSE ./scripts/install.py "$DESTDIR/scripts/"
  cp $VERBOSE ./scripts/control.py "$DESTDIR/scripts/"
  cp $VERBOSE ./scripts/malcolm_common.py "$DESTDIR/scripts/"
  cp $VERBOSE ./README.md "$DESTDIR/"
  cp $VERBOSE ./logstash/certs/*.conf "$DESTDIR/logstash/certs/"
  cp $VERBOSE ./logstash/maps/malcolm_severity.yaml "$DESTDIR/logstash/maps/"
  pushd "$DESTDIR" >/dev/null 2>&1
  pushd "./scripts" >/dev/null 2>&1
  ln -s ./control.py auth_setup
  ln -s ./control.py logs
  ln -s ./control.py restart
  ln -s ./control.py start
  ln -s ./control.py status
  ln -s ./control.py stop
  ln -s ./control.py wipe
  popd  >/dev/null 2>&1
  echo "You must set an administrator username and password for Malcolm, and self-signed X.509 certificates will be generated"
  ./scripts/auth_setup
  rm -rf logstash/certs/ca.key
  pushd .. >/dev/null 2>&1
  DESTNAME="$RUN_PATH/$(basename $DESTDIR).tar.gz"
  README="$RUN_PATH/$(basename $DESTDIR).README.txt"
  README_HTML="$RUN_PATH/$(basename $DESTDIR).README.html"
  docker run --rm --entrypoint /bin/bash "$(grep -E 'image: *malcolmnetsec/arkime' "$DESTDIR/docker-compose.yml" | awk '{print $2}')" -c "cat /opt/arkime/doc/README.html" > "$README_HTML" || true
  cp $VERBOSE "$SCRIPT_PATH/install.py" "$RUN_PATH/"
  cp $VERBOSE "$SCRIPT_PATH/malcolm_common.py" "$RUN_PATH/"
  tar -czf $VERBOSE "$DESTNAME" "./$(basename $DESTDIR)/"
  echo "Packaged Malcolm to \"$DESTNAME\""
  echo ""

  unset CONFIRMATION
  echo ""
  read -p "Do you need to package docker images also [y/N]? " CONFIRMATION
  CONFIRMATION=${CONFIRMATION:-N}
  if [[ $CONFIRMATION =~ ^[Yy]$ ]]; then
    echo "This might take a few minutes..."
    DESTNAMEIMAGES="$RUN_PATH/$(basename $DESTDIR)_images.tar.gz"
    IMAGES=( $(grep image: $DESTDIR/docker-compose.yml | awk '{print $2}') )
    docker save "${IMAGES[@]}" | gzip > "$DESTNAMEIMAGES"
    echo "Packaged Malcolm docker images to \"$DESTNAMEIMAGES\""
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
  echo "A minute or so after starting Malcolm, the following services will be accessible:" | tee -a "$README"
  echo "  - Arkime: https://localhost/" | tee -a "$README"
  echo "  - OpenSearch Dashboards: https://localhost/dashboards/" | tee -a "$README"
  echo "  - PCAP upload (web): https://localhost/upload/" | tee -a "$README"
  echo "  - PCAP upload (sftp): sftp://USERNAME@127.0.0.1:8022/files/" | tee -a "$README"
  echo "  - Host and subnet name mapping editor: https://localhost/name-map-ui/" | tee -a "$README"
  echo "  - Account management: https://localhost:488/" | tee -a "$README"
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
