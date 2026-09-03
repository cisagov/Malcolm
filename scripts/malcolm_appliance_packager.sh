#!/usr/bin/env bash

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

if [[ -z "${BASH_VERSION:-}" ]]; then
  echo "Wrong interpreter, please run \"$0\" with bash"
  exit 1
fi

set -e

VERBOSE="-v"

# force-navigate to Malcolm base directory (parent of scripts/ directory)
RUN_PATH="$(pwd)"

# Prefer GNU tools everywhere (use g*-prefixed on macOS, plain on Linux)
if [[ "$(uname -s)" == Darwin ]]; then
  AWK=gawk
  BASENAME=gbasename
  CHMOD=gchmod
  CP=gcp
  DATE=gdate
  DIRNAME=gdirname
  GREP=ggrep
  LN=gln
  MKDIR=gmkdir
  MKTEMP=gmktemp
  REALPATH=grealpath
  RM=grm
  SORT=gsort
  TAR=gtar
  TEE=gtee
  TOUCH=gtouch
  XARGS=gxargs
else
  AWK=awk
  BASENAME=basename
  CHMOD=chmod
  CP=cp
  DATE=date
  DIRNAME=dirname
  GREP=grep
  LN=ln
  MKDIR=mkdir
  MKTEMP=mktemp
  REALPATH=realpath
  RM=rm
  SORT=sort
  TAR=tar
  TEE=tee
  TOUCH=touch
  XARGS=xargs
fi

required=(
  git xz rsync
  "$AWK" "$BASENAME" "$CHMOD" "$CP" "$DATE" "$DIRNAME" "$GREP" "$LN" "$MKDIR"
  "$MKTEMP" "$REALPATH" "$RM" "$SORT" "$TAR" "$TEE" "$TOUCH" "$XARGS"
)

missing=()
for cmd in "${required[@]}"; do
  command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
done
if ((${#missing[@]})); then
  echo "$("$BASENAME" "${BASH_SOURCE[0]}") requires: ${missing[*]}"
  exit 1
fi

SCRIPT_PATH="$("$DIRNAME" "$("$REALPATH" -e "${BASH_SOURCE[0]}")")"
pushd "$SCRIPT_PATH/.." >/dev/null 2>&1
MALCOLM_CONTAINER_RUNTIME="${MALCOLM_CONTAINER_RUNTIME:-docker}"

CURRENT_REV_SHA="$(git rev-parse --short --verify HEAD 2>/dev/null || true)"
if [[ -z "$CURRENT_REV_SHA" ]]; then
  CURRENT_REV_TAG="$("$DATE" +%Y.%m.%d_%H:%M:%S)"
else
  CURRENT_REV_DATE="$(git log -1 --format="%at" | "$XARGS" -I{} "$DATE" -d @{} +%Y%m%d_%H%M%S)"
  if [[ -z "$CURRENT_REV_DATE" ]]; then
    CURRENT_REV_DATE="$("$DATE" +%Y.%m.%d_%H:%M:%S)"
  fi
  CURRENT_REV_TAG="${CURRENT_REV_DATE}_${CURRENT_REV_SHA}"
fi

DESTDIR="${TMPDIR:-/tmp}/malcolm_${CURRENT_REV_TAG}"
if [[ -d "$DESTDIR" ]]; then
  unset CONFIRMATION
  echo ""
  read -p "Temporary directory \"$DESTDIR\" exists, delete before proceeding? [y/N]? " CONFIRMATION
  CONFIRMATION=${CONFIRMATION:-N}
  if [[ $CONFIRMATION =~ ^[Yy]$ ]]; then
    "$RM" -rf "$DESTDIR"
  else
    echo "Aborting"
    popd >/dev/null 2>&1
    popd >/dev/null 2>&1
    exit 1
  fi
fi

cleanup() {
  if ! "$RM" -rf "$DESTDIR"; then
    echo "Failed to remove temporary directory '$DESTDIR'"
    exit 1
  fi
}

if "$MKDIR" "$DESTDIR"; then
  # ensure that if we "grabbed a lock", we release it (works for clean exit, SIGTERM, and SIGINT/Ctrl-C)
  trap cleanup EXIT

  "$MKDIR" $VERBOSE -p "$DESTDIR/arkime/etc/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/arkime/parsers/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/arkime/rules/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/config/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/filebeat/certs/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/filescan-logs"
  "$MKDIR" $VERBOSE -p "$DESTDIR/htadmin/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/kubernetes/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/logstash/certs/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/logstash/maps/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/netbox/custom-plugins/requirements/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/netbox/custom-scripts/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/netbox/media/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/netbox/preload/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/nginx/ca-trust/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/nginx/certs/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/opensearch-backup/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/opensearch/nodes/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/pcap/arkime-live/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/pcap/processed/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/pcap/upload/tmp/spool"
  "$MKDIR" $VERBOSE -p "$DESTDIR/pcap/upload/variants/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/postgres/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/valkey/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/scripts/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/strelka/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/suricata-logs/live/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/suricata/include-configs/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/suricata/rules/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/yara/rules/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/zeek-logs/current/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/zeek-logs/extract_files/filescan/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/zeek-logs/live/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/zeek-logs/processed/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/zeek-logs/upload/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/zeek/custom/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/zeek/intel/Google/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/zeek/intel/Mandiant/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/zeek/intel/MISP/"
  "$MKDIR" $VERBOSE -p "$DESTDIR/zeek/intel/STIX/"

  git ls-files -z ./config/*.example | "$XARGS" -0 -I{} "$CP" $VERBOSE "{}" "$DESTDIR/config/"
  git ls-files -z ./config/*.yml | "$XARGS" -0 -I{} "$CP" $VERBOSE "{}" "$DESTDIR/config/"
  "$CP" $VERBOSE ./docker-compose.yml "$DESTDIR/docker-compose.yml"
  "$CP" $VERBOSE ./.justfile "$DESTDIR/.justfile"
  "$CP" $VERBOSE ./.envrc.example "$DESTDIR/.envrc.example"
  git ls-files -z ./kubernetes/*.* | "$XARGS" -0 -I{} "$CP" $VERBOSE "{}" "$DESTDIR/kubernetes/"
  "$CP" $VERBOSE ./README.md "$DESTDIR/"
  "$CP" $VERBOSE ./arkime/etc/wise.ini.example "$DESTDIR/arkime/etc/"
  git ls-files -z ./arkime/rules/*.yml | "$XARGS" -0 -I{} "$CP" $VERBOSE "{}" "$DESTDIR/arkime/rules/"
  "$CP" $VERBOSE ./logstash/maps/malcolm_severity.yaml "$DESTDIR/logstash/maps/"
  git ls-files ./netbox/config | rsync -R --files-from=- ./ "$DESTDIR/"
  git ls-files -z ./netbox/preload/*.yml | "$XARGS" -0 -I{} "$CP" $VERBOSE "{}" "$DESTDIR/netbox/preload/"
  git ls-files ./strelka/config | rsync -R --files-from=- ./ "$DESTDIR/"
  "$CP" $VERBOSE ./scripts/tx-rx-secure.sh "$DESTDIR/scripts/"
  "$CP" $VERBOSE ./scripts/control.py "$DESTDIR/scripts/"

  # these scripts go in both the tarball and the run path
  "$CP" $VERBOSE ./scripts/install.py "$DESTDIR/scripts/"
  "$CP" $VERBOSE ./scripts/install.py "$RUN_PATH/"
  git ls-files ./scripts/installer | rsync -R --files-from=- ./ "$DESTDIR/"
  "$RM" -rf "$DESTDIR/scripts/installer/tests" "$DESTDIR/scripts/installer/ui/gui"
  pushd "./scripts" >/dev/null 2>&1
  git ls-files ./installer | rsync -R --files-from=- ./ "$RUN_PATH/"
  "$RM" -rf "$RUN_PATH/installer/tests" "$RUN_PATH/installer/ui/gui"
  popd >/dev/null 2>&1

  "$CP" $VERBOSE ./scripts/malcolm_common.py "$DESTDIR/scripts/"
  "$CP" $VERBOSE ./scripts/malcolm_common.py "$RUN_PATH/"
  "$CP" $VERBOSE ./scripts/malcolm_constants.py "$DESTDIR/scripts/"
  "$CP" $VERBOSE ./scripts/malcolm_constants.py "$RUN_PATH/"
  "$CP" $VERBOSE ./scripts/malcolm_kubernetes.py "$DESTDIR/scripts/"
  "$CP" $VERBOSE ./scripts/malcolm_kubernetes.py "$RUN_PATH/"
  "$CP" $VERBOSE ./scripts/malcolm_utils.py "$DESTDIR/scripts/"
  "$CP" $VERBOSE ./scripts/malcolm_utils.py "$RUN_PATH/"
  "$CP" $VERBOSE ./scripts/package_zeek_logs.sh "$DESTDIR/scripts/"

  pushd "$DESTDIR" >/dev/null 2>&1
  "$TOUCH" ./.opensearch.primary.curlrc ./.opensearch.secondary.curlrc
  "$CHMOD" 600 ./.opensearch.primary.curlrc ./.opensearch.secondary.curlrc
  pushd "./scripts" >/dev/null 2>&1
  "$LN" -sf ./control.py auth_setup
  "$LN" -sf ./control.py logs
  "$LN" -sf ./control.py netbox-backup
  "$LN" -sf ./control.py netbox-restore
  "$LN" -sf ./control.py restart
  "$LN" -sf ./control.py start
  "$LN" -sf ./control.py status
  "$LN" -sf ./control.py stop
  "$LN" -sf ./control.py wipe
  "$LN" -sf ./install.py configure
  popd >/dev/null 2>&1

  pushd .. >/dev/null 2>&1
  DESTNAME="$RUN_PATH/$("$BASENAME" "$DESTDIR").tar.gz"
  README="$RUN_PATH/$("$BASENAME" "$DESTDIR").README.txt"

  "$TAR" $VERBOSE --numeric-owner --owner=0 --group=0 -czf "$DESTNAME" "./$("$BASENAME" "$DESTDIR")/"
  echo "Packaged Malcolm to \"$DESTNAME\""

  unset CONFIRMATION
  echo ""
  read -p "Do you need to package container images also [m/h/N]? " CONFIRMATION
  CONFIRMATION=${CONFIRMATION:-N}
  if [[ $CONFIRMATION =~ ^[YyMmHh]$ ]]; then
    [[ $CONFIRMATION =~ ^[Hh]$ ]] && IMAGE_PROFILE=hedgehog || IMAGE_PROFILE=malcolm
    echo "This might take a few minutes..."
    DESTNAMEIMAGES="$RUN_PATH/$("$BASENAME" "$DESTDIR")_images.tar.xz"
    if command -v yq >/dev/null 2>&1; then
      IMAGES=( $(yq ".services[] | select((.profiles // []) | contains([\"$IMAGE_PROFILE\"])) | .image" $DESTDIR/docker-compose.yml | "$SORT" -u) )
    else
      IMAGES=( $("$GREP" 'image:' "$DESTDIR/docker-compose.yml" | "$AWK" '{print $2}' | "$SORT" -u) )
    fi
    if [[ "$MALCOLM_CONTAINER_RUNTIME" == "podman" ]]; then
      "$MALCOLM_CONTAINER_RUNTIME" save --multi-image-archive --format docker-archive "${IMAGES[@]}" | xz -1 >"$DESTNAMEIMAGES"
    else
      "$MALCOLM_CONTAINER_RUNTIME" save "${IMAGES[@]}" | xz -1 >"$DESTNAMEIMAGES"
    fi
    echo "Packaged Malcolm container images to \"$DESTNAMEIMAGES\""
    echo ""
  fi

  echo ""
  echo "To install and configure Malcolm, run install.py" | "$TEE" -a "$README"
  echo "" | "$TEE" -a "$README"
  echo "To start, stop, restart, etc. Malcolm:" | "$TEE" -a "$README"
  echo "  Use the control scripts in the \"scripts/\" directory:" | "$TEE" -a "$README"
  echo "   - start       (start Malcolm)" | "$TEE" -a "$README"
  echo "   - stop        (stop Malcolm)" | "$TEE" -a "$README"
  echo "   - restart     (restart Malcolm)" | "$TEE" -a "$README"
  echo "   - logs        (monitor Malcolm logs)" | "$TEE" -a "$README"
  echo "   - wipe        (stop Malcolm and clear its database)" | "$TEE" -a "$README"
  echo "   - auth_setup  (change authentication-related settings)" | "$TEE" -a "$README"
  echo "" | "$TEE" -a "$README"
  echo "Malcolm services can be accessed at https://<IP or hostname>/" | "$TEE" -a "$README"

  popd >/dev/null 2>&1
  popd >/dev/null 2>&1
  popd >/dev/null 2>&1
else
  echo "Unable to create temporary directory \"$DESTDIR\""
  popd >/dev/null 2>&1
  exit 1
fi
