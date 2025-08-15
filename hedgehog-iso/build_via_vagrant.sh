#!/bin/bash

SCRIPT_PATH="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
unset SSH_AUTH_SOCK

function vm_state() {
  vagrant status --machine-readable | grep ",state," | egrep -o '([a-z_]*)$'
}

function vm_is_running() {
  STATE="$(vm_state)"
  if [[ "$STATE" == "running" ]] ; then
    return 0
  else
    return 1
  fi
}

function vm_execute() {
  echo "Running $1" >&2
  vagrant ssh --no-tty --command "$1"
}

function cleanup_shared_and_docs {
  rm -rf "$SCRIPT_PATH"/shared \
         "$SCRIPT_PATH"/docs \
         "$SCRIPT_PATH"/_config.yml \
         "$SCRIPT_PATH"/_includes \
         "$SCRIPT_PATH"/_layouts \
         "$SCRIPT_PATH"/Gemfile \
         "$SCRIPT_PATH"/README.md \
         "$SCRIPT_PATH"/suricata \
         "$SCRIPT_PATH"/nginx \
         "$SCRIPT_PATH"/htpdate
}

unset FORCE_PROVISION
while getopts 'f' OPTION; do
  case "$OPTION" in
    f)
      FORCE_PROVISION=0
      ;;
    ?)
      echo "script usage: $(basename $0) [-f]" >&2
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"

pushd "$SCRIPT_PATH"/vagrant

VM_NAME="$(grep "config.vm.box" Vagrantfile | tr -d "[:space:]" | sed "s/.*=//")"

if [[ -n $FORCE_PROVISION ]]; then
  echo "Destroying build machine to force provisioning..." >&2
  vagrant destroy -f
  sleep 1
fi

# make sure the VM is up and running, or start it otherwise
if ! vm_is_running; then
  echo "Starting build machine..." >&2
  vagrant up
  NEED_SHUTDOWN=true
  sleep 1
fi
until vm_is_running; do
  echo "Waiting for $VM_NAME..." >&2
  sleep 1
done
echo "$VM_NAME is running!" >&2

# make sure we can connect via SSH
echo "Checking SSH availability..." >&2
until vm_execute 'sudo whoami' | grep -q "root" ; do
  echo "Waiting for SSH availability..." >&2
  sleep 1
done
echo "SSH available." >&2

# need to make a temporary local copy of the ../shared directory and files for building documentation (and clean it up when we're done)
cleanup_shared_and_docs
cp -r "$SCRIPT_PATH"/../shared \
      "$SCRIPT_PATH"/../docs \
      "$SCRIPT_PATH"/../_config.yml \
      "$SCRIPT_PATH"/../_includes \
      "$SCRIPT_PATH"/../_layouts \
      "$SCRIPT_PATH"/../Gemfile \
      "$SCRIPT_PATH"/../malcolm-iso/htpdate \
      "$SCRIPT_PATH"/../README.md "$SCRIPT_PATH"/
cp "$SCRIPT_PATH"/../scripts/documentation_build.sh "$SCRIPT_PATH"/docs/
cp "$SCRIPT_PATH"/../scripts/malcolm_utils.py "$SCRIPT_PATH"/shared/bin/
mkdir "$SCRIPT_PATH"/nginx "$SCRIPT_PATH"/suricata
cp -r "$SCRIPT_PATH"/../suricata/rules-default "$SCRIPT_PATH"/suricata/
cp -r "$SCRIPT_PATH"/../nginx/landingpage/css "$SCRIPT_PATH"/nginx/
cp -r "$SCRIPT_PATH"/../nginx/landingpage/js "$SCRIPT_PATH"/nginx/

YML_IMAGE_VERSION="$(grep -P "^\s+image:.*/malcolm/" "$SCRIPT_PATH"/../docker-compose.yml | awk '{print $2}' | cut -d':' -f2 | uniq -c | sort -nr | awk '{print $2}' | head -n 1)"
[[ -n $YML_IMAGE_VERSION ]] && echo "$YML_IMAGE_VERSION" > "$SCRIPT_PATH"/shared/version.txt
[[ ${#MAXMIND_GEOIP_DB_LICENSE_KEY} -gt 1 ]] && echo "$MAXMIND_GEOIP_DB_LICENSE_KEY" > "$SCRIPT_PATH"/shared/maxmind_license.txt
[[ ${#MAXMIND_GEOIP_DB_ALTERNATE_DOWNLOAD_URL} -gt 1 ]] && echo "$MAXMIND_GEOIP_DB_ALTERNATE_DOWNLOAD_URL" > "$SCRIPT_PATH"/shared/maxmind_url.txt
[[ ${#ZEEK_DEB_ALTERNATE_DOWNLOAD_URL} -gt 1 ]] && echo "$ZEEK_DEB_ALTERNATE_DOWNLOAD_URL" > "$SCRIPT_PATH"/shared/zeek_url.txt
[[ ${#GITHUB_TOKEN} -gt 1 ]] && echo "GITHUB_TOKEN=$GITHUB_TOKEN" >> "$SCRIPT_PATH"/shared/environment.chroot
echo "VCS_REVSION=$( git rev-parse --short HEAD 2>/dev/null || echo main )" >> "$SCRIPT_PATH"/shared/environment.chroot
trap cleanup_shared_and_docs EXIT

# send source code to VM
vagrant rsync

# build ISO
vm_execute "sudo bash -c \"whoami && cd /sensor-build && pwd && ./build.sh\""

# retrieve build artifacts from VM
BUILD_ARTIFACTS="/sensor-build/hedgehog-*.*"
eval "$(vagrant ssh-config | awk '
/HostName/ {host=$2}
/Port/ {port=$2}
/User / {user=$2}
/IdentityFile/ {key=$2}
END {
    printf("V_HOST=%s\nV_PORT=%s\nV_USER=%s\nV_KEY=%s\n", host, port, user, key)
}')"
RSYNC_CMD=(
    rsync -av
    -e "ssh -p $V_PORT -i $V_KEY -o IdentityAgent=none -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    "$V_USER@$V_HOST:$BUILD_ARTIFACTS"
    "$SCRIPT_PATH"
)
"${RSYNC_CMD[@]}"

if [[ -n $NEED_SHUTDOWN ]]; then
  echo "Shutting down $VM_NAME..." >&2
  vagrant halt
  sleep 1
  while vm_is_running; do
    echo "Waiting for $VM_NAME to shutdown..." >&2
    sleep 1
  done
  echo "$VM_NAME is stopped." >&2
fi

popd
