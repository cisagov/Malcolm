#!/bin/bash

unset SSH_AUTH_SOCK
unset FORCE_PROVISION
DOCKER_IMAGES_TGZ=""
while getopts fd: opts; do
   case ${opts} in
      d) DOCKER_IMAGES_TGZ=${OPTARG} ;;
      f) FORCE_PROVISION=0 ;;
   esac
done

SCRIPT_PATH="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

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

function cleanup_shared {
  rm -rf "$SCRIPT_PATH"/shared
}

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

# pass a few things across to the vagrant environment in a "shared" directory (and clean it up when done)
cleanup_shared
mkdir -p "$SCRIPT_PATH"/shared
[[ ${#GITHUB_TOKEN} -gt 1 ]] && echo "GITHUB_TOKEN=$GITHUB_TOKEN" >> "$SCRIPT_PATH"/shared/environment.chroot
trap cleanup_shared EXIT

if [[ -r "$DOCKER_IMAGES_TGZ" ]]; then
  DOCKER_IMAGES_LOCAL="$SCRIPT_PATH/../$(basename "$DOCKER_IMAGES_TGZ")"
  DOCKER_IMAGES_TGZ_REMOTE="/malcolm-build/$(basename "$DOCKER_IMAGES_TGZ")"
  cp -v "$DOCKER_IMAGES_TGZ" "$DOCKER_IMAGES_LOCAL"
else
  DOCKER_IMAGES_LOCAL=""
  DOCKER_IMAGES_TGZ_REMOTE=""
fi

vm_execute "sudo bash -c \"whoami && cd /malcolm-build/malcolm-iso && pwd && ./build.sh -d \\\"$DOCKER_IMAGES_TGZ_REMOTE\\\"\""

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

[[ -r "$DOCKER_IMAGES_LOCAL" ]] && rm -vf "$DOCKER_IMAGES_LOCAL"

popd
