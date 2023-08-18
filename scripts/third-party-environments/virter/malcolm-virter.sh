#!/usr/bin/env bash

set -o pipefail
set -u
shopt -s nocasematch
ENCODING="utf-8"

SCRIPT_PATH="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

MALCOLM_REPO_OWNER=idaholab
MALCOLM_REPO_NAME=Malcolm
MALCOLM_REPO_BRANCH=main
GITHUB_TOKEN=${GITHUB_TOKEN:-}

MALCOLM_CPU=${QEMU_CPU:-4}
MALCOLM_RAM=${QEMU_RAM:-16384}
MALCOLM_DISK=${QEMU_DISK:-50G}

MALCOLM_IMAGE=${QEMU_IMAGE:-debian-12}
MALCOLM_IMAGE_USER=${QEMU_USER:-debian}

VM_ID=$((120 + $RANDOM % 80))
VM_NAME="malcolm-${VM_ID}"
RM_AFTER_EXEC=

while getopts 'rvo:b:c:m:d:i:u:n:g:' OPTION; do
  case "$OPTION" in

    r)
      RM_AFTER_EXEC=0
      ;;

    v)
      set -x
      ;;

    o)
      MALCOLM_REPO_OWNER="$OPTARG"
      ;;

    b)
      MALCOLM_REPO_BRANCH="$OPTARG"
      ;;

    g)
      GITHUB_TOKEN="$OPTARG"
      ;;

    c)
      MALCOLM_CPU="$OPTARG"
      ;;

    m)
      MALCOLM_RAM="$OPTARG"
      ;;

    d)
      MALCOLM_DISK="$OPTARG"
      ;;

    i)
      MALCOLM_IMAGE="$OPTARG"
      ;;

    n)
      VM_NAME="$OPTARG"
      ;;

    u)
      MALCOLM_IMAGE_USER="$OPTARG"
      ;;

    ?)
      echo -e "\nscript usage: $(basename $0) OPTIONS"
      echo -e "Options:\n\t[-v (verbose)]\n\t[-c <CPUs>]\n\t[-m <RAM mebibytes>]\n\t[-d <disk size and units>]\n\t[-i <image name>]\n\t[-n <VM name>]\n\t[-u <default user>]\n\t[-o <Malcolm repo owner>]\n\t[-b <Malcolm repo branch>]\n\t[-g <GitHub token>]\n\t[-r (remove VM upon completion)]\n" >&2
      exit 1
      ;;

  esac
done
shift "$(($OPTIND -1))"

unset SSH_AUTH_SOCK

virter vm run "${MALCOLM_IMAGE}" \
  --id ${VM_ID} \
  --name "${VM_NAME}" \
  --vcpus ${MALCOLM_CPU} \
  --memory ${MALCOLM_RAM}MiB \
  --bootcapacity "${MALCOLM_DISK}" \
  --user "${MALCOLM_IMAGE_USER}" \
  --wait-ssh \
  "$@"

pushd "$SCRIPT_PATH" >/dev/null 2>&1
for SETUPFILE in malcolm-setup*.toml; do
    virter vm exec "${VM_NAME}" \
      --set "env.MALCOLM_REPO_OWNER=$MALCOLM_REPO_OWNER" \
      --set "env.MALCOLM_REPO_BRANCH=$MALCOLM_REPO_BRANCH" \
      --set "env.MALCOLM_REPO_NAME=$MALCOLM_REPO_NAME" \
      --set "env.GITHUB_TOKEN=$GITHUB_TOKEN" \
      --provision "${SETUPFILE}"
done
popd >/dev/null 2>&1

[[ -n "$RM_AFTER_EXEC" ]] && virter vm rm "${VM_NAME}"
