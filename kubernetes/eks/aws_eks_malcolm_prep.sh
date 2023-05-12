#!/usr/bin/env bash

if [ -z "$BASH_VERSION" ]; then
  echo "Wrong interpreter, please run \"$0\" with bash" >&2
  exit 1
fi

###############################################################################
# script options
set -o pipefail
set -e
shopt -s nocasematch
ENCODING="utf-8"

###############################################################################
# script variables
VERBOSE_FLAG=
DRY_RUN=none
REGION=us-east-1
CLUSTER_NAME=

###############################################################################
# show script usage
function help() {
    echo -e "$(basename $0)\n"
    echo "-v                              enable bash verbosity"
    echo "-c cluster-name                 cluster name"
    echo "-d dryrunval                    --dry-run=dryrunval for kubectl (dryrunval=none|server|client)"
    echo "-r region                       region code (default: us-east-1)"
    exit 1
}

###############################################################################
# parse command-line parameters
while getopts 'vc:d:' OPTION; do
  case "$OPTION" in

    v)
      VERBOSE_FLAG="-v"
      set -x
      ;;

    c)
      CLUSTER_NAME="${OPTARG}"
      ;;

    d)
      DRY_RUN="${OPTARG}"
      ;;

    ?)
      help >&2
      exit 1;
      ;;

  esac
done
shift "$(($OPTIND -1))"

###############################################################################
function cleanup {
    true
}

if ! command -v aws >/dev/null 2>&1 || ! command -v eksctl >/dev/null 2>&1 || ! command -v kubectl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
    echo "$(basename $0) requires aws, eksctl kubectl and jq" >&2
    exit 1
fi

###############################################################################

if [[ -z "${CLUSTER_NAME}" ]]; then
  echo "Please specify -c cluster-name" >&2
  help >&2
  exit 1
fi

ACCOUNT="$(aws --output=json sts get-caller-identity | jq -r '.Account')"
if [[ -z "${ACCOUNT}" ]]; then
  echo "Could not get account ID from aws sts get-caller-identity" >&2
  exit 1
fi
[[ -n "${VERBOSE_FLAG}" ]] && echo "Account ID: ${ACCOUNT}"

trap "cleanup" EXIT
