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
LOAD_BALANCER_ADDITIONAL_PORTS="{\"appProtocol\": \"tcp\", \"name\": \"lumberjack\", \"port\": 5044, \"targetPort\": 5044, \"protocol\": \"TCP\"}, {\"appProtocol\": \"tcp\", \"name\": \"tcpjson\", \"port\": 5045, \"targetPort\": 5045, \"protocol\": \"TCP\"}, {\"appProtocol\": \"tcp\", \"name\": \"sftp\", \"port\": 8022, \"targetPort\": 8022, \"protocol\": \"TCP\"}, {\"appProtocol\": \"tcp\", \"name\": \"opensearch\", \"port\": 9200, \"targetPort\": 9200, \"protocol\": \"TCP\"}"
DEPLOYMENT_ADDITIONAL_PORTS="{\"name\": \"lumberjack\", \"containerPort\": 5044, \"protocol\": \"TCP\"}, {\"name\": \"tcpjson\", \"containerPort\": 5045, \"protocol\": \"TCP\"}, {\"name\": \"sftp\", \"containerPort\": 8022, \"protocol\": \"TCP\"}, {\"name\": \"opensearch\", \"containerPort\": 9200, \"protocol\": \"TCP\"}"
INGRESS_NGINX_CONTROLLER_VERSION=1.7.0
KUBECONFIG=
DEPLOY_YAML_FILE=
DRY_RUN=none

###############################################################################
# show script usage
function help() {
    echo -e "$(basename $0)\n" >&2
    echo "-v                              enable bash verbosity" >&2
    echo "-h                              display help" >&2
    echo "-k kubeconfig                   kubeconfig file" >&2
    echo "-d dryrunval                    --dry-run=dryrunval for kubectl (dryrunval=none|server|client)" >&2
    echo "-i version                      ingress-nginx controller version" >&2
    exit 1
}

###############################################################################
# parse command-line parameters
while getopts 'vhd:k:i:' OPTION; do
  case "$OPTION" in

    v)
      VERBOSE_FLAG="-v"
      set -x
      ;;

    d)
      DRY_RUN="${OPTARG}"
      ;;

    k)
      KUBECONFIG="${OPTARG}"
      ;;

    i)
      INGRESS_NGINX_CONTROLLER_VERSION="${OPTARG}"
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
    [[ -n "${DEPLOY_YAML_FILE}" ]] && [[ -f "${DEPLOY_YAML_FILE}" ]] && rm ${VERBOSE_FLAG} -f "${DEPLOY_YAML_FILE}"
}

if ! command -v curl >/dev/null 2>&1 || ! command -v yq >/dev/null 2>&1 || ! command -v kubectl >/dev/null 2>&1; then
    echo "$(basename $0) requires curl, kubectl and yq" >&2
    exit 1

elif [[ -z "${KUBECONFIG}" ]] || [[ ! -f "${KUBECONFIG}" ]]; then
    echo "$(basename $0) requires kubeconfig specified with -k" >&2
    exit 1
fi

###############################################################################

trap "cleanup" EXIT

DEPLOY_YAML_FILE="$(mktemp --suffix=.yaml)"

curl -fsSL -o "${DEPLOY_YAML_FILE}" "https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v${INGRESS_NGINX_CONTROLLER_VERSION}/deploy/static/provider/cloud/deploy.yaml"
yq -i '( select(.kind == "Deployment").spec.template.spec.containers[].args[] | select(contains("/nginx-ingress-controller")) | parent ) += ["--enable-ssl-passthrough", "--tcp-services-configmap=ingress-nginx/tcp-services"]' "${DEPLOY_YAML_FILE}"
yq -i "( select(.kind == \"Deployment\").spec.template.spec.containers[].args[] | select(contains(\"/nginx-ingress-controller\")) | parent | parent | .ports ) += [${DEPLOYMENT_ADDITIONAL_PORTS}]" "${DEPLOY_YAML_FILE}"
yq -i "( select(.kind == \"Service\" and .spec.type == \"LoadBalancer\").spec.ports ) += [${LOAD_BALANCER_ADDITIONAL_PORTS}]" "${DEPLOY_YAML_FILE}"

[[ -n "${VERBOSE_FLAG}" ]] && cat "${DEPLOY_YAML_FILE}"

kubectl --kubeconfig "${KUBECONFIG}" apply --dry-run="${DRY_RUN}" -f "${DEPLOY_YAML_FILE}"
