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
AWS_EXPOSE_ANNOTATIONS=(
    # see https://repost.aws/knowledge-center/eks-access-kubernetes-services (Option 1), step 2.
    "{\"service.beta.kubernetes.io/aws-load-balancer-backend-protocol\":\"tcp\"}"
    "{\"service.beta.kubernetes.io/aws-load-balancer-cross-zone-load-balancing-enabled\":\"true\"}"
    "{\"service.beta.kubernetes.io/aws-load-balancer-type\":\"external\"}"
    "{\"service.beta.kubernetes.io/aws-load-balancer-nlb-target-type\":\"instance\"}"
    "{\"service.beta.kubernetes.io/aws-load-balancer-scheme\":\"internet-facing\"}"
)
INGRESS_NGINX_CONTROLLER_VERSION=1.8.0
KUBECONFIG=
WORKDIR=
DRY_RUN=none
INGRESS_NGINX_PROVIDER=cloud
EXPOSE_VIA_AWS_LB=
SSL_PASSTHROUGH=
OTHER_TCP_SERVICES=

###############################################################################
# show script usage
function help() {
    echo -e "\n$(basename $0)\n"
    echo -e "-h                              display help\n"
    echo -e "-v                              enable bash verbosity\n"
    echo -e "-k kubeconfig                   kubeconfig file\n"
    echo -e "-d dryrunval                    --dry-run=dryrunval for kubectl apply (none|server|client)\n"
    echo -e "-i version                      ingress-nginx controller version"
    echo -e "                                    https://github.com/kubernetes/ingress-nginx/releases\n"
    echo -e "-a                              use AWS provider for ingress-nginx"
    echo -e " OR"
    echo -e "-p provider                     specify provider for ingress-nginx"
    echo -e "                                    https://github.com/kubernetes/ingress-nginx/tree/main/deploy/static/provider\n"
    echo -e "-e                              expose ingress-nginx via AWS load balancer (only applies to -a/-p aws)"
    echo -e "                                    https://repost.aws/knowledge-center/eks-access-kubernetes-services\n"
    echo -e "-s                              start ingress-nginx with --enable-ssl-passthrough"
    echo -e "                                    https://kubernetes.github.io/ingress-nginx/user-guide/tls/#ssl-passthrough\n"
    echo -e "-t                              start ingress-nginx with --tcp-services-configmap=ingress-nginx/tcp-services"
    echo -e "                                    https://kubernetes.github.io/ingress-nginx/user-guide/exposing-tcp-udp-services\n"
    exit 1
}

###############################################################################
# parse command-line parameters
while getopts 'vhaestp:d:k:i:' OPTION; do
    case "$OPTION" in

        v)
            VERBOSE_FLAG="-v"
            # set -x
            ;;

        d)
            DRY_RUN="${OPTARG}"
            ;;

        p)
            INGRESS_NGINX_PROVIDER="${OPTARG}"
            ;;

        a)
            INGRESS_NGINX_PROVIDER="aws"
            ;;

        e)
            EXPOSE_VIA_AWS_LB="true"
            ;;

        s)
            SSL_PASSTHROUGH="true"
            ;;

        t)
            OTHER_TCP_SERVICES="true"
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
    set +e
    if [[ -n "${WORKDIR}" ]] && [[ -d "${WORKDIR}" ]]; then
        popd >/dev/null >/dev/null 2>&1
        rm ${VERBOSE_FLAG} -r -f "${WORKDIR}" >/dev/null 2>&1
    fi
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

WORKDIR="$(mktemp -d -t malcolm-XXXXXX)"
pushd "${WORKDIR}" >/dev/null 2>&1

INGRESS_NGINX_DEPLOY_FILE_ORIG=ingress-nginx-orig.yaml
INGRESS_NGINX_DEPLOY_FILE_NEW=ingress-nginx-new.yaml

curl -fsSL -o "${INGRESS_NGINX_DEPLOY_FILE_ORIG}" "https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v${INGRESS_NGINX_CONTROLLER_VERSION}/deploy/static/provider/${INGRESS_NGINX_PROVIDER}/deploy.yaml"
yq --split-exp '"deploy_" + $index' --no-doc "${INGRESS_NGINX_DEPLOY_FILE_ORIG}"

readarray -d '' DEPLOY_FILES_SPLIT < <(printf '%s\0' deploy_*.yml | sort -zV)
for DEPLOY_FILE in "${DEPLOY_FILES_SPLIT[@]}"; do

    if (( $(yq 'select(.kind == "Deployment")' "${DEPLOY_FILE}" | wc -l) > 0 )); then

        if [[ "${SSL_PASSTHROUGH}" == "true" ]]; then
          yq -i '( select(.kind == "Deployment").spec.template.spec.containers[].args[] | select(contains("/nginx-ingress-controller")) | parent ) += ["--enable-ssl-passthrough"]' "${DEPLOY_FILE}"
        fi

        if [[ "${OTHER_TCP_SERVICES}" == "true" ]]; then
          yq -i '( select(.kind == "Deployment").spec.template.spec.containers[].args[] | select(contains("/nginx-ingress-controller")) | parent ) += ["--tcp-services-configmap=ingress-nginx/tcp-services"]' "${DEPLOY_FILE}"
          yq -i "( select(.kind == \"Deployment\").spec.template.spec.containers[].args[] | select(contains(\"/nginx-ingress-controller\")) | parent | parent | .ports ) += [${DEPLOYMENT_ADDITIONAL_PORTS}]" "${DEPLOY_FILE}"
        fi
    fi

    if (( $(yq 'select(.kind == "Service" and .spec.type == "LoadBalancer")' "${DEPLOY_FILE}" | wc -l) > 0 )); then

        if [[ "${OTHER_TCP_SERVICES}" == "true" ]]; then
            yq -i "( select(.kind == \"Service\" and .spec.type == \"LoadBalancer\").spec.ports ) += [${LOAD_BALANCER_ADDITIONAL_PORTS}]" "${DEPLOY_FILE}"
        fi

        if [[ "${EXPOSE_VIA_AWS_LB}" == "true" ]]; then
          # see https://repost.aws/knowledge-center/eks-access-kubernetes-services (Option 1), step 2.
          for OLDKEY in $(yq "select(.kind == \"Service\" and .spec.type == \"LoadBalancer\").metadata.annotations | keys | .[] | select(. == \"service.beta.kubernetes.io*\")" "${DEPLOY_FILE}"); do
            yq -i "( select(.kind == \"Service\" and .spec.type == \"LoadBalancer\") ) | del(.metadata.annotations.\"$OLDKEY\")" "${DEPLOY_FILE}"
          done
          for NEWKEY in ${AWS_EXPOSE_ANNOTATIONS[@]}; do
            yq -i "( select(.kind == \"Service\" and .spec.type == \"LoadBalancer\").metadata.annotations ) += ${NEWKEY}" "${DEPLOY_FILE}"
          done
        fi
    fi

    [[ -f "${INGRESS_NGINX_DEPLOY_FILE_NEW}" ]] && echo "---" >> "${INGRESS_NGINX_DEPLOY_FILE_NEW}"
    cat "${DEPLOY_FILE}" >> "${INGRESS_NGINX_DEPLOY_FILE_NEW}"

done

[[ -n "${VERBOSE_FLAG}" ]] && cat "${INGRESS_NGINX_DEPLOY_FILE_NEW}"

kubectl --kubeconfig "${KUBECONFIG}" apply --dry-run="${DRY_RUN}" -f "${INGRESS_NGINX_DEPLOY_FILE_NEW}"

exit 0