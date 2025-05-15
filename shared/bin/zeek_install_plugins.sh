#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

if [ -z "$BASH_VERSION" ]; then
  echo "Wrong interpreter, please run \"$0\" with bash"
  exit 1
fi

ZEEK_DIR=${ZEEK_DIR:-/opt/zeek}

#
# get_latest_github_tagged_release
#
# get the latest GitHub release tag name given a github repo URL
#
function get_latest_github_tagged_release() {
  REPO_URL="$1"
  REPO_NAME="$(echo "$REPO_URL" | sed 's|.*github\.com/||')"
  LATEST_URL="https://github.com/$REPO_NAME/releases/latest"
  REDIRECT_URL="$(curl -fsSLI -o /dev/null -w %{url_effective} "$LATEST_URL" 2>/dev/null)"
  if [[ "$LATEST_URL" = "$REDIRECT_URL"/latest ]]; then
    echo ""
  else
    echo "$REDIRECT_URL" | sed 's|.*tag/||'
  fi
}

#
# zkg_install_github_repo
#
# zkg install the latest GitHub release tag if available (else, master/HEAD)
# some optional overrides can be specified using | as a delimiter in the URL parameter:
#   URL|branch|environment variables
#   URL - the full GitHub URL to install
#   branch - the branch to checkout and install (otherwise, the latest release tag will be used, or the default branch if no releases exist)
#   environment variables - semicolon-separated list of environment variables to set before calling zkg (e.g., CMAKE_BUILD_TYPE=Debug;HILTI_CXX_FLAGS=-fno-var-tracking-assignments)
function zkg_install_github_repo() {
  URL_PARAM="$1"
  URL_DELIM='|'
  URL_DELIM_COUNT="$(awk -F"${URL_DELIM}" '{print NF-1}' <<< "${URL_PARAM}")"
  REPO_URL=""
  BRANCH_OVERRIDE=""
  ENV_LIST=""
  if (( $URL_DELIM_COUNT >= 0 )); then
    REPO_URL="$(echo "$URL_PARAM" | cut -d'|' -f1)"
  fi
  if (( $URL_DELIM_COUNT >= 1 )); then
    BRANCH_OVERRIDE="$(echo "$URL_PARAM" | cut -d'|' -f2)"
  fi
  if (( $URL_DELIM_COUNT >= 2 )); then
    ENV_LIST="$(echo "$URL_PARAM" | cut -d'|' -f3)"
  fi
  if [[ -n $REPO_URL ]]; then
    if [[ -n $BRANCH_OVERRIDE ]]; then
      REPO_LATEST_RELEASE="$BRANCH_OVERRIDE"
    else
      REPO_LATEST_RELEASE="$(get_latest_github_tagged_release "$REPO_URL")"
    fi
    if [[ -n $ENV_LIST ]]; then
      IFS=';' read -ra ENVS <<< "${ENV_LIST}"
      for ENV in "${ENVS[@]}"; do
        export "$ENV"
      done
    fi
    EXTRA_ZKG_PARAMS=()
    if [[ "$REPO_URL" =~ "zeek-kafka" ]]; then
      EXTRA_ZKG_PARAMS+=( --user-var )
      EXTRA_ZKG_PARAMS+=( LIBRDKAFKA_ROOT=/usr/include/librdkafka )
    fi
    if [[ -n $REPO_LATEST_RELEASE ]]; then
      zkg install --nodeps --force --skiptests "${EXTRA_ZKG_PARAMS[@]}" --version "$REPO_LATEST_RELEASE" "$REPO_URL"
    else
      zkg install --nodeps --force --skiptests "${EXTRA_ZKG_PARAMS[@]}" "$REPO_URL"
    fi
  fi
}

# don't consume as many resources when building spicy analyzers, even if it's slower.
# https://docs.zeek.org/projects/spicy/en/latest/toolchain.html
TOTAL_CPUS="$(nproc --all 2>/dev/null || echo '1')"
TOTAL_CPUS=$(( TOTAL_CPUS / 2 ))
(( $TOTAL_CPUS <= 0 )) && TOTAL_CPUS=1
export HILTI_JIT_PARALLELISM=${BUILD_JOBS:-$TOTAL_CPUS}

# install Zeek packages that install nicely using zkg
ZKG_GITHUB_URLS=(
  "https://github.com/0xl3x1/zeek-EternalSafety"
  "https://github.com/0xxon/cve-2020-0601"
  "https://github.com/0xxon/cve-2020-13777"
  "https://github.com/amzn/zeek-plugin-profinet|master"
  "https://github.com/amzn/zeek-plugin-tds|master"
  "https://github.com/cisagov/icsnpp-bacnet"
  "https://github.com/cisagov/icsnpp-bsap"
  "https://github.com/cisagov/icsnpp-dnp3"
  "https://github.com/cisagov/icsnpp-enip"
  "https://github.com/cisagov/icsnpp-ethercat"
  "https://github.com/cisagov/icsnpp-ge-srtp"
  "https://github.com/cisagov/icsnpp-genisys"
  "https://github.com/cisagov/icsnpp-hart-ip"
  "https://github.com/cisagov/icsnpp-modbus"
  "https://github.com/cisagov/icsnpp-omron-fins"
  "https://github.com/cisagov/icsnpp-opcua-binary"
  "https://github.com/mmguero-dev/icsnpp-profinet-io-cm"
  "https://github.com/cisagov/icsnpp-roc-plus"
  "https://github.com/cisagov/icsnpp-s7comm"
  "https://github.com/cisagov/icsnpp-synchrophasor"
  "https://github.com/corelight/callstranger-detector"
  "https://github.com/corelight/CVE-2020-16898"
  "https://github.com/corelight/CVE-2021-1675"
  "https://github.com/corelight/CVE-2021-31166"
  "https://github.com/corelight/CVE-2021-38647"
  "https://github.com/corelight/CVE-2021-41773"
  "https://github.com/corelight/CVE-2021-42292"
  "https://github.com/corelight/cve-2021-44228"
  "https://github.com/corelight/cve-2022-21907"
  "https://github.com/corelight/cve-2022-22954"
  "https://github.com/corelight/CVE-2022-23270-PPTP"
  "https://github.com/corelight/CVE-2022-24491"
  "https://github.com/corelight/CVE-2022-24497"
  "https://github.com/corelight/cve-2022-26809"
  "https://github.com/corelight/CVE-2022-26937"
  "https://github.com/corelight/CVE-2022-30216"
  "https://github.com/corelight/CVE-2022-3602"
  "https://github.com/corelight/hassh"
  "https://github.com/corelight/http-more-files-names"
  "https://github.com/corelight/pingback"
  "https://github.com/corelight/ripple20"
  "https://github.com/corelight/SIGRed"
  "https://github.com/corelight/zeek-agenttesla-detector"
  "https://github.com/corelight/zeek-asyncrat-detector"
  "https://github.com/corelight/zeek-long-connections|master"
  "https://github.com/corelight/zeek-netsupport-detector"
  "https://github.com/corelight/zeek-quasarrat-detector"
  "https://github.com/corelight/zeek-spicy-ipsec"
  "https://github.com/corelight/zeek-spicy-openvpn"
  "https://github.com/corelight/zeek-spicy-ospf|master"
  "https://github.com/corelight/zeek-spicy-stun"
  "https://github.com/corelight/zeek-spicy-wireguard"
  "https://github.com/corelight/zeek-strrat-detector"
  "https://github.com/corelight/zeek-xor-exe-plugin|master"
  "https://github.com/corelight/zerologon"
  "https://github.com/cybera/zeek-sniffpass"
  "https://github.com/FoxIO-LLC/ja4|main"
  "https://github.com/mmguero-dev/bzar"
  "https://github.com/mmguero-dev/GQUIC_Protocol_Analyzer"
  "https://github.com/ncsa/bro-is-darknet"
  "https://github.com/ncsa/bro-simple-scan"
  "https://github.com/precurse/zeek-httpattacks"
  "https://github.com/SeisoLLC/zeek-kafka"
  "https://github.com/zeek/spicy-tftp|main"
  "https://github.com/zeek/spicy-zip|main"
)

for i in ${ZKG_GITHUB_URLS[@]}; do
  zkg_install_github_repo "$i"
done

find "${ZEEK_DIR}"/lib/zeek/plugins/packages -type f -name "*.hlto" -exec chmod 755 "{}" \;

# plugins/packages/scripts that don't play nicely or need to be coddled
git clone \
  --single-branch --depth 1 --recurse-submodules --shallow-submodules \
  "https://github.com/cisagov/ACID" "${ZEEK_DIR}"/share/zeek/site/ACID

# one-off packages from local build
if [[ -d "$ZEEK_DIR"/custom-pkg ]]; then
  while IFS= read -r -d '' PKGDIR; do
    pushd "$PKGDIR" >/dev/null 2>&1
    if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      git init
      git add .
      git config --global user.email "nobody@example.com"
      git config --global user.name "nobody"
      git commit -m "initial commit"
    fi
    zkg install --nodeps --force --skiptests .
    popd >/dev/null 2>&1
  done < <(find "$ZEEK_DIR"/custom-pkg -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)
fi