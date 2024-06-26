#!/bin/bash

# Copyright (c) 2024 Battelle Energy Alliance, LLC.  All rights reserved.

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
# release tag/branch can be overriden by specifying the branch name with after the URL delimited by a |
#
function zkg_install_github_repo() {
  URL_PARAM="$1"
  URL_BRANCH_DELIM='|'
  URL_BRANCH_DELIM_COUNT="$(awk -F"${URL_BRANCH_DELIM}" '{print NF-1}' <<< "${URL_PARAM}")"
  if (( $URL_BRANCH_DELIM_COUNT > 0 )); then
    REPO_URL="$(echo "$URL_PARAM" | cut -d'|' -f1)"
    BRANCH_OVERRIDE="$(echo "$URL_PARAM" | cut -d'|' -f2)"
  else
    REPO_URL="$URL_PARAM"
    BRANCH_OVERRIDE=""
  fi
  if [[ -n $REPO_URL ]]; then
    if [[ -n $BRANCH_OVERRIDE ]]; then
      REPO_LATEST_RELEASE="$BRANCH_OVERRIDE"
    else
      REPO_LATEST_RELEASE="$(get_latest_github_tagged_release "$REPO_URL")"
    fi
    if [[ -n $REPO_LATEST_RELEASE ]]; then
      zkg install --nodeps --force --skiptests --version "$REPO_LATEST_RELEASE" "$REPO_URL"
    else
      zkg install --nodeps --force --skiptests "$REPO_URL"
    fi
  fi
}

# don't consume as many resources when building spicy-analyzers, even if it's slower.
# https://github.com/zeek/spicy-analyzers/pull/60
export SPICY_ZKG_PROCESSES=1

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
  "https://github.com/cisagov/icsnpp-genisys"
  "https://github.com/cisagov/icsnpp-modbus"
  "https://github.com/cisagov/icsnpp-opcua-binary"
  "https://github.com/cisagov/icsnpp-profinet-io-cm"
  "https://github.com/cisagov/icsnpp-s7comm"
  "https://github.com/cisagov/icsnpp-synchrophasor"
  "https://github.com/corelight/callstranger-detector"
  "https://github.com/corelight/CVE-2020-16898"
  "https://github.com/corelight/CVE-2021-31166"
  "https://github.com/corelight/CVE-2021-38647"
  "https://github.com/corelight/CVE-2021-41773"
  "https://github.com/corelight/CVE-2021-42292"
  "https://github.com/corelight/cve-2021-44228"
  "https://github.com/corelight/cve-2022-22954"
  "https://github.com/corelight/cve-2022-26809"
  "https://github.com/corelight/CVE-2022-3602"
  "https://github.com/corelight/hassh"
  "https://github.com/corelight/http-more-files-names"
  "https://github.com/corelight/pingback"
  "https://github.com/corelight/ripple20"
  "https://github.com/corelight/SIGRed"
  "https://github.com/corelight/zeek-spicy-ipsec"
  "https://github.com/corelight/zeek-spicy-openvpn"
  "https://github.com/corelight/zeek-spicy-ospf"
  "https://github.com/corelight/zeek-spicy-stun"
  "https://github.com/corelight/zeek-spicy-wireguard"
  "https://github.com/corelight/zeek-xor-exe-plugin|master"
  "https://github.com/corelight/zerologon"
  "https://github.com/cybera/zeek-sniffpass"
  "https://github.com/FoxIO-LLC/ja4"
  "https://github.com/mmguero-dev/bzar"
  "https://github.com/ncsa/bro-is-darknet"
  "https://github.com/ncsa/bro-simple-scan"
  "https://github.com/precurse/zeek-httpattacks"
  "https://github.com/mmguero-dev/GQUIC_Protocol_Analyzer"
  "https://github.com/zeek/spicy-dhcp"
  "https://github.com/zeek/spicy-dns"
  "https://github.com/zeek/spicy-http"
  "https://github.com/zeek/spicy-pe"
  "https://github.com/zeek/spicy-tftp"
  "https://github.com/zeek/spicy-zip"
)
for i in ${ZKG_GITHUB_URLS[@]}; do
  zkg_install_github_repo "$i"
done

find "${ZEEK_DIR}"/lib/zeek/plugins/packages -type f -name "*.hlto" -exec chmod 755 "{}" \;

# plugins/packages/scripts that don't play nicely or need to be coddled
git clone \
  --single-branch --depth 1 --recurse-submodules --shallow-submodules \
  "https://github.com/cisagov/ACID" "${ZEEK_DIR}"/share/zeek/site/ACID
