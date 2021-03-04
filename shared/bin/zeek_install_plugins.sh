#!/bin/bash

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.

if [ -z "$BASH_VERSION" ]; then
  echo "Wrong interpreter, please run \"$0\" with bash"
  exit 1
fi

SPICY_DIR=${SPICY_DIR:-/opt/spicy}
ZEEK_DIR=${ZEEK_DIR:-/opt/zeek}

# some of the packages will install via zkg, so the zkg config file must be present
# read Zeek paths out of zkg config file for plugins that must be installed manually
ZKG_CONFIG_FILE="$ZEEK_DIR/etc/zkg/config"
if [[ -f "$ZKG_CONFIG_FILE" ]]; then
  ZEEK_SCRIPTS_DIR="$(grep -P "^script_dir\s*=\s*" "$ZKG_CONFIG_FILE" | sed 's/^script_dir[[:space:]]*=[[:space:]]*//')"
  ZEEK_DIST_DIR="$(grep -P "^zeek_dist\s*=\s*" "$ZKG_CONFIG_FILE" | sed 's/^zeek_dist[[:space:]]*=[[:space:]]*//')"
  ZEEK_PLUGIN_DIR="$(grep -P "^plugin_dir\s*=\s*" "$ZKG_CONFIG_FILE" | sed 's/^plugin_dir[[:space:]]*=[[:space:]]*//')"
else
  unset ZEEK_SCRIPTS_DIR
  unset ZEEK_DIST_DIR
  unset ZEEK_PLUGIN_DIR
fi
if [[ -z $ZEEK_SCRIPTS_DIR ]] || [[ -z $ZEEK_DIST_DIR ]]; then
  echo "Unable to determine Zeek scripts and/or source directory"
  exit 1
fi

# going to clone under /usr/local/src
SRC_BASE_DIR="/usr/local/src"
mkdir -p "$SRC_BASE_DIR"

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
# clone_github_repo
#
# clone the latest GitHub release tag if available (else, master/HEAD) under $SRC_BASE_DIR
# release tag/branch can be overriden by specifying the branch name with after the URL delimited by a |
#
function clone_github_repo() {
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
    SRC_DIR="$SRC_BASE_DIR"/"$(echo "$REPO_URL" | sed 's|.*/||')"
    rm -rf "$SRC_DIR"
    if [[ -n $REPO_LATEST_RELEASE ]]; then
      git -c core.askpass=true clone --single-branch --branch "$REPO_LATEST_RELEASE" --recursive --shallow-submodules "$REPO_URL" "$SRC_DIR" >/dev/null 2>&1
    else
      git -c core.askpass=true clone --single-branch --recursive --shallow-submodules "$REPO_URL" "$SRC_DIR" >/dev/null 2>&1
    fi
    [ $? -eq 0 ] && echo "$SRC_DIR" || echo "cloning \"$REPO_URL\" failed" >&2
  fi
}

# install Spicy (if not already installed)
if [[ ! -d "$SPICY_DIR" ]]; then
  SRC_DIR="$(clone_github_repo "https://github.com/zeek/spicy")"
  if [[ -d "$SRC_DIR" ]]; then
    CWD="$(pwd)"
    cd "$SRC_DIR" && \
      ./configure --generator=Ninja --prefix="$SPICY_DIR" --with-zeek="$ZEEK_DIR" --enable-ccache && \
      ninja -j 2 -C build install
    cd "$CWD"
  fi
fi

# install Zeek packages that install nicely using zkg

# TODO check failing unit tests during install for:
# - zeek-EternalSafety
# - cve-2020-0601

# TODO
# https://github.com/zeek/spicy-analyzers
# A collection of zeek-hosted spicy analyzers, some of which
# "replace" the built-in zeek parsers for those protocols.
# We need to compare the built-in ones, but use what we're used to until
# we make the decision with eyes open. As of 2021/03/04, that list is:
# - DHCP      - compare to Zeek DHCP
# - DNS       - compare to Zeek DNS
# - HTTP      - compare to Zeek HTTP
# - TFTP

ZKG_GITHUB_URLS=(
  "https://github.com/0xl3x1/zeek-EternalSafety"
  "https://github.com/0xxon/cve-2020-0601"
  "https://github.com/0xxon/cve-2020-13777"
  "https://github.com/corelight/callstranger-detector"
  "https://github.com/corelight/CVE-2020-16898"
  "https://github.com/corelight/ripple20"
  "https://github.com/corelight/SIGRed"
  "https://github.com/corelight/zeek-community-id"
  "https://github.com/corelight/zerologon"
  "https://github.com/corelight/zeek-openvpn"
  "https://github.com/cybera/zeek-sniffpass"
  "https://github.com/mitre-attack/bzar"
  "https://github.com/mmguero-dev/GQUIC_Protocol_Analyzer|topic/christian/zeek-4.0.0-fixes"
  "https://github.com/mmguero-dev/zeek-plugin-profinet|topic/zeek-4-compat"
  "https://github.com/mmguero-dev/zeek-plugin-s7comm|topic/zeek-4-compat"
  "https://github.com/mmguero-dev/zeek-plugin-tds|topic/zeek-4-compat"
  "https://github.com/precurse/zeek-httpattacks"
  "https://github.com/salesforce/hassh"
  "https://github.com/salesforce/ja3"
  "https://github.com/zeek/spicy-analyzers"
)
for i in ${ZKG_GITHUB_URLS[@]}; do
  SRC_DIR="$(clone_github_repo "$i")"
  [[ -d "$SRC_DIR" ]] && zkg install --force "$SRC_DIR"
done

# manual build processes that don't fit the other patterns

# TODO
# - there are still some issues with ldap-analyzer, getting some garbage output for some fields

MANUAL_ZEEK_GITHUB_URLS=(
  "https://github.com/cisagov/icsnpp-bacnet"
  "https://github.com/cisagov/icsnpp-bsap-ip"
  "https://github.com/cisagov/icsnpp-bsap-serial"
  "https://github.com/cisagov/icsnpp-enip"
  "https://github.com/corelight/bro-xor-exe-plugin"
  "https://github.com/mmguero-dev/ldap-analyzer|topic/zeek-4-compat"
)
for i in ${MANUAL_ZEEK_GITHUB_URLS[@]}; do
  SRC_DIR="$(clone_github_repo "$i")"
  if [[ -d "$SRC_DIR" ]]; then
    CWD="$(pwd)"
    cd "$SRC_DIR" && \
      ./configure --zeek-dist="$ZEEK_DIST_DIR" --install-root="$ZEEK_PLUGIN_DIR" && \
      make && \
      make install
    cd "$CWD"
  fi
done

ICSNPP_UPDATES_GITHUB_URLS=(
  "https://github.com/cisagov/icsnpp-dnp3"
  "https://github.com/cisagov/icsnpp-modbus"
)
for i in ${ICSNPP_UPDATES_GITHUB_URLS[@]}; do
  SRC_DIR="$(clone_github_repo "$i")"
  [[ -d "$SRC_DIR" ]] && cp -r "$SRC_DIR"/scripts/ "$ZEEK_DIR"/share/zeek/site/"$(basename "$SRC_DIR")"
done

SRC_DIR="$(clone_github_repo "https://github.com/J-Gras/zeek-af_packet-plugin|master")"
if [[ -d "$SRC_DIR" ]]; then
  CWD="$(pwd)"
  cd "$SRC_DIR" && \
    ./configure --with-kernel=/usr --install-root="$ZEEK_PLUGIN_DIR" && \
    make && \
    make install
  cd "$CWD"
fi
