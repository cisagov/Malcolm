#!/usr/bin/env bash

# clone some repositories of YARA rules and symlink to them from another directory

set -u
set -o pipefail

ENCODING="utf-8"

RUN_PATH="$(pwd)"
[[ "$(uname -s)" = 'Darwin' ]] && REALPATH=grealpath || REALPATH=realpath
if ! command -v "$REALPATH" >/dev/null 2>&1 || ! command -v git >/dev/null 2>&1; then
  echo "$(basename "${BASH_SOURCE[0]}") requires $REALPATH and git" >&2
  exit 1
fi

VERBOSE_FLAG=
YARA_RULES_SRC_DIR=${YARA_RULES_SRC_DIR:-"/yara-rules-src"}
YARA_RULES_DIR=${YARA_RULES_DIR:-"/yara-rules"}
while getopts 'vr:y:' OPTION; do
  case "$OPTION" in
    v)
      VERBOSE_FLAG="-v"
      set -x
      ;;

    r)
      YARA_RULES_SRC_DIR="$OPTARG"
      ;;

    y)
      YARA_RULES_DIR="$OPTARG"
      ;;

    ?)
      echo "script usage: $(basename $0) [-v (verbose)] [-n (non-interactive)] [-s <parent directory of repositories>] [-y <directory for rule symlinks>]" >&2
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"

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
  if [[ "$LATEST_URL" == "$REDIRECT_URL"/latest ]]; then
    echo ""
  else
    echo "$REDIRECT_URL" | sed 's|.*tag/||'
  fi
}

#
# clone_github_repo
#
# clone the latest GitHub release tag if available (else, master/HEAD) under ./
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
    SRC_DIR=./"$(echo "$REPO_URL" | sed 's|.*/\(.*\)/\(.*\)|\1_\2|')"
    rm $VERBOSE_FLAG -r -f "$SRC_DIR" >&2
    if [[ -n $REPO_LATEST_RELEASE ]]; then
      git -c core.askpass=true clone --depth=1 --single-branch --branch "$REPO_LATEST_RELEASE" --recursive --shallow-submodules "$REPO_URL" "$SRC_DIR" >&2
    else
      git -c core.askpass=true clone --depth=1 --single-branch --recursive --shallow-submodules "$REPO_URL" "$SRC_DIR" >&2
    fi
    [ $? -eq 0 ] && echo "$SRC_DIR" || echo "cloning \"$REPO_URL\" failed" >&2
  fi
}

mkdir -p "$YARA_RULES_SRC_DIR" "$YARA_RULES_DIR"

# clone yara rules and create symlinks in destination directory
pushd "$YARA_RULES_SRC_DIR" >/dev/null 2>&1
YARA_RULE_GITHUB_URLS=(
  "https://github.com/bartblaze/Yara-rules|master"
  "https://github.com/Neo23x0/signature-base|master"
  "https://github.com/reversinglabs/reversinglabs-yara-rules|develop"
)
for i in ${YARA_RULE_GITHUB_URLS[@]}; do
  SRC_DIR="$(clone_github_repo "$i")"
  if [[ -d "$SRC_DIR" ]]; then
    find "$SRC_DIR" -type f \( -iname '*.yara' -o -iname '*.yar' \) -print0 | xargs -0 -r -I XXX ln $VERBOSE_FLAG -s -f "$("$REALPATH" "XXX")" "$YARA_RULES_DIR"/
  fi
done
popd >/dev/null 2>&1

# remove broken symlinks from destination directory
pushd "$YARA_RULES_DIR" >/dev/null 2>&1
find . -type l ! -exec test -r {} \; -print0 | xargs -0 -r -I XXX rm $VERBOSE_FLAG -f "XXX"
popd >/dev/null 2>&1