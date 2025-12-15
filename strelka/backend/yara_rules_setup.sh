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
YARA_COMPILED_RULES_FILE=${YARA_COMPILED_RULES_FILE:-"rules.compiled"}
[[ "${RULES_UPDATE_ENABLED:-false}" == "true" ]] && GIT_UPDATE=1 || GIT_UPDATE=0
[[ "${YARA_CUSTOM_RULES_ONLY:-false}" == "true" ]] && CUSTOM_RULES_ONLY=1 || CUSTOM_RULES_ONLY=0
STRELKA_RESTART_AFTER_UPDATE=0
while getopts 'cusvf:r:y:' OPTION; do
  case "$OPTION" in
    v)
      VERBOSE_FLAG="-v"
      set -x
      ;;

    c)
      CUSTOM_RULES_ONLY=1
      ;;

    s)
      STRELKA_RESTART_AFTER_UPDATE=1
      ;;

    u)
      GIT_UPDATE=1
      ;;

    f)
      YARA_COMPILED_RULES_FILE="$OPTARG"
      ;;

    r)
      YARA_RULES_SRC_DIR="$OPTARG"
      ;;

    y)
      YARA_RULES_DIR="$OPTARG"
      ;;

    ?)
      echo "script usage: $(basename $0) [-v verbose] [-c custom-only] [-u git-update] [-f compiled_rules_file] [-r rules_src_dir] [-y yara_rules_dir]" >&2
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

function get_top_level_subdir_for_symlink() {
    local symlink="$1"
    # Resolve the absolute target path
    local target
    target="$(readlink -f "$symlink")"

    # Remove the base directory prefix
    target="${target#$YARA_RULES_SRC_DIR/}"

    # Extract the first path component
    echo "${target%%/*}"
}

function filename_base() {
  local f="${1##*/}"
  echo "${f%.*}"
}

mkdir -p "${YARA_RULES_SRC_DIR}" "${YARA_RULES_DIR}"

# clone yara rules and create symlinks in destination directory
if [[ "${GIT_UPDATE}" == "1" ]] && [[ "${CUSTOM_RULES_ONLY}" != "1" ]]; then
  pushd "$YARA_RULES_SRC_DIR" >/dev/null 2>&1
  YARA_RULE_GITHUB_URLS=(
    "https://github.com/advanced-threat-research/Yara-Rules|master"
    "https://github.com/bartblaze/Yara-rules|master"
    "https://github.com/elastic/protections-artifacts|main"
    "https://github.com/eset/malware-ioc|master"
    "https://github.com/kevoreilly/CAPEv2|master"
    "https://github.com/Neo23x0/signature-base|master"
    "https://github.com/reversinglabs/reversinglabs-yara-rules|develop"
    "https://github.com/SEKOIA-IO/Community|main"
    "https://github.com/volexity/threat-intel|main"
  )
  for i in ${YARA_RULE_GITHUB_URLS[@]}; do
    SRC_DIR="$(clone_github_repo "$i")"
    if [[ -d "$SRC_DIR" ]]; then
      find "$SRC_DIR" -type f \( -iname '*.yara' -o -iname '*.yar' \) -print0 | xargs -0 -r -I XXX ln $VERBOSE_FLAG -s -f "$("$REALPATH" "XXX")" "$YARA_RULES_DIR"/
    fi
  done
  popd >/dev/null 2>&1
fi

pushd "${YARA_RULES_DIR}" >/dev/null || exit 1
YARA_COMPILED_RULES_FILE="$(basename "${YARA_COMPILED_RULES_FILE}")"

# remove broken symlinks (or, if CUSTOM_RULES_ONLY, all symlinks, leaving only the custom
# rules for the while loop to find) from destination directory
echo "Removing stale symlinks..." >&2
[[ "${CUSTOM_RULES_ONLY}" == "1" ]] && \
  find . -path ./custom -prune -o -type l -exec rm -vf "{}" \; 2>/dev/null || \
  find . -type l \( ! -exec test -r "{}" \; \) -print -delete 2>/dev/null

# gather yara files for compilation
YARAC_ARGS=()
while IFS= read -r -d '' YARA_FILE; do

  # don't include the previously-compiled rules file
  [[ "${YARA_FILE}" == "./${YARA_COMPILED_RULES_FILE}" ]] && continue

  # test compile this file by itself
  if ! YARAC_ERR=$(yarac "${YARA_FILE}" /dev/null 2>&1); then
    # bad file, warn and skip
    echo "Skipping invalid YARA file: ${YARA_FILE}" >&2
    # too verbose, but uncomment if you want it...
    # echo "$YARAC_ERR" >&2
    continue
  fi

  # good file, add with namespace
  YARA_NAMESPACE=$(echo "$(get_top_level_subdir_for_symlink "${YARA_FILE}")" | sed 's/[^A-Za-z0-9]/_/g')_$(filename_base "${YARA_FILE}" | sed 's/[^A-Za-z0-9]/_/g')
  [[ "${YARA_NAMESPACE}" =~ ^[A-Za-z] ]] || YARA_NAMESPACE="ns_${YARA_NAMESPACE}"
  # Use awk to remove contiguous duplicates
  YARA_NAMESPACE=$(echo "${YARA_NAMESPACE}" | awk -F'_' '{
      for (i=1; i<=NF; i++) {
          if (i==1 || $i != $(i-1)) {
              printf("%s%s", sep, $i)
              sep="_"
          }
      }
  }')
  YARAC_ARGS+=("${YARA_NAMESPACE}:${YARA_FILE}")

done < <(find . \
          \( -type f -o -type l \) \
          \( -name "*.yar" -o -name "*.yara" -o -name "*.rule" \) \
          ! -name ".*" ! -name "~*" ! -name "_*" \
          -print0
        )

# precompile yara rules for performance gains in Streka
if (( ${#YARAC_ARGS[@]} > 0 )); then
  rm -f "${YARA_COMPILED_RULES_FILE}"
  yarac "${YARAC_ARGS[@]}" "${YARA_COMPILED_RULES_FILE}"
  YARAC_RESULT=$?
  [[ ${YARAC_RESULT} == 0 ]] && \
    echo "Compiled ${#YARAC_ARGS[@]} YARA rule files to \"${YARA_RULES_DIR}/${YARA_COMPILED_RULES_FILE}\"" >&2 || \
    echo "Failed to compile YARA rules" >&2

else
  echo "No valid YARA files found; refusing to generate empty compiled set" >&2
  YARAC_RESULT=1
fi

popd >/dev/null

[[ ${STRELKA_RESTART_AFTER_UPDATE} == 1 ]] && [[ ${YARAC_RESULT} == 0 ]] && supervisorctl restart backend

exit ${YARAC_RESULT}