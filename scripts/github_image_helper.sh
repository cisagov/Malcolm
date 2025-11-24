#!/usr/bin/env bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

if [ -z "$BASH_VERSION" ]; then
  echo "Wrong interpreter, please run \"$0\" with bash"
  exit 1
fi

[[ "$(uname -s)" = 'Darwin' ]] && REALPATH=grealpath || REALPATH=realpath
[[ "$(uname -s)" = 'Darwin' ]] && DIRNAME=gdirname || DIRNAME=dirname
[[ "$(uname -s)" = 'Darwin' ]] && GREP=ggrep || GREP=grep
if ! (type "$REALPATH" && type "$DIRNAME" && type "$GREP" && type git) > /dev/null; then
  echo "$(basename "${BASH_SOURCE[0]}") requires $REALPATH and $DIRNAME and $GREP and git"
  exit 1
fi
SCRIPT_PATH="$($DIRNAME $($REALPATH -e "${BASH_SOURCE[0]}"))"
IMAGE_ARCH_SUFFIX="$(uname -m | sed 's/^x86_64$//' | sed 's/^arm64$/-arm64/' | sed 's/^aarch64$/-arm64/')"
MALCOLM_CONTAINER_RUNTIME="${MALCOLM_CONTAINER_RUNTIME:-docker}"

set -uo pipefail
shopt -s nocasematch
ENCODING="utf-8"

if [ -t 0 ] ; then
  INTERACTIVE_SHELL=yes
  QUIET_PULL_FLAG=
else
  INTERACTIVE_SHELL=no
  QUIET_PULL_FLAG=--quiet
fi

# get the nth column of output
function _cols() {
  first="awk '{print "
  last="}'"
  cmd="${first}"
  commatime=""
  for var in "$@"; do
    if [ -z $commatime ]; then
      commatime="no"
      cmd=${cmd}\$${var}
    else
      cmd=${cmd}\,\$${var}
    fi
  done
  cmd="${cmd}${last}"
  eval $cmd
}

# get the current git working copy's branch (e.g., main)
function _gitbranch() {
  pushd "$SCRIPT_PATH/.." >/dev/null 2>&1
  git rev-parse --abbrev-ref HEAD
  popd >/dev/null 2>&1
}

# get the current git working copy's remote name (e.g., origin)
function _gitremote() {
  pushd "$SCRIPT_PATH/.." >/dev/null 2>&1
  git branch -vv | $GREP "^\*" | cut -d "[" -f2 | cut -d "]" -f1 | cut -d "/" -f1
  popd >/dev/null 2>&1
}

# get the current git working copy's top-level directory
function _gittoplevel() {
  pushd "$SCRIPT_PATH/.." >/dev/null 2>&1
  git rev-parse --show-toplevel
  popd >/dev/null 2>&1
}

# get the current git working copy's remote "owner" (github user or organization, e.g., johndoe)
function _gitowner() {
  pushd "$SCRIPT_PATH/.." >/dev/null 2>&1
  git remote get-url "$(_gitremote)" | sed 's@.*github\.com/@@' | cut -d'/' -f1
  popd >/dev/null 2>&1
}

# get the current git working copy's remote repository name (e.g., malcolm)
function _gitreponame() {
  pushd "$SCRIPT_PATH/.." >/dev/null 2>&1
  git remote get-url "$(_gitremote)" | sed 's@.*github\.com/@@' | cut -d'/' -f2
  popd >/dev/null 2>&1
}

# get the current git working copy's Malcolm version (grepped from docker-compose.yml, e.g., 5.0.3)
function _malcolmversion() {
  $GREP -P "^\s+image:.*/malcolm" "$(_gittoplevel)"/docker-compose.yml | awk '{print $2}' | cut -d':' -f2 | sed 's/-[^-]*$//' | uniq -c | sort -nr | awk '{print $2}' | head -n 1
}

################################################################################
# cleanup temporary directory, if any
WORKDIR="$(mktemp -d -t malcolm-github-XXXXXX)"

function _cleanup {
  if [[ -d "$WORKDIR" ]] && ! rm -rf "$WORKDIR"; then
   echo "Failed to remove temporary directory '$WORKDIR'" >&2
  fi
}

################################################################################
# pull ghcr.io/$OWNER/$IMG:$BRANCH for each image in docker-compose.yml and re-tag as ghcr.io/idaholab/$IMG:$VERSION
# e.g., pull ghcr.io/johndoe/malcolm/arkime:main and tag as ghcr.io/idaholab/malcolm/arkime:5.0.3
function _PullAndTagGithubWorkflowBuild() {
  BRANCH="$(_gitbranch)"
  VERSION="$(_malcolmversion)"
  OWNER="$(_gitowner)"
  IMAGE=$1

  $MALCOLM_CONTAINER_RUNTIME pull $QUIET_PULL_FLAG ghcr.io/"$OWNER"/"$IMAGE":"${BRANCH}${IMAGE_ARCH_SUFFIX}" && \
    $MALCOLM_CONTAINER_RUNTIME tag ghcr.io/"$OWNER"/"$IMAGE":"${BRANCH}${IMAGE_ARCH_SUFFIX}" ghcr.io/idaholab/"$IMAGE":"${VERSION}${IMAGE_ARCH_SUFFIX}"
}

function PullAndTagGithubWorkflowImages() {
  BRANCH="$(_gitbranch)"
  VERSION="$(_malcolmversion)"
  OWNER="$(_gitowner)"
  echo "Pulling images with $MALCOLM_CONTAINER_RUNTIME from ghcr.io/$OWNER ($BRANCH) and tagging as ${VERSION}${IMAGE_ARCH_SUFFIX}..."
  for IMG in $($GREP image: "$(_gittoplevel)"/docker-compose.yml | _cols 2 | cut -d: -f1 | sort -u | sed "s/.*\/\(malcolm\)/\1/"); do
    _PullAndTagGithubWorkflowBuild "$IMG"
  done
  echo "done"
}

function PullAndTagGithubWorkflowISOImages() {
  BRANCH="$(_gitbranch)"
  VERSION="$(_malcolmversion)"
  OWNER="$(_gitowner)"
  echo "Pulling ISO wrapper images with $MALCOLM_CONTAINER_RUNTIME from ghcr.io/$OWNER ($BRANCH) and tagging as $VERSION ..."
  for IMG in malcolm/{malcolm,hedgehog,hedgehog-raspi}; do
    _PullAndTagGithubWorkflowBuild "$IMG" 2>/dev/null
  done
  echo "done"
}

################################################################################
# extract the ISO wrapped in the ghcr.io docker image to the current directory
# e.g., extract live.iso from ghcr.io/johndoe/malcolm/hedgehog:development
# and save locally as hedgehog-5.0.3.iso
function _ExtractISOFromGithubWorkflowBuild() {
  BRANCH="$(_gitbranch)"
  VERSION="$(_malcolmversion)"
  OWNER="$(_gitowner)"

  TOOL="$1"
  DEST_DIR="${2:-"$(pwd)"}"

  if [[ "$TOOL" == "hedgehog-raspi" ]]; then
    SRV_NAME="$TOOL-img-srv"
    IMG_FILE_REMOTE=raspi_4_trixie.img.xz
    LOG_FILE_REMOTE=raspi_4_trixie.log
    IMG_NAME="${3:-"hedgehog-${VERSION}_raspi_4"}"
    IMG_FILE_LOCAL="$IMG_NAME".img.xz
    LOG_FILE_LOCAL="$IMG_NAME".log
  else
    SRV_NAME="$TOOL-iso-srv"
    IMG_FILE_REMOTE=live.iso
    IMG_NAME="${3:-"$TOOL-$VERSION"}"
    LOG_FILE_REMOTE="$IMG_NAME"-build.log
    IMG_FILE_LOCAL="$IMG_NAME".iso
    LOG_FILE_LOCAL="$IMG_NAME"-build.log
  fi

  $MALCOLM_CONTAINER_RUNTIME run --rm -d --name "$SRV_NAME" -p 127.0.0.1:8000:8000/tcp -e QEMU_START=false -e NOVNC_START=false \
      ghcr.io/"$OWNER"/malcolm/"$TOOL":"${BRANCH}${IMAGE_ARCH_SUFFIX}" 2>/dev/null && \
    sleep 10 && \
    curl -sSL -o "$DEST_DIR"/"$IMG_FILE_LOCAL" http://localhost:8000/"$IMG_FILE_REMOTE" && \
    curl -sSL -o "$DEST_DIR"/"$LOG_FILE_LOCAL" http://localhost:8000/"$LOG_FILE_REMOTE"
  $MALCOLM_CONTAINER_RUNTIME stop "$SRV_NAME" 2>/dev/null
}

function ExtractISOsFromGithubWorkflowBuilds() {
  _ExtractISOFromGithubWorkflowBuild malcolm
  _ExtractISOFromGithubWorkflowBuild hedgehog
  _ExtractISOFromGithubWorkflowBuild hedgehog-raspi
}

################################################################################
# extract the malcolm ISO wrapped in the ghcr.io docker image to a temp directory,
# then extract and load the docker images tarball from the ISO.
function ExtractAndLoadImagesFromGithubWorkflowBuildISO() {
  if ! type xorriso >/dev/null 2>&1 || ! type unsquashfs >/dev/null 2>&1 || ! type unxz >/dev/null 2>&1; then
    echo "Cannot extract ISO file without xorriso, unsquashfs, and unxz" >&2
  else
    mkdir -p "$WORKDIR"
    _ExtractISOFromGithubWorkflowBuild malcolm "$WORKDIR" malcolm
    pushd "$WORKDIR" >/dev/null 2>&1
    if [[ -e malcolm.iso ]]; then
      xorriso -osirrox on -indev malcolm.iso -extract /live/filesystem.squashfs filesystem.squashfs
      if [[ -e filesystem.squashfs ]]; then
        unsquashfs filesystem.squashfs -f malcolm_images.tar.xz
        if [[ -e squashfs-root/malcolm_images.tar.xz ]]; then
          unxz < squashfs-root/malcolm_images.tar.xz | $MALCOLM_CONTAINER_RUNTIME load
        else
          echo "Failed to images tarball" 2>&1
        fi
      else
        echo "Failed to extract squashfs file" 2>&1
      fi
    else
      echo "Failed to extract ISO file" 2>&1
    fi
    popd >/dev/null 2>&1
  fi
}

################################################################################
# use your GitHub personal access token (GITHUB_OAUTH_TOKEN) to issue a
# repository dispatch to build the Malcolm images from the GitHub workflows
function GithubTriggerPackagesBuild () {
  if [[ -n $GITHUB_OAUTH_TOKEN ]]; then
    REPO="$(_gitowner)/$(_gitreponame)"
    echo "Issuing repository_dispatch on $REPO"
    curl -sSL  -H "Authorization: token $GITHUB_OAUTH_TOKEN" -H "Accept: application/vnd.github.v3+json" \
      --data '{"event_type": "CLI trigger"}' \
      "https://api.github.com/repos/$REPO/dispatches"
  else
    echo "\$GITHUB_OAUTH_TOKEN not defined, see https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token">&2
  fi
}

################################################################################
# "main"

trap "_cleanup" EXIT

# force-navigate to Malcolm base directory (parent of scripts/ directory)
pushd "$SCRIPT_PATH/.." >/dev/null 2>&1

# get a list of all the "public" functions (not starting with _)
FUNCTIONS=($(declare -F | awk '{print $NF}' | sort -f | egrep -v "^_"))

# present the menu to our customer and get their selection
printf "%s\t%s\n" "0" "pull and extract everything"
for i in "${!FUNCTIONS[@]}"; do
  ((IPLUS=i+1))
  printf "%s\t%s\n" "$IPLUS" "${FUNCTIONS[$i]}"
done
echo -n "Operation:"
[[ -n "${1-}" ]] && USER_FUNCTION_IDX="$1" || read USER_FUNCTION_IDX

if (( $USER_FUNCTION_IDX == 0 )); then
  PullAndTagGithubWorkflowISOImages
  ExtractAndLoadImagesFromGithubWorkflowBuildISO
  ExtractISOsFromGithubWorkflowBuilds
  PullAndTagGithubWorkflowImages

elif (( $USER_FUNCTION_IDX > 0 )) && (( $USER_FUNCTION_IDX <= "${#FUNCTIONS[@]}" )); then
  # execute one function, à la carte
  USER_FUNCTION="${FUNCTIONS[((USER_FUNCTION_IDX-1))]}"
  echo $USER_FUNCTION
  $USER_FUNCTION

else
  # some people just want to watch the world burn
  echo "Invalid operation selected"
  exit 1;
fi
