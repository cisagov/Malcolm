#!/usr/bin/env bash

set -uo pipefail
shopt -s nocasematch
ENCODING="utf-8"

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
  git rev-parse --abbrev-ref HEAD
}

# get the current git working copy's remote name (e.g., origin)
function _gitremote() {
  git branch -vv | grep "^\*" | cut -d "[" -f2 | cut -d "]" -f1 | cut -d "/" -f1
}

# get the current git working copy's top-level directory
function _gittoplevel() {
  git rev-parse --show-toplevel
}

# get the current git working copy's remote "owner" (github user or organization, e.g., johndoe)
function _gitowner() {
  git remote get-url "$(_gitremote)" | sed 's@.*github\.com/@@' | cut -d'/' -f1
}

# get the current git working copy's remote repository name (e.g., malcolm)
function _gitreponame() {
  git remote get-url "$(_gitremote)" | sed 's@.*github\.com/@@' | cut -d'/' -f2
}

# get the current git working copy's Malcolm version (grepped from docker-compose.yml, e.g., 5.0.3)
function _malcolmversion() {
  grep -P "^\s+image:.*/malcolm" "$(_gittoplevel)"/docker-compose.yml | awk '{print $2}' | cut -d':' -f2 | uniq -c | sort -nr | awk '{print $2}' | head -n 1
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

  docker pull ghcr.io/"$OWNER"/"$IMAGE":"$BRANCH" && \
    docker tag ghcr.io/"$OWNER"/"$IMAGE":"$BRANCH" ghcr.io/idaholab/"$IMAGE":"$VERSION"
}

function PullAndTagGithubWorkflowImages() {
  BRANCH="$(_gitbranch)"
  VERSION="$(_malcolmversion)"
  OWNER="$(_gitowner)"
  echo "Pulling images from ghcr.io/$OWNER ($BRANCH) and tagging as $VERSION ..."
  for IMG in $(grep image: "$(_gittoplevel)"/docker-compose.yml | _cols 2 | cut -d: -f1 | sort -u | sed "s/.*\/\(malcolm\)/\1/"); do
    _PullAndTagGithubWorkflowBuild "$IMG"
  done
  echo "done"
}

function PullAndTagGithubWorkflowISOImages() {
  BRANCH="$(_gitbranch)"
  VERSION="$(_malcolmversion)"
  OWNER="$(_gitowner)"
  echo "Pulling ISO wrapper images from ghcr.io/$OWNER ($BRANCH) and tagging as $VERSION ..."
  for IMG in malcolm/{malcolm,hedgehog}; do
    _PullAndTagGithubWorkflowBuild "$IMG"
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
  ISO_NAME="${3:-"$TOOL-$VERSION"}"

  docker run --rm -d --name "$TOOL"-iso-srv -p 127.0.0.1:8000:8000/tcp -e QEMU_START=false -e NOVNC_START=false \
      ghcr.io/"$OWNER"/malcolm/"$TOOL":"$BRANCH" && \
    sleep 10 && \
    curl -sSL -o "$DEST_DIR"/"$ISO_NAME".iso http://localhost:8000/live.iso && \
    curl -sSL -o "$DEST_DIR"/"$ISO_NAME"-build.log http://localhost:8000/"$TOOL"-"$VERSION"-build.log
  docker stop "$TOOL"-iso-srv
}

function ExtractISOsFromGithubWorkflowBuilds() {
  _ExtractISOFromGithubWorkflowBuild malcolm
  _ExtractISOFromGithubWorkflowBuild hedgehog
}

################################################################################
# extract the malcolm ISO wrapped in the ghcr.io docker image to a temp directory,
# then extract and load the docker images tarball from the ISO.
function ExtractAndLoadImagesFromGithubWorkflowBuildISO() {
  if ! type xorriso >/dev/null 2>&1 || ! type unsquashfs >/dev/null 2>&1; then
    echo "Cannot extract ISO file without xorriso" >&2
  else
    mkdir -p "$WORKDIR"
    _ExtractISOFromGithubWorkflowBuild malcolm "$WORKDIR" malcolm
    pushd "$WORKDIR" >/dev/null 2>&1
    if [[ -e malcolm.iso ]]; then
      xorriso -osirrox on -indev malcolm.iso -extract /live/filesystem.squashfs filesystem.squashfs
      if [[ -e filesystem.squashfs ]]; then
        unsquashfs filesystem.squashfs -f malcolm_images.tar.xz
        if [[ -e squashfs-root/malcolm_images.tar.xz ]]; then
          docker load -i squashfs-root/malcolm_images.tar.xz
        else
          echo "Failed to images tarball" 2>&1
        fi
      else
        echo "Failed to extract squashfs file" 2>&1
      fi
    else
      echo "Failed to extract ISO file" 2>&1
    fi
    popd "$WORKDIR" >/dev/null 2>&1
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

# get a list of all the "public" functions (not starting with _)
FUNCTIONS=($(declare -F | awk '{print $NF}' | sort | egrep -v "^_"))

# present the menu to our customer and get their selection
for i in "${!FUNCTIONS[@]}"; do
  ((IPLUS=i+1))
  printf "%s\t%s\n" "$IPLUS" "${FUNCTIONS[$i]}"
done
echo -n "Operation:"
[[ -n "${1-}" ]] && USER_FUNCTION_IDX="$1" || read USER_FUNCTION_IDX

if (( $USER_FUNCTION_IDX > 0 )) && (( $USER_FUNCTION_IDX <= "${#FUNCTIONS[@]}" )); then
  # execute one function, à la carte
  USER_FUNCTION="${FUNCTIONS[((USER_FUNCTION_IDX-1))]}"
  echo $USER_FUNCTION
  $USER_FUNCTION

else
  # some people just want to watch the world burn
  echo "Invalid operation selected"
  exit 1;
fi
