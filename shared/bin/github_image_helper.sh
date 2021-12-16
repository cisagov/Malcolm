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

# get the current git working copy's Malcolm version (grepped from docker-compose.yml, e.g., 5.0.3)
function _malcolmversion() {
  grep -P "^\s+image:\s*malcolm" "$(_gittoplevel)"/docker-compose.yml | awk '{print $2}' | cut -d':' -f2 | uniq -c | sort -nr | awk '{print $2}' | head -n 1
}

################################################################################
# pull ghcr.io/$OWNER/$IMG:$BRANCH for each image in docker-compose.yml and re-tag as $IMG:$VERSION
# e.g., pull ghcr.io/johndoe/malcolmnetsec/arkime:main and tag as malcolmnetsec/arkime:5.0.3
function PullAndTagGithubWorkflowBuilds() {
  BRANCH="$(_gitbranch)"
  VERSION="$(_malcolmversion)"
  OWNER="$(_gitowner)"

  echo "Pulling images from ghcr.io/$OWNER ($BRANCH) and tagging as $VERSION ..."
  for IMG in $(grep image: "$(_gittoplevel)"/docker-compose.yml | _cols 2 | cut -d: -f1) malcolmnetsec/{malcolm,hedgehog}; do
    docker pull ghcr.io/"$OWNER"/"$IMG":"$BRANCH" && \
      docker tag ghcr.io/"$OWNER"/"$IMG":"$BRANCH" "$IMG":"$VERSION"
  done
  echo "done"
}

################################################################################
# extract the ISO wrapped in the ghcr.io docker image to the current directory
# e.g., extract live.iso from ghcr.io/johndoe/malcolmnetsec/hedgehog:development
# and save locally as hedgehog-5.0.3.iso
function ExtractISOsFromGithubWorkflowBuilds() {
  BRANCH="$(_gitbranch)"
  VERSION="$(_malcolmversion)"
  OWNER="$(_gitowner)"

  for TOOL in malcolm hedgehog; do
    docker run --rm -d --name "$TOOL"-iso-srv -p 127.0.0.1:8000:8000/tcp -e QEMU_START=false -e NOVNC_START=false \
        ghcr.io/"$OWNER"/malcolmnetsec/"$TOOL":"$BRANCH" && \
      sleep 10 && \
      curl -sSL -o "$TOOL"-"$VERSION".iso http://localhost:8000/live.iso && \
      curl -sSL -O -J http://localhost:8000/"$TOOL"-"$VERSION"-build.log
    docker stop "$TOOL"-iso-srv
  done
}

################################################################################
# "main"

# get a list of all the "public" functions (not starting with _)
FUNCTIONS=($(declare -F | awk '{print $NF}' | sort | egrep -v "^_"))

# present the menu to our customer and get their selection
for i in "${!FUNCTIONS[@]}"; do
  ((IPLUS=i+1))
  printf "%s\t%s\n" "$IPLUS" "${FUNCTIONS[$i]}"
done
echo -n "Operation:"
read USER_FUNCTION_IDX

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
