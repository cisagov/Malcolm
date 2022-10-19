#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

if [ -z "$BASH_VERSION" ]; then
  echo "Wrong interpreter, please run \"$0\" with bash"
  exit 1
fi

set -e
set -u
set -o pipefail

ENCODING="utf-8"

# options
# -v      (verbose)

# parse command-line options
VERBOSE_FLAG=""
REVISION="${VCS_REVSION:-$( git rev-parse --short HEAD 2>/dev/null || true )}"
REPOSITORY_NAME=""
OWNER_NAME=""
DEFAULT_BRANCH=""
TOKEN="${GITHUB_TOKEN:-}"
LOG_BASE_DIR=$(pwd)
while getopts 'vr:t:n:o:b:' OPTION; do
  case "$OPTION" in
    v)
      set -x
      VERBOSE_FLAG="-v"
      ;;

    r)
      REVISION="$OPTARG"
      ;;

    n)
      REPOSITORY_NAME="$OPTARG"
      ;;

    o)
      OWNER_NAME="$OPTARG"
      ;;

    b)
      DEFAULT_BRANCH="$OPTARG"
      ;;

    t)
      TOKEN="$OPTARG"
      ;;

    ?)
      echo "script usage: $(basename $0) [-v (verbose)] [-r revision] [-n repository-name] [-o owner-name] [-b default-branch] [-t github-token]" >&2
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"

# cross-platform GNU gnonsense for core utilities
[[ "$(uname -s)" = 'Darwin' ]] && REALPATH=grealpath || REALPATH=realpath
[[ "$(uname -s)" = 'Darwin' ]] && DIRNAME=gdirname || DIRNAME=dirname
[[ "$(uname -s)" = 'Darwin' ]] && GREP=ggrep || GREP=grep
[[ "$(uname -s)" = 'Darwin' ]] && SED=gsed || SED=sed
[[ "$(uname -s)" = 'Darwin' ]] && FIND=gfind || FIND=find
if ! (command -v "$REALPATH" && command -v "$DIRNAME" && command -v "$GREP" && command -v "$SED" && command -v "$FIND") > /dev/null; then
  echo "$(basename "${BASH_SOURCE[0]}") requires $REALPATH and $DIRNAME and $GREP and $SED and $FIND"
  exit 1
fi

# ensure docker (or podman, whatever) exists, too
if $GREP -q Microsoft /proc/version && docker.exe version >/dev/null 2>&1; then
  DOCKER_BIN=docker.exe
  SUDO_CMD=
elif podman version >/dev/null 2>&1; then
  DOCKER_BIN=podman
  SUDO_CMD=
elif docker version >/dev/null 2>&1; then
  DOCKER_BIN=docker
  SUDO_CMD=sudo
else
  echo "$(basename "${BASH_SOURCE[0]}") requires docker or podman"
  exit 1
fi

################################################################################
# cleanup temporary directory, if any
WORKDIR="$(mktemp -d -t malcolm-docs-XXXXXX)"

function _cleanup {
  if [[ -d "$WORKDIR" ]] && ! rm -rf "$WORKDIR"; then
   echo "Failed to remove temporary directory '$WORKDIR'" >&2
  fi
}

trap "_cleanup" EXIT

# force-navigate to Malcolm base directory (parent of scripts/ directory)
RUN_PATH="$(pwd)"
SCRIPT_PATH="$($DIRNAME $($REALPATH -e "${BASH_SOURCE[0]}"))"
pushd "$SCRIPT_PATH/.." >/dev/null 2>&1

# clean up old documentation builds
[[ -d ./_site/ ]] && rm -rf ./_site/

# copy just what's needed for documentation into temporary working directory and build there
cp $VERBOSE_FLAG -r README.md _includes _layouts _config.yml Gemfile docs "$WORKDIR"
pushd "$WORKDIR" >/dev/null 2>&1

# if the revision commit has been specified, replace references to site.github.build_revision with it
[[ -n "$REVISION" ]] && $FIND . -type f -name "*.md" -exec $SED -i "s/{{[[:space:]]*site.github.build_revision[[:space:]]*}}/$REVISION/g" "{}" \;

# if they want to override some values in _config.yml, do it
if command -v yq >/dev/null 2>&1; then
  YQ=yq
else
  YQ="$WORKDIR"/yq
  curl -sSL -o "$YQ" "https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64"
  chmod 755 "$YQ"
fi

[[ -n "$REPOSITORY_NAME" ]] && "$YQ" eval --inplace ".\"repository\"=\"$REPOSITORY_NAME\""               ./_config.yml
[[ -n "$OWNER_NAME" ]] &&      "$YQ" eval --inplace ".\"github\".\"owner_name\"=\"$OWNER_NAME\""         ./_config.yml
[[ -n "$DEFAULT_BRANCH" ]] &&  "$YQ" eval --inplace ".\"github\".\"default_branch\"=\"$DEFAULT_BRANCH\"" ./_config.yml

# pass GitHub API token through to Jekyll if it's available
if [[ -n "${TOKEN:-}" ]]; then
  TOKEN_ARGS=(-e JEKYLL_GITHUB_TOKEN="$TOKEN")
else
  TOKEN_ARGS=()
fi
# run jekyll docker container to generate HTML version of the documentation
$DOCKER_BIN run --rm -v "$(pwd)":/site "${TOKEN_ARGS[@]}" --entrypoint="docker-entrypoint.sh" ghcr.io/mmguero-dev/jekyll:latest bundle exec jekyll build

# clean up some files no longer needed
$FIND ./_site/ -type f -name "*.md" -delete

# TODO: can we get this to run mapping UID so it doesn't have to be sudo'd?
$SUDO_CMD chown -R $(id -u):$(id -g) ./_site/

popd >/dev/null 2>&1

# copy built documentation from work directory
cp $VERBOSE_FLAG -r "$WORKDIR"/_site/ ./

popd >/dev/null 2>&1