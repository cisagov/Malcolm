#!/usr/bin/env bash
#
# bump-hardening-manifest.sh
#
# https://repo1.dso.mil/dsop/afdco/malcolm
#
# Bumps the version tag in a hardening_manifest.yaml, resolves the new
# container digest via `docker buildx imagetools`, re-downloads the
# source tarball (if present) to compute its new sha512, and pulls the
# commit sha and commit date for the corresponding git tag into
# VCS_REVISION and BUILD_DATE. Forces double-quote style on every
# scalar it touches.
#
# The GitHub repo used to resolve VCS_REVISION/BUILD_DATE is taken from
# labels."org.opencontainers.image.url" in the manifest. Pass a repo URL
# as a third argument to override that.
#
# A GitHub token can be passed as a fourth argument, or picked up from
# $GITHUB_TOKEN, to authenticate the GitHub API call and avoid the
# unauthenticated rate limit (60 req/hr per IP).
#
# Fields that are absent from the manifest are skipped, not fatal.
# A remote operation (curl, docker, git) failing on a field that IS
# present in the manifest still aborts the script.
#
# Requires: mikefarah/yq (v4+), docker buildx, curl, sha512sum, git
#
# Usage:
#   ./bump-hardening-manifest.sh <new_tag> [manifest_file] [github_repo_url] [github_token]
#
# Example:
#   ./bump-hardening-manifest.sh 26.08.0
#   ./bump-hardening-manifest.sh 26.08.0 ./hardening_manifest.yaml
#   ./bump-hardening-manifest.sh 26.08.0 ./hardening_manifest.yaml https://github.com/idaholab/Malcolm
#   ./bump-hardening-manifest.sh 26.08.0 ./hardening_manifest.yaml "" ghp_xxxxxxxxxxxx
#   GITHUB_TOKEN=ghp_xxxxxxxxxxxx ./bump-hardening-manifest.sh 26.08.0

set -euo pipefail

usage() {
    echo "Usage: $0 <new_tag> [manifest_file] [github_repo_url] [github_token]" >&2
    echo "  manifest_file    defaults to hardening_manifest.yaml" >&2
    echo "  github_repo_url  overrides labels.\"org.opencontainers.image.url\"" >&2
    echo "  github_token     falls back to \$GITHUB_TOKEN if not given" >&2
    exit 1
}

[[ $# -ge 1 ]] || usage

NEW_VERSION="$1"
FILE="${2:-hardening_manifest.yaml}"
REPO_URL_OVERRIDE="${3:-}"
GITHUB_TOKEN="${4:-${GITHUB_TOKEN:-}}"

command -v yq >/dev/null 2>&1 || { echo "yq (mikefarah) is required" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }
command -v git >/dev/null 2>&1 || { echo "git is required" >&2; exit 1; }

if ! yq --version 2>&1 | grep -qi "mikefarah"; then
    echo "Warning: expected mikefarah/yq; got: $(yq --version 2>&1)" >&2
fi

[[ -f "$FILE" ]] || { echo "File not found: $FILE" >&2; exit 1; }

if [[ -n "$GITHUB_TOKEN" ]]; then
    echo "Using GitHub token for API authentication"
fi

TMPFILE=""
cleanup() { [[ -n "$TMPFILE" && -f "$TMPFILE" ]] && rm -f "$TMPFILE"; }
trap cleanup EXIT

# lookup <yq_query> -- prints the result, or nothing if null/empty.
# Never triggers `set -e`, since a missing field is a normal outcome here.
lookup() {
    local out
    out="$(yq "$1" "$FILE" 2>/dev/null || true)"
    [[ "$out" == "null" ]] && out=""
    echo "$out"
}

# set_quoted <yq_path> <value>
# Sets a value at the given yq path and forces double-quote style on it.
set_quoted() {
    local yq_path="$1"
    local value="$2"
    VALUE="$value" yq -i "${yq_path} = env(VALUE) | ${yq_path} style=\"double\"" "$FILE"
}

# github_api_curl <url> -- curl wrapper that adds auth if a token is set.
github_api_curl() {
    local url="$1"
    if [[ -n "$GITHUB_TOKEN" ]]; then
        curl -fsSL \
            -H "Accept: application/vnd.github+json" \
            -H "Authorization: Bearer ${GITHUB_TOKEN}" \
            "$url"
    else
        curl -fsSL \
            -H "Accept: application/vnd.github+json" \
            "$url"
    fi
}

# ---- 1. figure out the old version from args.MALCOLM_VERSION ----
OLD_VERSION="$(lookup '.args.MALCOLM_VERSION')"

if [[ -z "$OLD_VERSION" ]]; then
    echo "args.MALCOLM_VERSION not found in $FILE -- cannot determine old version" >&2
    exit 1
fi

echo "Old version: $OLD_VERSION"
echo "New version: $NEW_VERSION"

# ---- 2. swap the numbered tag in tags: (skip if not present) ----
TAG_MATCH="$(OLD_VERSION="$OLD_VERSION" yq '.tags[] | select(. == env(OLD_VERSION))' "$FILE" 2>/dev/null || true)"

if [[ -n "$TAG_MATCH" ]]; then
    OLD_VERSION="$OLD_VERSION" NEW_VERSION="$NEW_VERSION" yq -i \
        '(.tags[] | select(. == env(OLD_VERSION))) = env(NEW_VERSION) | (.tags[] | select(. == env(NEW_VERSION))) style="double"' \
        "$FILE"
    echo "Updated tags: entry"
else
    echo "No matching entry in tags: for $OLD_VERSION -- skipping"
fi

# ---- 3. swap args.MALCOLM_VERSION and the matching OCI label ----
set_quoted '.args.MALCOLM_VERSION' "$NEW_VERSION"

OCI_VERSION_LABEL="$(lookup '.labels."org.opencontainers.image.version"')"
if [[ -n "$OCI_VERSION_LABEL" ]]; then
    set_quoted '.labels."org.opencontainers.image.version"' "$NEW_VERSION"
    echo "Updated org.opencontainers.image.version label"
else
    echo "No org.opencontainers.image.version label present -- skipping"
fi

# ---- 4. resolve new digest for the ghcr.io resource and swap it in (skip if absent) ----
OLD_DOCKER_URL="$(lookup '.resources[] | select(.url != null) | select(.url | test("^docker://ghcr.io/idaholab")) | .url')"

if [[ -n "$OLD_DOCKER_URL" ]]; then
    REPO="${OLD_DOCKER_URL#docker://}"
    REPO="${REPO%@sha256:*}"

    echo "Inspecting ${REPO}:${NEW_VERSION} ..."
    DIGEST="$(docker buildx imagetools inspect "${REPO}:${NEW_VERSION}" | awk '/^Digest:/{print $2; exit}')"

    if [[ -z "$DIGEST" ]]; then
        echo "Failed to resolve digest for ${REPO}:${NEW_VERSION}" >&2
        exit 1
    fi

    echo "New digest: $DIGEST"
    NEW_DOCKER_URL="docker://${REPO}@${DIGEST}"
    set_quoted '(.resources[] | select(.url != null) | select(.url | test("^docker://ghcr.io/idaholab")) | .url)' "$NEW_DOCKER_URL"
else
    echo "No docker://ghcr.io/idaholab resource present -- skipping digest resolution"
fi

# ---- 5. bump the source tarball url, download it, recompute sha512 (skip if absent) ----
OLD_SOURCE_URL="$(lookup '.resources[] | select(.filename == "malcolm-source.tar.gz") | .url')"

if [[ -n "$OLD_SOURCE_URL" ]]; then
    NEW_SOURCE_URL="${OLD_SOURCE_URL//$OLD_VERSION/$NEW_VERSION}"
    set_quoted '(.resources[] | select(.filename == "malcolm-source.tar.gz") | .url)' "$NEW_SOURCE_URL"

    TMPFILE="$(mktemp)"
    echo "Downloading ${NEW_SOURCE_URL} ..."
    curl -fsSL "$NEW_SOURCE_URL" -o "$TMPFILE"

    NEW_SHA512="$(sha512sum "$TMPFILE" | awk '{print $1}')"
    echo "New sha512: $NEW_SHA512"
    set_quoted '(.resources[] | select(.filename == "malcolm-source.tar.gz") | .validation.value)' "$NEW_SHA512"
else
    echo "No malcolm-source.tar.gz resource present -- skipping tarball/sha512 update"
fi

# ---- 6 & 7. resolve commit sha/date for the new tag ----
# Repo comes from (in priority order): explicit CLI override, then
# labels."org.opencontainers.image.url". Independent of whether a
# source tarball resource exists.
GH_REPO_URL="$REPO_URL_OVERRIDE"

if [[ -z "$GH_REPO_URL" ]]; then
    GH_REPO_URL="$(lookup '.labels."org.opencontainers.image.url"')"
fi

if [[ -n "$GH_REPO_URL" ]]; then
    # Trim a trailing slash if present, for consistent path-joining below.
    GH_REPO_URL="${GH_REPO_URL%/}"

    if [[ "$GH_REPO_URL" != https://github.com/* ]]; then
        echo "Resolved repo url '$GH_REPO_URL' is not a github.com URL -- skipping VCS_REVISION/BUILD_DATE" >&2
    else
        OWNER_REPO="$(echo "$GH_REPO_URL" | sed -E 's#https://github\.com/##')"
        GIT_TAG="v${NEW_VERSION}"
        echo "Resolving commit for tag ${GIT_TAG} on ${GH_REPO_URL} ..."

        LS_REMOTE_OUT="$(git ls-remote "$GH_REPO_URL" "refs/tags/${GIT_TAG}" "refs/tags/${GIT_TAG}^{}")"

        if [[ -z "$LS_REMOTE_OUT" ]]; then
            echo "Tag ${GIT_TAG} not found on ${GH_REPO_URL}" >&2
            exit 1
        fi

        FULL_SHA="$(echo "$LS_REMOTE_OUT" | awk '/\^\{\}$/{print $1; found=1} END{if(!found) exit 1}' || true)"
        if [[ -z "$FULL_SHA" ]]; then
            FULL_SHA="$(echo "$LS_REMOTE_OUT" | awk '{print $1; exit}')"
        fi

        VCS_REVISION="${FULL_SHA:0:7}"
        echo "New VCS_REVISION: $VCS_REVISION"

        if [[ -n "$(lookup '.args.VCS_REVISION')" ]]; then
            set_quoted '.args.VCS_REVISION' "$VCS_REVISION"
        else
            echo "No args.VCS_REVISION present -- skipping"
        fi

        echo "Fetching commit date for ${FULL_SHA} ..."
        COMMIT_JSON="$(github_api_curl "https://api.github.com/repos/${OWNER_REPO}/commits/${FULL_SHA}")"

        BUILD_DATE="$(echo "$COMMIT_JSON" | yq -p json '.commit.committer.date')"

        if [[ -z "$BUILD_DATE" || "$BUILD_DATE" == "null" ]]; then
            echo "Failed to resolve commit date for ${FULL_SHA}" >&2
            exit 1
        fi

        echo "New BUILD_DATE: $BUILD_DATE"

        if [[ -n "$(lookup '.args.BUILD_DATE')" ]]; then
            set_quoted '.args.BUILD_DATE' "$BUILD_DATE"
        else
            echo "No args.BUILD_DATE present -- skipping"
        fi
    fi
else
    echo "No repo URL available (no override given, no org.opencontainers.image.url label) -- skipping VCS_REVISION/BUILD_DATE"
fi

echo "Done. Updated $FILE from $OLD_VERSION to $NEW_VERSION."
