#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<EOF
Usage: $(basename "$0") -r RELEASE -s SOURCE_BRANCH -d IRONBANK_DIR [-t TARGET_BRANCH]

  -r, --release          Malcolm release version, e.g. 26.09.0   (required)
  -s, --source-branch    Source branch for the merge request     (required)
  -d, --ironbank-dir     Path to the ironbank checkout directory (required)
  -t, --target-branch    Target branch for the merge request     (default: development)
  -h, --help             Show this help text
EOF
}

RELEASE=""
SOURCE_BRANCH=""
IRONBANK_DIR=""
TARGET_BRANCH="development"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--release)
            RELEASE="$2"
            shift 2
            ;;
        -s|--source-branch)
            SOURCE_BRANCH="$2"
            shift 2
            ;;
        -d|--ironbank-dir)
            IRONBANK_DIR="$2"
            shift 2
            ;;
        -t|--target-branch)
            TARGET_BRANCH="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

missing=()
[[ -z "$RELEASE" ]] && missing+=("--release")
[[ -z "$SOURCE_BRANCH" ]] && missing+=("--source-branch")
[[ -z "$IRONBANK_DIR" ]] && missing+=("--ironbank-dir")

if [[ ${#missing[@]} -gt 0 ]]; then
    echo "Missing required argument(s): ${missing[*]}" >&2
    usage >&2
    exit 1
fi

if [[ ! -d "$IRONBANK_DIR" ]]; then
    echo "IRONBANK_DIR does not exist or is not a directory: $IRONBANK_DIR" >&2
    exit 1
fi

query="$(
    RELEASE="$RELEASE" \
    SOURCE_BRANCH="$SOURCE_BRANCH" \
    TARGET_BRANCH="$TARGET_BRANCH" \
    python3 - <<'PY'
import os
from urllib.parse import urlencode

release = os.environ["RELEASE"]
source_branch = os.environ["SOURCE_BRANCH"]
target_branch = os.environ["TARGET_BRANCH"]

params = [
    ("merge_request[source_branch]", source_branch),
    ("merge_request[target_branch]", target_branch),
    ("merge_request[force_remove_source_branch]", "0"),
    ("merge_request[squash]", "1"),
    ("merge_request[title]", f"updates for Malcolm release v{release}"),
    (
        "merge_request[description]",
        f"""## Summary

Changes corresponding to the upstream [v{release}](https://github.com/idaholab/Malcolm/releases/tag/v{release}) Malcolm release.

[Malcolm-Helm](https://github.com/idaholab/Malcolm-Helm) has also been tagged at [v{release}](https://github.com/idaholab/Malcolm-Helm/releases/tag/v{release}).
""",
    ),
    ("merge_request[label_ids][]", "878"),
    ("merge_request[label_ids][]", "7441"),
]

print(urlencode(params))
PY
)"

while IFS= read -r -d '' dir; do
    project="$(basename "$dir")"
    url="https://repo1.dso.mil/dsop/afdco/malcolm/${project}/-/merge_requests/new?${query}"

    printf 'Opening %s\n' "$url"
    xdg-open "$url"
done < <(
    find "$IRONBANK_DIR" \
        -mindepth 1 \
        -maxdepth 1 \
        -type d \
        -print0 |
        sort -z
)
