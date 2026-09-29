#!/usr/bin/env bash

set -euo pipefail

RELEASE="26.08.0"
SOURCE_BRANCH="inl-26.x"
TARGET_BRANCH="development"
IRONBANK_DIR="${HOME}/devel/ironbank"

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
