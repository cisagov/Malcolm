#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <file1.json> [file2.json ...]" >&2
    exit 1
fi

command -v jq >/dev/null 2>&1 || { echo "jq is required but not installed." >&2; exit 1; }

summary_file=$(mktemp)
findings_file=$(mktemp)
trap 'rm -f "$summary_file" "$findings_file"' EXIT

echo -e "IMAGE\tABC\tORA\t%VERIFIED" > "$summary_file"
echo -e "IMAGE\tSEVERITY\tSTATUS\tCOUNT" > "$findings_file"

for f in "$@"; do
    if [ ! -f "$f" ]; then
        echo "Warning: file not found, skipping: $f" >&2
        continue
    fi

    jq -r '
        to_entries[] | .value |
        "\(.imageName):\(.tag)\t\(.abc)\t\(.ora)\t\(.percentVerified)"
    ' "$f" >> "$summary_file"

    jq -r '
        to_entries[] | .value |
        (.imageName + ":" + .tag) as $name |
        .findings | to_entries[] as $sev |
        $sev.value | to_entries[] as $status |
        "\($name)\t\($sev.key)\t\($status.key)\t\($status.value)"
    ' "$f" >> "$findings_file"
done

echo "=== Summary ==="
column -t -s $'\t' "$summary_file"
echo
echo "=== Findings ==="
column -t -s $'\t' "$findings_file"
