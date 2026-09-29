#!/usr/bin/env bash

set -euo pipefail

OPENSEARCH_URL="${OPENSEARCH_URL:-https://opensearch:9200}"
INDEX_PATTERN="${INDEX_PATTERN:-malcolm_network}"
OUTPUT_FILE="${OUTPUT_FILE:-otkb-enriched-documents.ndjson}"
PAGE_SIZE="${PAGE_SIZE:-2000}"
SCROLL_KEEPALIVE="${SCROLL_KEEPALIVE:-5m}"
CURL_CONFIG="${CURL_CONFIG:-/var/local/curlrc/.opensearch.primary.curlrc}"

if [[ -e "${OUTPUT_FILE}" ]]; then
  printf 'Refusing to overwrite existing file: %s\n' "${OUTPUT_FILE}" >&2
  exit 1
fi

response_file="$(mktemp)"
scroll_id=""

curl_common=(
  --silent
  --show-error
  --fail-with-body
  --insecure
  --config "${CURL_CONFIG}"
  --header 'Content-Type: application/json'
)

cleanup() {
  if [[ -n "${scroll_id}" ]]; then
    jq -nc --arg scroll_id "${scroll_id}" \
      '{scroll_id: [$scroll_id]}' |
      curl "${curl_common[@]}" \
        --request DELETE \
        "${OPENSEARCH_URL}/_search/scroll" \
        --data-binary @- \
        >/dev/null 2>&1 || true
  fi

  rm -f -- "${response_file}"
}

trap cleanup EXIT INT TERM

curl "${curl_common[@]}" \
  --request POST \
  "${OPENSEARCH_URL}/${INDEX_PATTERN}/_search?scroll=${SCROLL_KEEPALIVE}" \
  --data-binary @- \
  --output "${response_file}" <<JSON
{
  "size": ${PAGE_SIZE},
  "track_total_hits": true,
  "sort": [
    "_doc"
  ],
  "query": {
    "exists": {
      "field": "otkb.function.id"
    }
  }
}
JSON

total="$(jq -r '.hits.total.value' "${response_file}")"
relation="$(jq -r '.hits.total.relation' "${response_file}")"
exported=0

while :; do
  page_count="$(jq '.hits.hits | length' "${response_file}")"
  scroll_id="$(jq -r '._scroll_id // empty' "${response_file}")"

  if (( page_count == 0 )); then
    break
  fi

  jq --compact-output \
    '.hits.hits[]._source' \
    "${response_file}" >> "${OUTPUT_FILE}"

  exported=$((exported + page_count))
  printf '\rExported %d of %d documents' "${exported}" "${total}" >&2

  if [[ -z "${scroll_id}" ]]; then
    printf '\nOpenSearch did not return a scroll ID\n' >&2
    exit 1
  fi

  jq -nc \
    --arg scroll "${SCROLL_KEEPALIVE}" \
    --arg scroll_id "${scroll_id}" \
    '{
      scroll: $scroll,
      scroll_id: $scroll_id
    }' |
    curl "${curl_common[@]}" \
      --request POST \
      "${OPENSEARCH_URL}/_search/scroll" \
      --data-binary @- \
      --output "${response_file}"
done

printf '\nWrote %d documents to %s\n' "${exported}" "${OUTPUT_FILE}"

if [[ "${relation}" == "eq" ]] && (( exported != total )); then
  printf 'ERROR: OpenSearch reported %d documents, but %d were exported\n' \
    "${total}" "${exported}" >&2
  exit 1
fi
