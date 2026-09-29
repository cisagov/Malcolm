#!/usr/bin/env bash

set -euo pipefail

if (( $# != 2 )); then
  echo "Usage: $0 COMPACT.ndjson VERBOSE.ndjson" >&2
  exit 2
fi

compact_file=$1
verbose_file=$2

for command in jq comm sort wc cmp; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "Required command was not found: ${command}" >&2
    exit 2
  fi
done

for input_file in "${compact_file}" "${verbose_file}"; do
  if [[ ! -r "${input_file}" ]]; then
    echo "Input file is not readable: ${input_file}" >&2
    exit 2
  fi

  if ! jq -e . "${input_file}" >/dev/null; then
    echo "Input file does not contain valid NDJSON: ${input_file}" >&2
    exit 2
  fi
done

work_dir=$(mktemp -d)
trap 'rm -rf "${work_dir}"' EXIT
export TMPDIR="${work_dir}"

pass_count=0
fail_count=0

pass() {
  printf 'PASS  %s\n' "$1"
  pass_count=$((pass_count + 1))
}

fail() {
  printf 'FAIL  %s\n' "$1"
  fail_count=$((fail_count + 1))
}

##############################################################################################
# Accept either raw _source documents or NDJSON records containing an _source object. Treat the
# rule objects as individual fields so their internal rule paths do not appear as enrichment fields.
read -r -d '' jq_otkb_fields <<'JQ' || true
def source:
  if type == "object" and has("_source") then ._source else . end;

def otkb_fields($path):
  if type == "object" then
    to_entries[] |
    ($path + [.key]) as $next |
    if (($next | join(".")) == "otkb.function.zeek_rules") or
       (($next | join(".")) == "otkb.function.wireshark_rules")
    then
      $next | join(".")
    else
      .value | otkb_fields($next)
    end
  elif type == "array" then
    .[] | otkb_fields($path)
  elif . != null then
    $path | join(".")
  else
    empty
  end;

source |
.otkb? |
select(type == "object") |
otkb_fields(["otkb"])
JQ

jq -r "${jq_otkb_fields}" "${compact_file}" |
  LC_ALL=C sort -u > "${work_dir}/compact-fields.txt"

jq -r "${jq_otkb_fields}" "${verbose_file}" |
  LC_ALL=C sort -u > "${work_dir}/verbose-fields.txt"

cat > "${work_dir}/expected-compact-fields.txt" <<'EOF'
otkb.function.created_at
otkb.function.description
otkb.function.function_code
otkb.function.id
otkb.function.message_type
otkb.function.name
otkb.function.origin_node
otkb.function.otkb_classifier.defend_id
otkb.function.otkb_classifier.definition
otkb.function.otkb_classifier.name
otkb.function.protocol
otkb.function.specification_classifier
otkb.function.wireshark_rules
otkb.function.zeek_rules
otkb.procedures.asset.attack_id
otkb.procedures.asset.name
otkb.procedures.attack_id
otkb.procedures.campaign.attack_id
otkb.procedures.campaign.name
otkb.procedures.software.attack_id
otkb.procedures.software.name
otkb.protocol.alternate_names
otkb.protocol.id
otkb.protocol.name
otkb.protocol.wireshark_dissector
otkb.protocol.zeek_parser
EOF
LC_ALL=C sort -u "${work_dir}/expected-compact-fields.txt" \
  -o "${work_dir}/expected-compact-fields.txt"

comm -13 \
  "${work_dir}/expected-compact-fields.txt" \
  "${work_dir}/compact-fields.txt" > "${work_dir}/unexpected-compact-fields.txt"

comm -13 \
  "${work_dir}/verbose-fields.txt" \
  "${work_dir}/compact-fields.txt" > "${work_dir}/compact-only-fields.txt"

comm -23 \
  "${work_dir}/verbose-fields.txt" \
  "${work_dir}/compact-fields.txt" > "${work_dir}/verbose-only-fields.txt"

##############################################################################################
# Count fields that should remain available to dashboards and ATT&CK processing in either mode.
read -r -d '' jq_retained_counts <<'JQ' || true
def source:
  if type == "object" and has("_source") then ._source else . end;

reduce inputs as $input (
  {
    documents: 0,
    function_id: 0,
    function_name: 0,
    classifier_name: 0,
    defend_id: 0,
    protocol_name: 0,
    asset_name: 0,
    campaign_name: 0,
    software_name: 0,
    threat_framework: 0,
    threat_tactic_id: 0,
    threat_technique_id: 0
  };

  ($input | source) as $doc |
  .documents += 1 |
  .function_id +=
    (if $doc.otkb.function.id? != null then 1 else 0 end) |
  .function_name +=
    (if $doc.otkb.function.name? != null then 1 else 0 end) |
  .classifier_name +=
    (if $doc.otkb.function.otkb_classifier.name? != null then 1 else 0 end) |
  .defend_id +=
    (if $doc.otkb.function.otkb_classifier.defend_id? != null then 1 else 0 end) |
  .protocol_name +=
    (if $doc.otkb.protocol.name? != null then 1 else 0 end) |
  .asset_name +=
    (if any($doc.otkb.procedures[]?; .asset.name? != null) then 1 else 0 end) |
  .campaign_name +=
    (if any($doc.otkb.procedures[]?; .campaign.name? != null) then 1 else 0 end) |
  .software_name +=
    (if any($doc.otkb.procedures[]?; .software.name? != null) then 1 else 0 end) |
  .threat_framework +=
    (if $doc.threat.framework? == "MITRE ATT&CK for ICS" then 1 else 0 end) |
  .threat_tactic_id +=
    (if $doc.threat.tactic.id? != null then 1 else 0 end) |
  .threat_technique_id +=
    (if $doc.threat.technique.id? != null then 1 else 0 end)
)
JQ

jq -n "${jq_retained_counts}" "${compact_file}" > "${work_dir}/compact-retained.json"
jq -n "${jq_retained_counts}" "${verbose_file}" > "${work_dir}/verbose-retained.json"

##############################################################################################
# Count representative fields that should appear only in the expanded verbose records.
read -r -d '' jq_verbose_markers <<'JQ' || true
def source:
  if type == "object" and has("_source") then ._source else . end;

reduce inputs as $input (
  {
    documents: 0,
    function_updated_at: 0,
    function_notes: 0,
    function_citations: 0,
    protocol_transport: 0,
    protocol_citations: 0,
    procedure_ids: 0,
    procedure_citations: 0,
    related_record_citations: 0
  };

  ($input | source) as $doc |
  .documents += 1 |
  .function_updated_at +=
    (if $doc.otkb.function.updated_at? != null then 1 else 0 end) |
  .function_notes +=
    (if $doc.otkb.function.notes? != null then 1 else 0 end) |
  .function_citations +=
    (if $doc.otkb.function.citations? != null then 1 else 0 end) |
  .protocol_transport +=
    (if $doc.otkb.protocol.transport? != null then 1 else 0 end) |
  .protocol_citations +=
    (if $doc.otkb.protocol.citations? != null then 1 else 0 end) |
  .procedure_ids +=
    (if any($doc.otkb.procedures[]?; .id? != null) then 1 else 0 end) |
  .procedure_citations +=
    (if any($doc.otkb.procedures[]?; .citations? != null) then 1 else 0 end) |
  .related_record_citations +=
    (if any(
          $doc.otkb.procedures[]?;
          (.asset.citations? != null) or
          (.campaign.citations? != null) or
          (.software.citations? != null)
        )
     then 1 else 0 end)
)
JQ

jq -n "${jq_verbose_markers}" "${compact_file}" > "${work_dir}/compact-markers.json"
jq -n "${jq_verbose_markers}" "${verbose_file}" > "${work_dir}/verbose-markers.json"

compact_documents=$(jq -r '.documents' "${work_dir}/compact-retained.json")
verbose_documents=$(jq -r '.documents' "${work_dir}/verbose-retained.json")
compact_bytes=$(wc -c < "${compact_file}")
verbose_bytes=$(wc -c < "${verbose_file}")

echo
echo 'OTKB compact versus verbose validation'
echo '========================================'

if (( compact_documents == verbose_documents )); then
  pass "Document counts match (${compact_documents})"
else
  fail "Document counts differ: compact=${compact_documents}, verbose=${verbose_documents}"
fi

if [[ ! -s "${work_dir}/unexpected-compact-fields.txt" ]]; then
  pass 'Compact output contains only approved fields'
else
  fail 'Compact output contains fields outside the approved set'
  sed 's/^/      /' "${work_dir}/unexpected-compact-fields.txt"
fi

if [[ ! -s "${work_dir}/compact-only-fields.txt" ]]; then
  pass 'Every compact field is also present in verbose output'
else
  fail 'Some compact fields are absent from verbose output'
  sed 's/^/      /' "${work_dir}/compact-only-fields.txt"
fi

if [[ -s "${work_dir}/verbose-only-fields.txt" ]]; then
  pass 'Verbose output contains additional expanded fields'
else
  fail 'Verbose output contains no fields beyond compact output'
fi

compact_marker_total=$(jq \
  '[to_entries[] | select(.key != "documents") | .value] | add // 0' \
  "${work_dir}/compact-markers.json")

if (( compact_marker_total == 0 )); then
  pass 'Compact output contains no representative verbose-only fields'
else
  fail "Compact output contains ${compact_marker_total} verbose-only field occurrence(s)"
  jq . "${work_dir}/compact-markers.json"
fi

if cmp -s "${work_dir}/compact-retained.json" "${work_dir}/verbose-retained.json"; then
  pass 'Dashboard and threat field counts match'
else
  fail 'Dashboard or threat field counts differ'
  echo '      Compact:'
  jq . "${work_dir}/compact-retained.json" | sed 's/^/        /'
  echo '      Verbose:'
  jq . "${work_dir}/verbose-retained.json" | sed 's/^/        /'
fi

if (( compact_bytes < verbose_bytes )); then
  reduction=$(jq -n \
    --argjson compact "${compact_bytes}" \
    --argjson verbose "${verbose_bytes}" \
    '((1 - ($compact / $verbose)) * 100) | round')
  pass "Compact output is smaller (${compact_bytes} versus ${verbose_bytes} bytes; ${reduction}% reduction)"
else
  fail "Compact output is not smaller (${compact_bytes} versus ${verbose_bytes} bytes)"
fi

echo
echo 'Compact fields'
echo '--------------'
sed 's/^/  /' "${work_dir}/compact-fields.txt"

echo
echo 'Fields removed from compact output'
echo '----------------------------------'
sed 's/^/  /' "${work_dir}/verbose-only-fields.txt"

echo
echo 'Representative verbose-only field counts'
echo '----------------------------------------'
echo 'Compact:'
jq . "${work_dir}/compact-markers.json"
echo 'Verbose:'
jq . "${work_dir}/verbose-markers.json"

echo
printf 'Summary: %d passed, %d failed\n' "${pass_count}" "${fail_count}"

(( fail_count == 0 ))
