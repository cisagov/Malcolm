#!/usr/bin/env bash

set -Eeuo pipefail

: "${MALCOLM_NETWORK_INDEX_PATTERN:?Set MALCOLM_NETWORK_INDEX_PATTERN to the OpenSearch index pattern to validate}"

OUTPUT_DIR="${OUTPUT_DIR:-otkb-validation}"
OPENSEARCH_URL="${OPENSEARCH_URL:-https://opensearch:9200}"
CURL_CONFIG="${CURL_CONFIG:-/var/local/curlrc/.opensearch.primary.curlrc}"

mkdir -p "${OUTPUT_DIR}"

run_query() {
  local filename="$1"
  local jq_filter="$2"
  local output_path="${OUTPUT_DIR}/${filename}"
  local temporary_path="${output_path}.tmp"

  if curl --silent --show-error --fail-with-body --insecure \
      --config "${CURL_CONFIG}" \
      --header 'Content-Type: application/json' \
      --request POST \
      "${OPENSEARCH_URL}/${MALCOLM_NETWORK_INDEX_PATTERN}/_search" \
      --data-binary @- | jq "
        if .timed_out == true then
          error(\"OpenSearch query timed out\")
        elif (._shards.failed // 0) > 0 then
          error(\"OpenSearch query had failed shards\")
        else
          (${jq_filter})
        end
      " > "${temporary_path}"; then
    mv "${temporary_path}" "${output_path}"
    printf 'Wrote %s\n' "${output_path}"
  else
    rm -f "${temporary_path}"
    return 1
  fi
}

validation_results=()
validation_failures=0

add_validation_result() {
  local status="$1"
  local check_name="$2"
  local detail="$3"

  validation_results+=(
    "$(
      jq --compact-output --null-input \
        --arg status "${status}" \
        --arg check "${check_name}" \
        --arg detail "${detail}" \
        '{status: $status, check: $check, detail: $detail}'
    )"
  )

  printf '%-4s  %-48s %s\n' "${status}" "${check_name}" "${detail}"

  if [[ "${status}" == 'FAIL' ]]; then
    validation_failures=$((validation_failures + 1))
  fi
}

read_number() {
  local filename="$1"
  local jq_filter="$2"

  jq --exit-status --raw-output \
    "(${jq_filter}) | if type == \"object\" then .value else . end | select(type == \"number\")" \
    "${OUTPUT_DIR}/${filename}"
}

check_zero() {
  local filename="$1"
  local jq_filter="$2"
  local check_name="$3"
  local success_detail="$4"
  local count

  if ! count="$(read_number "${filename}" "${jq_filter}")"; then
    add_validation_result \
      'FAIL' \
      "${check_name}" \
      "Could not read a numeric result from ${filename}"
  elif (( count == 0 )); then
    add_validation_result 'PASS' "${check_name}" "${success_detail}"
  else
    add_validation_result 'FAIL' "${check_name}" "${count} failing document(s)"
  fi
}

write_validation_report() {
  local report_path="${OUTPUT_DIR}/otkb-validation-results.json"
  local temporary_path="${report_path}.tmp"
  local passed
  local failed
  local skipped

  passed="$(printf '%s\n' "${validation_results[@]}" | jq --slurp '[.[] | select(.status == "PASS")] | length')"
  failed="$(printf '%s\n' "${validation_results[@]}" | jq --slurp '[.[] | select(.status == "FAIL")] | length')"
  skipped="$(printf '%s\n' "${validation_results[@]}" | jq --slurp '[.[] | select(.status == "SKIP")] | length')"

  printf '%s\n' "${validation_results[@]}" | jq --slurp \
    --arg generated_at "$(date --utc +'%Y-%m-%dT%H:%M:%SZ')" \
    --arg index_pattern "${MALCOLM_NETWORK_INDEX_PATTERN}" \
    --argjson passed "${passed}" \
    --argjson failed "${failed}" \
    --argjson skipped "${skipped}" \
    '{
      generated_at: $generated_at,
      index_pattern: $index_pattern,
      summary: {
        passed: $passed,
        failed: $failed,
        skipped: $skipped
      },
      results: .
    }' > "${temporary_path}"

  mv "${temporary_path}" "${report_path}"
  printf '\nSummary: %s passed, %s failed, %s skipped\n' \
    "${passed}" "${failed}" "${skipped}"
  printf 'Wrote %s\n' "${report_path}"
}

run_query 'otkb-enrichment-counts.json' \
  '.aggregations.validation_counts.buckets' <<'JSON'
{
  "size": 0,
  "aggs": {
    "validation_counts": {
      "filters": {
        "filters": {
          "ot_events": {
            "term": {
              "event.category": "ot"
            }
          },
          "otkb_enriched_events": {
            "exists": {
              "field": "otkb.function.id"
            }
          },
          "eligible_events": {
            "bool": {
              "should": [
                {
                  "bool": {
                    "filter": [
                      { "term": { "event.provider": "zeek" } },
                      { "term": { "event.category": "ot" } }
                    ]
                  }
                },
                {
                  "term": {
                    "event.provider": "wireshark"
                  }
                }
              ],
              "minimum_should_match": 1
            }
          },
          "eligible_without_otkb_function": {
            "bool": {
              "filter": [
                {
                  "bool": {
                    "should": [
                      {
                        "bool": {
                          "filter": [
                            { "term": { "event.provider": "zeek" } },
                            { "term": { "event.category": "ot" } }
                          ]
                        }
                      },
                      { "term": { "event.provider": "wireshark" } }
                    ],
                    "minimum_should_match": 1
                  }
                }
              ],
              "must_not": [
                { "exists": { "field": "otkb.function.id" } }
              ]
            }
          },
          "zeek_ot_events": {
            "bool": {
              "filter": [
                { "term": { "event.provider": "zeek" } },
                { "term": { "event.category": "ot" } }
              ]
            }
          },
          "zeek_ot_without_otkb_function": {
            "bool": {
              "filter": [
                { "term": { "event.provider": "zeek" } },
                { "term": { "event.category": "ot" } }
              ],
              "must_not": [
                { "exists": { "field": "otkb.function.id" } }
              ]
            }
          },
          "wireshark_events": {
            "term": {
              "event.provider": "wireshark"
            }
          },
          "wireshark_without_otkb_function": {
            "bool": {
              "filter": [
                { "term": { "event.provider": "wireshark" } }
              ],
              "must_not": [
                { "exists": { "field": "otkb.function.id" } }
              ]
            }
          }
        }
      }
    }
  }
}
JSON

run_query 'otkb-exceptions.json' \
  '{total: .hits.total, samples: [.hits.hits[]._source]}' <<'JSON'
{
  "size": 100,
  "track_total_hits": true,
  "_source": [
    "@timestamp",
    "event.provider",
    "event.dataset",
    "event.category",
    "network.protocol",
    "tags",
    "error.*"
  ],
  "query": {
    "terms": {
      "tags": [
        "_rubyexception_otkb_enrich",
        "_otkb_enrich"
      ]
    }
  }
}
JSON

run_query 'otkb-enriched-samples.json' \
  '{total: .hits.total, samples: [.hits.hits[]._source]}' <<'JSON'
{
  "size": 25,
  "track_total_hits": true,
  "_source": [
    "@timestamp",
    "event.provider",
    "event.dataset",
    "event.category",
    "network.protocol",
    "otkb.*",
    "threat.*"
  ],
  "query": {
    "exists": {
      "field": "otkb.function.id"
    }
  }
}
JSON

run_query 'otkb-structural-validation.json' \
  '.aggregations.structural_checks.buckets' <<'JSON'
{
  "size": 0,
  "query": {
    "exists": {
      "field": "otkb.function.id"
    }
  },
  "aggs": {
    "structural_checks": {
      "filters": {
        "filters": {
          "function_missing_name": {
            "bool": {
              "must_not": [
                { "exists": { "field": "otkb.function.name" } }
              ]
            }
          },
          "function_missing_protocol": {
            "bool": {
              "must_not": [
                { "exists": { "field": "otkb.function.protocol" } }
              ]
            }
          },
          "protocol_missing_id": {
            "bool": {
              "must_not": [
                { "exists": { "field": "otkb.protocol.id" } }
              ]
            }
          },
          "protocol_missing_name": {
            "bool": {
              "must_not": [
                { "exists": { "field": "otkb.protocol.name" } }
              ]
            }
          }
        }
      }
    }
  }
}
JSON

run_query 'ot-event-distribution.json' \
  '{total_ot_events: .hits.total, providers: .aggregations.providers.buckets, datasets: .aggregations.datasets.buckets, protocols: .aggregations.protocols.buckets}' <<'JSON'
{
  "size": 0,
  "track_total_hits": true,
  "query": {
    "term": {
      "event.category": "ot"
    }
  },
  "aggs": {
    "providers": {
      "terms": {
        "field": "event.provider",
        "size": 20
      }
    },
    "datasets": {
      "terms": {
        "field": "event.dataset",
        "size": 250
      }
    },
    "protocols": {
      "terms": {
        "field": "network.protocol",
        "size": 100
      }
    }
  }
}
JSON

run_query 'otkb-eligible-protocol-distribution.json' \
  '.aggregations.protocols.buckets' <<'JSON'
{
  "size": 0,
  "query": {
    "bool": {
      "should": [
        {
          "bool": {
            "filter": [
              { "term": { "event.provider": "zeek" } },
              { "term": { "event.category": "ot" } }
            ]
          }
        },
        {
          "term": {
            "event.provider": "wireshark"
          }
        }
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "protocols": {
      "terms": {
        "field": "network.protocol",
        "size": 100
      }
    }
  }
}
JSON

run_query 'ot-without-otkb-samples.json' \
  '{total: .hits.total, datasets: .aggregations.datasets.buckets, protocols: .aggregations.protocols.buckets, samples: [.hits.hits[]._source]}' <<'JSON'
{
  "size": 20,
  "track_total_hits": true,
  "_source": [
    "@timestamp",
    "event.provider",
    "event.dataset",
    "event.category",
    "network.protocol",
    "zeek.*",
    "wireshark.*"
  ],
  "query": {
    "bool": {
      "filter": [
        { "term": { "event.category": "ot" } }
      ],
      "must_not": [
        { "exists": { "field": "otkb.function.id" } }
      ]
    }
  },
  "aggs": {
    "datasets": {
      "terms": {
        "field": "event.dataset",
        "size": 250
      }
    },
    "protocols": {
      "terms": {
        "field": "network.protocol",
        "size": 100
      }
    }
  }
}
JSON

run_query 'ot-classification-checks.json' \
  '.aggregations.classification_checks.buckets' <<'JSON'
{
  "size": 0,
  "aggs": {
    "classification_checks": {
      "filters": {
        "filters": {
          "attackics_total": {
            "term": {
              "zeek.notice.category": "ATTACKICS"
            }
          },
          "attackics_missing_ot": {
            "bool": {
              "filter": [
                { "term": { "zeek.notice.category": "ATTACKICS" } }
              ],
              "must_not": [
                { "term": { "event.category": "ot" } }
              ]
            }
          },
          "bestguess_total": {
            "bool": {
              "should": [
                { "term": { "event.dataset": "bestguess" } },
                { "exists": { "field": "zeek.bestguess.category" } }
              ],
              "minimum_should_match": 1
            }
          },
          "bestguess_missing_ot": {
            "bool": {
              "filter": [
                {
                  "bool": {
                    "should": [
                      { "term": { "event.dataset": "bestguess" } },
                      { "exists": { "field": "zeek.bestguess.category" } }
                    ],
                    "minimum_should_match": 1
                  }
                }
              ],
              "must_not": [
                { "term": { "event.category": "ot" } }
              ]
            }
          },
          "legacy_ics_tag": {
            "term": {
              "tags": "ics"
            }
          },
          "legacy_ics_best_guess_tag": {
            "term": {
              "tags": "ics_best_guess"
            }
          }
        }
      }
    }
  }
}
JSON

run_query 'otkb-protocol-samples.json' \
  '.aggregations.by_protocol.buckets' <<'JSON'
{
  "size": 0,
  "query": {
    "exists": {
      "field": "otkb.function.id"
    }
  },
  "aggs": {
    "by_protocol": {
      "filters": {
        "filters": {
          "bacnet": { "term": { "network.protocol": "bacnet" } },
          "cip": { "term": { "network.protocol": "cip" } },
          "dnp3": { "term": { "network.protocol": "dnp3" } },
          "enip": { "term": { "network.protocol": "enip" } },
          "ge_srtp": { "term": { "network.protocol": "ge_srtp" } },
          "gems": { "term": { "network.protocol": "gems" } },
          "iec104": { "term": { "network.protocol": "iec104" } },
          "iec61850": { "term": { "network.protocol": "iec61850" } },
          "modbus": { "term": { "network.protocol": "modbus" } },
          "rtl": { "term": { "network.protocol": "rtl" } },
          "space_packet_protocol": { "term": { "network.protocol": "space_packet_protocol" } }
        }
      },
      "aggs": {
        "samples": {
          "top_hits": {
            "size": 5,
            "_source": [
              "@timestamp",
              "event.*",
              "network.*",
              "zeek.*",
              "wireshark.*",
              "otkb.*",
              "threat.*"
            ]
          }
        }
      }
    }
  }
}
JSON

run_query 'otkb-threat-content.json' \
  '{total: .hits.total, counts: .aggregations.content_counts.buckets, samples: [.hits.hits[]._source]}' <<'JSON'
{
  "size": 20,
  "track_total_hits": true,
  "_source": [
    "@timestamp",
    "event.*",
    "network.*",
    "otkb.function.*",
    "otkb.procedures.*",
    "threat.*"
  ],
  "query": {
    "bool": {
      "should": [
        { "exists": { "field": "otkb.procedures.id" } },
        { "exists": { "field": "threat.technique.id" } },
        { "exists": { "field": "threat.tactic.id" } }
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "content_counts": {
      "filters": {
        "filters": {
          "has_procedures": { "exists": { "field": "otkb.procedures.id" } },
          "has_threat_technique_id": { "exists": { "field": "threat.technique.id" } },
          "has_threat_technique_name": { "exists": { "field": "threat.technique.name" } },
          "has_threat_technique_reference": { "exists": { "field": "threat.technique.reference" } },
          "has_threat_tactic_id": { "exists": { "field": "threat.tactic.id" } },
          "has_threat_tactic_name": { "exists": { "field": "threat.tactic.name" } },
          "has_threat_tactic_reference": { "exists": { "field": "threat.tactic.reference" } },
          "has_threat_indicator": { "exists": { "field": "threat.indicator.name" } }
        }
      }
    }
  }
}
JSON

run_query 'otkb-threat-translation-validation.json' \
  '{
    total_procedure_documents: .hits.total,
    attack_ids: .aggregations.attack_ids.buckets,
    frameworks: .aggregations.frameworks.buckets,
    validation: .aggregations.translation_checks.buckets,
    sampled_shape_failures: [
      .hits.hits[]._source
      | select(
          ((.threat.tactic.name? // []) | if type == "array" then any(.[]; type == "array") else false end)
          or
          ((.threat.technique.name? // []) | if type == "array" then any(.[]; type == "array") else false end)
        )
    ],
    samples: [.hits.hits[]._source]
  }' <<'JSON'
{
  "size": 100,
  "track_total_hits": true,
  "_source": [
    "@timestamp",
    "event.provider",
    "event.dataset",
    "event.category",
    "network.protocol",
    "otkb.function.id",
    "otkb.function.name",
    "otkb.procedures.*",
    "threat.*"
  ],
  "query": {
    "exists": {
      "field": "otkb.procedures.id"
    }
  },
  "aggs": {
    "attack_ids": {
      "terms": {
        "field": "otkb.procedures.attack_id",
        "size": 250
      }
    },
    "frameworks": {
      "terms": {
        "field": "threat.framework",
        "size": 20
      }
    },
    "translation_checks": {
      "filters": {
        "filters": {
          "has_technique_id": { "exists": { "field": "threat.technique.id" } },
          "technique_id_missing_name": {
            "bool": {
              "filter": [ { "exists": { "field": "threat.technique.id" } } ],
              "must_not": [ { "exists": { "field": "threat.technique.name" } } ]
            }
          },
          "technique_id_missing_reference": {
            "bool": {
              "filter": [ { "exists": { "field": "threat.technique.id" } } ],
              "must_not": [ { "exists": { "field": "threat.technique.reference" } } ]
            }
          },
          "technique_reference_wrong_path": {
            "bool": {
              "filter": [ { "exists": { "field": "threat.technique.reference" } } ],
              "must_not": [
                {
                  "prefix": {
                    "threat.technique.reference": "https://attack.mitre.org/techniques/"
                  }
                }
              ]
            }
          },
          "has_tactic_id": { "exists": { "field": "threat.tactic.id" } },
          "tactic_id_missing_name": {
            "bool": {
              "filter": [ { "exists": { "field": "threat.tactic.id" } } ],
              "must_not": [ { "exists": { "field": "threat.tactic.name" } } ]
            }
          },
          "tactic_id_missing_reference": {
            "bool": {
              "filter": [ { "exists": { "field": "threat.tactic.id" } } ],
              "must_not": [ { "exists": { "field": "threat.tactic.reference" } } ]
            }
          },
          "tactic_reference_wrong_path": {
            "bool": {
              "filter": [ { "exists": { "field": "threat.tactic.reference" } } ],
              "must_not": [
                {
                  "prefix": {
                    "threat.tactic.reference": "https://attack.mitre.org/tactics/"
                  }
                }
              ]
            }
          },
          "threat_id_missing_framework": {
            "bool": {
              "filter": [
                {
                  "bool": {
                    "should": [
                      { "exists": { "field": "threat.technique.id" } },
                      { "exists": { "field": "threat.tactic.id" } }
                    ],
                    "minimum_should_match": 1
                  }
                }
              ],
              "must_not": [ { "exists": { "field": "threat.framework" } } ]
            }
          }
        }
      }
    }
  }
}
JSON

validate_results() {
  local eligible_events
  local enriched_events
  local unenriched_events
  local total
  local source_count
  local enriched_count
  local invalid_attack_ids
  local invalid_attack_id_values
  local protocol

  printf '\nOTKB validation results\n'
  printf '%s\n' '======================='

  check_zero \
    'otkb-exceptions.json' \
    '.total' \
    'Ruby filter exceptions' \
    'No OTKB Ruby filter exceptions were found'

  if eligible_events="$(read_number 'otkb-enrichment-counts.json' '.eligible_events.doc_count')" &&
     enriched_events="$(read_number 'otkb-enrichment-counts.json' '.otkb_enriched_events.doc_count')" &&
     unenriched_events="$(read_number 'otkb-enrichment-counts.json' '.eligible_without_otkb_function.doc_count')"; then
    if (( eligible_events == 0 )); then
      add_validation_result \
        'SKIP' \
        'OTKB enrichment produced results' \
        'No eligible Zeek OT or Wireshark events were found'
    elif (( enriched_events == 0 )); then
      add_validation_result \
        'FAIL' \
        'OTKB enrichment produced results' \
        "0 of ${eligible_events} eligible events were enriched"
    else
      add_validation_result \
        'PASS' \
        'OTKB enrichment produced results' \
        "${enriched_events} enriched event(s); ${unenriched_events} eligible event(s) had no function match"
    fi
  else
    add_validation_result \
      'FAIL' \
      'OTKB enrichment produced results' \
      'Could not read the enrichment counts'
  fi

  check_zero \
    'otkb-structural-validation.json' \
    '.function_missing_name.doc_count' \
    'Enriched functions have names' \
    'Every enriched function has a name'
  check_zero \
    'otkb-structural-validation.json' \
    '.function_missing_protocol.doc_count' \
    'Enriched functions reference protocols' \
    'Every enriched function references a protocol'
  check_zero \
    'otkb-structural-validation.json' \
    '.protocol_missing_id.doc_count' \
    'Enriched protocols have IDs' \
    'Every enriched protocol has an ID'
  check_zero \
    'otkb-structural-validation.json' \
    '.protocol_missing_name.doc_count' \
    'Enriched protocols have names' \
    'Every enriched protocol has a name'

  if total="$(read_number 'ot-classification-checks.json' '.attackics_total.doc_count')"; then
    if (( total == 0 )); then
      add_validation_result \
        'SKIP' \
        'ATTACKICS notices receive the OT category' \
        'No ATTACKICS notices were found'
    else
      check_zero \
        'ot-classification-checks.json' \
        '.attackics_missing_ot.doc_count' \
        'ATTACKICS notices receive the OT category' \
        "All ${total} ATTACKICS notice(s) have the OT category"
    fi
  else
    add_validation_result \
      'FAIL' \
      'ATTACKICS notices receive the OT category' \
      'Could not read the ATTACKICS count'
  fi

  if total="$(read_number 'ot-classification-checks.json' '.bestguess_total.doc_count')"; then
    if (( total == 0 )); then
      add_validation_result \
        'SKIP' \
        'Best-guess events receive the OT category' \
        'No best-guess events were found'
    else
      check_zero \
        'ot-classification-checks.json' \
        '.bestguess_missing_ot.doc_count' \
        'Best-guess events receive the OT category' \
        "All ${total} best-guess event(s) have the OT category"
    fi
  else
    add_validation_result \
      'FAIL' \
      'Best-guess events receive the OT category' \
      'Could not read the best-guess count'
  fi

  check_zero \
    'ot-classification-checks.json' \
    '.legacy_ics_tag.doc_count' \
    'Legacy ICS tag was removed' \
    'No events contain the legacy ics tag'
  check_zero \
    'ot-classification-checks.json' \
    '.legacy_ics_best_guess_tag.doc_count' \
    'Legacy best-guess tag was removed' \
    'No events contain the legacy ics_best_guess tag'

  for protocol in \
    bacnet \
    cip \
    dnp3 \
    enip \
    ge_srtp \
    gems \
    iec104 \
    iec61850 \
    modbus \
    rtl \
    space_packet_protocol; do
    if ! source_count="$(
      jq --exit-status --raw-output \
        --arg protocol "${protocol}" \
        '[.[]? | select(.key == $protocol) | .doc_count] | add // 0' \
        "${OUTPUT_DIR}/otkb-eligible-protocol-distribution.json"
    )" || ! enriched_count="$(
      jq --exit-status --raw-output \
        --arg protocol "${protocol}" \
        '.[$protocol].doc_count // 0' \
        "${OUTPUT_DIR}/otkb-protocol-samples.json"
    )"; then
      add_validation_result \
        'FAIL' \
        "Protocol coverage: ${protocol}" \
        'Could not read protocol counts'
    elif (( source_count == 0 )); then
      add_validation_result \
        'SKIP' \
        "Protocol coverage: ${protocol}" \
        'No source traffic was found'
    elif (( enriched_count == 0 )); then
      add_validation_result \
        'FAIL' \
        "Protocol coverage: ${protocol}" \
        "${source_count} source event(s) produced no OTKB enrichment"
    else
      add_validation_result \
        'PASS' \
        "Protocol coverage: ${protocol}" \
        "${enriched_count} enriched event(s) from ${source_count} source event(s)"
    fi
  done

  if total="$(read_number 'otkb-threat-translation-validation.json' '.total_procedure_documents')"; then
    if (( total == 0 )); then
      add_validation_result \
        'SKIP' \
        'OTKB procedure and threat translations' \
        'No documents with OTKB procedures were found'
    else
      check_zero \
        'otkb-threat-translation-validation.json' \
        '.validation.technique_id_missing_name.doc_count' \
        'Technique IDs have names' \
        'Every technique ID has a translated name'
      check_zero \
        'otkb-threat-translation-validation.json' \
        '.validation.technique_id_missing_reference.doc_count' \
        'Technique IDs have references' \
        'Every technique ID has a reference'
      check_zero \
        'otkb-threat-translation-validation.json' \
        '.validation.technique_reference_wrong_path.doc_count' \
        'Technique references use the MITRE path' \
        'Every technique reference uses the MITRE technique path'
      check_zero \
        'otkb-threat-translation-validation.json' \
        '.validation.tactic_id_missing_name.doc_count' \
        'Tactic IDs have names' \
        'Every tactic ID has a translated name'
      check_zero \
        'otkb-threat-translation-validation.json' \
        '.validation.tactic_id_missing_reference.doc_count' \
        'Tactic IDs have references' \
        'Every tactic ID has a reference'
      check_zero \
        'otkb-threat-translation-validation.json' \
        '.validation.tactic_reference_wrong_path.doc_count' \
        'Tactic references use the MITRE path' \
        'Every tactic reference uses the MITRE tactic path'
      check_zero \
        'otkb-threat-translation-validation.json' \
        '.validation.threat_id_missing_framework.doc_count' \
        'Threat IDs have a framework' \
        'Every threat ID has a framework'

      if invalid_attack_ids="$(
        jq --exit-status --raw-output \
          '[
            .attack_ids[]?.key
            | select(test("^(T[0-9]{4}(\\.[0-9]{3})?|TA[0-9]{4})$") | not)
          ] | length' \
          "${OUTPUT_DIR}/otkb-threat-translation-validation.json"
      )"; then
        if (( invalid_attack_ids == 0 )); then
          add_validation_result \
            'PASS' \
            'OTKB ATT&CK IDs are normalized' \
            'Every aggregated ATT&CK ID has a normalized format'
        else
          invalid_attack_id_values="$(
            jq --raw-output \
              '[
                .attack_ids[]?.key
                | select(test("^(T[0-9]{4}(\\.[0-9]{3})?|TA[0-9]{4})$") | not)
              ] | join(", ")' \
              "${OUTPUT_DIR}/otkb-threat-translation-validation.json"
          )"
          add_validation_result \
            'FAIL' \
            'OTKB ATT&CK IDs are normalized' \
            "Unexpected value(s): ${invalid_attack_id_values}"
        fi
      else
        add_validation_result \
          'FAIL' \
          'OTKB ATT&CK IDs are normalized' \
          'Could not inspect the aggregated ATT&CK IDs'
      fi

      check_zero \
        'otkb-threat-translation-validation.json' \
        '.sampled_shape_failures | length' \
        'Translated threat names have flat arrays' \
        'No nested tactic or technique name arrays were found in the sample'
    fi
  else
    add_validation_result \
      'FAIL' \
      'OTKB procedure and threat translations' \
      'Could not read the procedure document count'
  fi
}

validate_results
write_validation_report

if (( validation_failures > 0 )); then
  exit 1
fi
