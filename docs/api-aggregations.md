# Field Aggregations

`GET` or `POST` - `/mapi/agg/<fieldname>` (or `/mapi/agg` for `event.provider`)

Executes an OpenSearch bucket aggregation for the requested fields in the configured index for the selected document type.

## Parameters

For GET requests, supply query parameters. For POST requests, supply a JSON object with `Content-Type: application/json`. POST parameters are read from the body; `fieldname` remains part of the URL.

| Parameter | Description | Default |
|---|---|---|
| `fieldname` | URL parameter identifying the field to aggregate. Comma-separated names create nested aggregations in the supplied order. | `event.provider` |
| `limit` | Positive integer specifying the maximum number of buckets at each aggregation level. | `RESULT_SET_LIMIT`, normally `500` |
| `from` | Inclusive beginning of the time range, supplied as a string containing UNIX epoch seconds or a date/time supported by [dateparser](https://github.com/scrapinghub/dateparser). | `"1 day ago"` |
| `to` | Inclusive end of the time range, using the same string formats as `from`. | `"now"` |
| `filter` | Field filters as a JSON dictionary. Use a JSON-encoded string in GET or an object in POST. | No field filters |
| `doctype` | Selects the configured index pattern and time-filter field. Canonical values are `network`, `host`, and `arkime`. | `DOCTYPE_DEFAULT`, normally `network` |

The default time-filter field is `firstPacket` for network and Arkime documents and `@timestamp` for host documents. The index patterns and time fields are configurable. Send `from` and `to` as strings in POST bodies too. Use `to` for the end of the range; `till` is ignored.

## Field filters

The `filter` dictionary's keys are field names and its values are the values to match. Filters for different fields are combined with AND. A list of values matches any of its members. A field name may be prepended with `!` to negate the filter. A `null` value tests whether a field is missing; combining `!` and `null` tests whether it exists.

Examples:

* `{"!network.transport":"icmp"}` - `network.transport` is not `icmp`.
* `{"network.direction":["inbound","outbound"]}` - `network.direction` is either `inbound` or `outbound`.
* `{"event.provider":"zeek","event.dataset":["conn","dns"]}` - `event.provider` is `zeek` and `event.dataset` is either `conn` or `dns`.
* `{"event.dataset":null}` - `event.dataset` is missing.
* `{"!event.dataset":null}` - `event.dataset` exists.

## Response and search status

The top-level aggregation key is the first requested field name. Nested aggregation keys use each subsequent field name. The response also contains `fields`, the resolved time `range` in UNIX epoch seconds, and the parsed `filter`. A `urls` array is included when relevant dashboard links are available.

Both `shards` and `timed_out` are passed through from the backend. `shards` contains the complete `_shards` object, including `failures` when supplied. Either status field is `null` if unavailable.

Partial results remain HTTP 200. If `shards.failed > 0` or `timed_out == true`, treat bucket counts as incomplete. Missing status metadata means completeness is unknown. An empty bucket array alone cannot establish that no documents matched. See [Search completeness](api.md#search-completeness).

The bucket limit and the backend's terms-aggregation behavior can also limit the returned data, even when every shard succeeds. Inspect `sum_other_doc_count` and `doc_count_error_upper_bound` in each aggregation where provided. Search-status metadata does not establish that every bucket was returned or that each distributed bucket count is exact.

`sort`, `offset`, `track_total_hits`, and a document `total` response are specific to [Document Lookup](api-document-lookup.md). This aggregation endpoint does not implement those parameters.

The first aggregation field cannot be `range`, `filter`, `fields`, `urls`, `shards`, or `timed_out`, because these are reserved response keys. Such requests return HTTP 400. These names may still appear as nested aggregation fields.

An invalid `limit`, including zero, a negative or fractional number, or a JSON boolean, returns HTTP 400 with an `error` string. Backend exceptions retain the existing generic HTTP 500 response.

## Example

```bash
curl -k -u username -L -G 'https://localhost/mapi/agg/event.provider' \
    --data-urlencode 'from=0' \
    --data-urlencode 'to=2026-10-05T17:30:00Z' \
    --data-urlencode 'limit=10'
```

Illustrative response:

```json
{
  "event.provider": {
    "buckets": [
      {"doc_count": 2194, "key": "zeek"},
      {"doc_count": 697, "key": "suricata"}
    ],
    "doc_count_error_upper_bound": 0,
    "sum_other_doc_count": 0
  },
  "fields": ["event.provider"],
  "filter": null,
  "range": [0, 1791221400],
  "shards": {"total": 2, "successful": 2, "skipped": 0, "failed": 0},
  "timed_out": false,
  "urls": [
    "/dashboards/app/dashboards#/view/0ad3d7c2-3441-485e-9dfe-dbb22e84e576?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:'1970-01-01T00:00:00Z',to:'2026-10-05T17:30:00Z'))"
  ]
}
```

See [Examples](api-examples.md#APIExamples) for additional filters and aggregation responses.
