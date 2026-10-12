# Document Lookup

`GET` or `POST` - `/mapi/document`

Searches documents in the configured index for the selected document type, applying time and field filters. Responses include the matching hits, total hit information, and backend search status.

## Parameters

For GET requests, supply query parameters. For POST requests, supply a JSON object with `Content-Type: application/json`. POST parameters are read from the body. URL-encode GET parameter values, for example with cURL's `--data-urlencode`.

| Parameter | Description | Default |
|---|---|---|
| `limit` | Nonnegative integer specifying the maximum number of documents to return. Use `0` to retrieve count and status information without document hits. | `RESULT_SET_LIMIT`, normally `500` |
| `offset` | Nonnegative integer specifying how many matching documents to skip. | `0` |
| `sort` | A field expression, comma-separated expressions, or a POST JSON array of expressions. See [Sorting and paging](#sorting-and-paging). | Backend default ordering |
| `track_total_hits` | Boolean or nonnegative integer controlling hit counting. See [Total hits](#total-hits). | Backend default counting |
| `from` | Inclusive beginning of the time range, supplied as a string containing UNIX epoch seconds or a date/time supported by [dateparser](https://github.com/scrapinghub/dateparser). | UNIX epoch |
| `to` | Inclusive end of the time range, using the same string formats as `from`. | `"now"` |
| `filter` | Field filters as a JSON dictionary. Use a JSON-encoded string in GET or an object in POST. See [Field Aggregations](api-aggregations.md) for filter syntax. | No field filters |
| `doctype` | Selects the configured index pattern and time-filter field. Canonical values are `network`, `host`, and `arkime`. | `DOCTYPE_DEFAULT`, normally `network` |

The default time-filter field is `firstPacket` for network and Arkime documents and `@timestamp` for host documents. These fields and index patterns are configurable. Sorting uses the literal field names supplied in `sort` independently of the time-filter field.

Use `to` for the end of the time range. The unrecognized parameter `till` is ignored. Send `from` and `to` as strings in POST bodies too, for example `"from": "0"`.

## Sorting and paging

Accepted sort expressions include:

* `firstPacket` or `firstPacket:asc` for ascending order.
* `-@timestamp` or `@timestamp:desc` for descending order.
* `firstPacket:asc,event.id:asc` for multiple fields in priority order.
* `["firstPacket:asc", "event.id:asc"]` as a POST JSON array.

Directions are case-insensitive. Each field must support sorting in the selected indexes. For example, a keyword field can be used to sort string values. The API supports field/direction expressions; advanced sort objects and scripts are outside this interface. Sorted hits retain the backend's `sort` array.

Use `offset=0&limit=100` for the first page, then `offset=100&limit=100` for the next. The request parameter `from` continues to specify a time boundary. The API translates `offset` into the backend's document offset.

Keep the same explicit time bounds, filters, and sort order between requests. Include a sortable unique tie-breaker field when stable ordering of equal primary values matters. Offset paging operates on live data, so indexing or deletion between requests can change page contents even with fixed time bounds. This endpoint provides no point-in-time snapshot or `search_after` cursor.

`offset + limit` is subject to the selected indexes' `index.max_result_window` setting, commonly `10000`. Deep offsets also increase backend work. Narrow the query's time range or filters when the requested page would exceed the result window.

## Total hits

The response's `total` comes from the backend's `hits.total` and describes matches across the full query, independent of `offset` and `limit`:

```json
{"value": 16179, "relation": "eq"}
```

`eq` indicates an exact count for the search results counted by the backend. `gte` indicates a lower bound. OpenSearch normally counts accurately up to 10,000 matches, then returns a lower bound. The counting threshold is separate from the page-size limit.

* `track_total_hits=true` requests an exact count. This can increase the cost of broad searches.
* `track_total_hits=false` disables counting; the API returns `"total": null`.
* `track_total_hits=1000` requests accurate counting up to that threshold and a lower bound beyond it. Zero is also accepted as a threshold.

For GET, use strings such as `true`, `false`, or `1000`. POST also accepts JSON booleans and integers. If the backend omits `hits.total`, the response contains `"total": null`.

Always inspect `shards` and `timed_out` before treating a count as complete. Even `relation: "eq"` cannot establish completeness when shards failed or the search timed out.

## Response and search status

| Field | Meaning |
|---|---|
| `results` | Array of backend hits, retaining fields such as `_index`, `_id`, `_source`, and `sort` when present. |
| `total` | Hit count object with `value` and `relation`, or `null` when unavailable or disabled. |
| `range` | Resolved inclusive time bounds as UNIX epoch seconds. |
| `filter` | Parsed field filters, or `null` when none were supplied. |
| `shards` | Complete backend `_shards` object, including `failures` when provided. `null` if unavailable. |
| `timed_out` | Backend timeout flag, or `null` if unavailable. |

A backend response containing partial results remains HTTP 200. Treat `shards.failed > 0` or `timed_out == true` as an incomplete search, even if `results` is empty. Missing status metadata means completeness is unknown. See [Search completeness](api.md#search-completeness).

Malformed `sort`, `offset`, `limit`, or `track_total_hits` arguments return HTTP 400 with an `error` string. Negative numbers, fractional numbers, and JSON booleans are rejected for `offset` and `limit`. Backend exceptions, including an unsupported sort field or a result-window violation, use the existing generic HTTP 500 response.

## Examples

Look up documents by an existing field filter:

```bash
curl -k -u username -L -H 'Content-Type: application/json' \
    'https://localhost/mapi/document' \
    -d '{"limit": 10, "filter": {"zeek.uid": "CYeji2z7CKmPRGyga"}}'
```

Fetch a page in ascending timestamp order:

```bash
curl -k -u username -L -G 'https://localhost/mapi/document' \
    --data-urlencode 'from=2026-10-01T00:00:00Z' \
    --data-urlencode 'to=2026-10-02T00:00:00Z' \
    --data-urlencode 'sort=firstPacket:asc' \
    --data-urlencode 'offset=100' \
    --data-urlencode 'limit=100' \
    --data-urlencode 'track_total_hits=true'
```

Equivalent POST parameters can include an ordered array of sort expressions. Choose a secondary field that is sortable and uniquely identifies documents in your data:

```json
{
  "from": "2026-10-01T00:00:00Z",
  "to": "2026-10-02T00:00:00Z",
  "sort": ["firstPacket:asc", "event.id:asc"],
  "offset": 100,
  "limit": 100,
  "track_total_hits": true
}
```

Illustrative response to a lookup matching one document (the `_source` object is abbreviated):

```json
{
  "filter": {"zeek.uid": "CYeji2z7CKmPRGyga"},
  "range": [0, 1643056677],
  "results": [
    {
      "_id": "220124-CYeji2z7CKmPRGyga-http-7677",
      "_index": "arkime_sessions3-220124",
      "_score": 0.0,
      "_source": {
        "@timestamp": "2022-01-24T20:31:01.846Z",
        "zeek": {"uid": "CYeji2z7CKmPRGyga"}
      }
    }
  ],
  "total": {"value": 1, "relation": "eq"},
  "shards": {"total": 2, "successful": 2, "skipped": 0, "failed": 0},
  "timed_out": false
}
```
