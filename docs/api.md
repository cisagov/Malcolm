# <a name="API"></a>API

* [Dashboard Export](api-dashboard-export.md)
* [Document Ingest Statistics](api-ingest-stats.md)
* [Document Lookup](api-document-lookup.md)
* [Event Logging](api-event-logging.md)
* [Field Aggregations](api-aggregations.md)
* [Fields](api-fields.md)
* [Indices](api-indices.md)
* [Ping](api-ping.md)
* [Ready](api-ready.md)
* [Version](api-version.md)
* [Examples](api-examples.md)

Malcolm provides a [REST API]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/api/project/__init__.py) that can be used to programmatically query some aspects of Malcolm's status and data.

In addition to the items listed above, Malcolm will also forward requests to some of its components' APIs at the following URIs:

* **/mapi/logstash/** - the [Logstash API](https://www.elastic.co/guide/en/logstash/current/monitoring-logstash.html)
* **/mapi/opensearch/** - the [OpenSearch API](https://opensearch.org/docs/latest/api-reference/)
* **/mapi/netbox/** - the [NetBox API](https://netboxlabs.com/docs/netbox/integrations/rest-api/) (also accessible at `/netbox/api/`)
* **/arkime/api/** - the [Arkime Viewer API](https://arkime.com/apiv3)

## Search completeness

[Document Lookup](api-document-lookup.md) and [Field Aggregations](api-aggregations.md) expose backend search status through `shards` and `timed_out`. The `shards` value is the complete backend `_shards` object, including failure details when supplied. Missing status values are returned as `null`.

An HTTP 200 response may contain partial results. Clients should inspect both status fields before interpreting an empty result as “no data” or using counts as complete:

* `shards.failed > 0` indicates shard failures.
* `timed_out == true` indicates a backend search timeout, even if no shard failure is reported.
* A `null` status value means that status is unknown.

Available results remain in the response when the backend returns a partial search response. Backend exceptions continue to return the API's generic HTTP 500 error. Argument validation errors in these endpoints return HTTP 400 with an `error` string.

Document lookup additionally returns `total`, preserving the backend hit count and its `eq` (exact) or `gte` (lower-bound) relation. `total` is independent of the requested page size and offset. A successful search may have more matches than the current page contains. An `eq` relation must still be interpreted alongside search status. See [Total hits](api-document-lookup.md#total-hits) for counting controls and [Sorting and paging](api-document-lookup.md#sorting-and-paging) for page limits.

Aggregation responses retain bucket-level information such as `sum_other_doc_count` and `doc_count_error_upper_bound`. Successful shard status alone does not guarantee that all buckets are included or that distributed bucket counts are exact.

## Debugging document and aggregation searches

With `MALCOLM_API_DEBUG=true`, the API logs request arguments and the constructed query, followed by a compact JSON response summary. Document summaries include the returned hit count, offset, total, and count relation. Aggregation summaries include the requested fields and number of top-level buckets. Both include shard counters, `timed_out`, and backend `took_ms`.

Shard failure details are logged separately when present. Missing response metadata remains `null` in the summary. Response summaries omit document bodies and reuse the response already fetched. Aggregation arguments are parsed and logged once per request.
