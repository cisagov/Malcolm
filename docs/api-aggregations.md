# Field Aggregations

`GET` or `POST` - /mapi/agg/`<fieldname>`

Executes an OpenSearch [bucket aggregation](https://opensearch.org/docs/latest/opensearch/bucket-agg/) query for the requested fields across all of Malcolm's indexed network traffic metadata.

Parameters:

* `fieldname` (URL parameter) - the name(s) of the field(s) to be queried (comma-separated if multiple fields) (default: `event.provider`)
* `limit` (query parameter) - the maximum number of records to return at each level of aggregation (default: 500)
* `from` (query parameter) - the time frame ([`gte`](https://opensearch.org/docs/latest/opensearch/query-dsl/term/#range)) for the beginning of the search based on the session's `firstPacket` field value in a format supported by the [dateparser](https://github.com/scrapinghub/dateparser) library (default: "1 day ago")
* `to` (query parameter) - the time frame ([`lte`](https://opensearch.org/docs/latest/opensearch/query-dsl/term/#range)) for the beginning of the search based on the session's `firstPacket` field value in a format supported by the [dateparser](https://github.com/scrapinghub/dateparser) library (default: "now")
* `filter` (query parameter) - field filters formatted as a JSON dictionary

The `from`, `to`, and `filter` parameters can be used to further restrict the range of documents returned. The `filter` dictionary should be formatted such that its keys are field names and its values are the values for which to filter. A field name may be prepended with a `!` to negate the filter (e.g., `{"event.provider":"zeek"}` vs. `{"!event.provider":"zeek"}`). Filtering for value `null` implies "is not set" or "does not exist" (e.g., `{"event.dataset":null}` means "the field `event.dataset` is `null`/is not set" while `{"!event.dataset":null}` means "the field `event.dataset` is not `null`/is set").

Examples of `filter` parameter:

* `{"!network.transport":"icmp"}` - `network.transport` is not `icmp`
* `{"network.direction":["inbound","outbound"]}` - `network.direction` is either `inbound` or `outbound`
* `{"event.provider":"zeek","event.dataset":["conn","dns"]}` - "`event.provider` is `zeek` and `event.dataset` is either `conn` or `dns`"
* `{"!event.dataset":null}` - "`event.dataset` is set (is not `null`)"

See [Examples](api-examples.md#APIExamples) for more examples of `filter` and corresponding output.