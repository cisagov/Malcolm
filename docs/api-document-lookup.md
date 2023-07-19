# Document Lookup

`GET` or `POST` - /mapi/document

Executes an OpenSearch [query](https://opensearch.org/docs/latest/opensearch/bucket-agg/) for the matching documents across all of Malcolm's indexed network traffic metadata.

Parameters:

* `limit` (query parameter) - the maximum number of documents to return (default: 500)
* `from` (query parameter) - the time frame ([`gte`](https://opensearch.org/docs/latest/opensearch/query-dsl/term/#range)) for the beginning of the search based on the session's `firstPacket` field value in a format supported by the [dateparser](https://github.com/scrapinghub/dateparser) library (default: the UNIX epoch)
* `to` (query parameter) - the time frame ([`lte`](https://opensearch.org/docs/latest/opensearch/query-dsl/term/#range)) for the beginning of the search based on the session's `firstPacket` field value in a format supported by the [dateparser](https://github.com/scrapinghub/dateparser) library (default: "now")
* `filter` (query parameter) - field filters formatted as a JSON dictionary (see **Field Aggregations** for examples)

**Example cURL command and output:**

```
$ curl -k -u username -L -XPOST -H 'Content-Type: application/json' \
    'https://localhost/mapi/document' \
    -d '{"limit": 10, filter":{"zeek.uid":"CYeji2z7CKmPRGyga"}}'
```

```json
{
    "filter": {
        "zeek.uid": "CYeji2z7CKmPRGyga"
    },
    "range": [
        0,
        1643056677
    ],
    "results": [
        {
            "_id": "220124-CYeji2z7CKmPRGyga-http-7677",
            "_index": "arkime_sessions3-220124",
            "_score": 0.0,
            "_source": {
                "@timestamp": "2022-01-24T20:31:01.846Z",
                "@version": "1",
                "agent": {
                    "hostname": "filebeat",
                    "id": "bc25716b-8fe7-4de6-a357-65c7d3c15c33",
                    "name": "filebeat",
                    "type": "filebeat",
                    "version": "7.10.2"
                },
                "client": {
                    "bytes": 0
                },
                "destination": {
                    "as": {
                        "full": "AS54113 Fastly"
                    },
                    "geo": {
                        "city_name": "Seattle",
                        "continent_code": "NA",
                        "country_code2": "US",
                        "country_code3": "US",
                        "country_iso_code": "US",
                        "country_name": "United States",
                        "dma_code": 819,
                        "ip": "151.101.54.132",
                        "latitude": 47.6092,
                        "location": {
                            "lat": 47.6092,
                            "lon": -122.3314
                        },
                        "longitude": -122.3314,
                        "postal_code": "98111",
                        "region_code": "WA",
                        "region_name": "Washington",
                        "timezone": "America/Los_Angeles"
                    },
                    "ip": "151.101.54.132",
                    "port": 80
                },
                "ecs": {
                    "version": "1.6.0"
                },
                "event": {
                    "action": [
                        "GET"
                    ],
                    "category": [
                        "web",
                        "network"
                    ],
…
```