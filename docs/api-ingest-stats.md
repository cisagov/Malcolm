# Document Ingest Statistics

`GET` - /mapi/ingest-stats

Executes an OpenSearch [bucket aggregation](https://opensearch.org/docs/latest/opensearch/bucket-agg/) query for the `host.name` field and its maximum (i.e., most regent) `event.ingested` UTC time value for all of Malcolm's indexed network traffic metadata.

This can be used to know the most recent time a log was indexed for each network sensor.

Example output:

```
{
  "sources": {
    "malcolm": "2024-11-04T14:58:57+00:00",
    "sensor_a": "2024-11-04T14:57:41+00:00",
    "sensor_b": "2024-11-04T14:58:59+00:00"
  },
  "latest_ingest_age_seconds": 107
}
```