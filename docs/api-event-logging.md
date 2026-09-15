# Event Logging

`POST` `/mapi/event` (also accepts `POST` `/mapi/alert`)

A webhook that accepts alert data to be reindexed into OpenSearch as session records for viewing in Malcolm's [dashboards](dashboards.md#Dashboards). See [Alerting](alerting.md#Alerting) for more details and examples of how this API is used.

## How it works

When a POST request is received, the endpoint constructs a document and indexes it into OpenSearch under the configured network index (e.g., the default `arkime_sessions3-YYMMDD`).

The endpoint accepts data from three sources, checked in this order of priority:

1. A structured JSON body under the `alert` key (standard OpenSearch Alerting webhook format)
2. A raw string or JSON object in the `_contents` key
3. A raw string or JSON object in the `_raw` key

## Request body

The top-level `alert` object supports the following fields:

| Field | Type | Description |
|---|---|---|
| `alert.monitor.name` | string | Name of the monitor that generated the alert. Mapped to `rule.name` in the indexed document. |
| `alert.trigger.name` | string | Name of the trigger. Mapped to `event.reason`. |
| `alert.trigger.severity` | integer | OpenSearch severity (1–5, where 1 is highest). Converted to a 0–100 risk score: severity 1 → 100, severity 2 → 80, severity 3 → 60, severity 4 → 40, severity 5 → 20. Mapped to `event.risk_score`, `event.risk_score_norm`, and `event.severity`. |
| `alert.period.start` | ISO 8601 string | Start of the alert period. Used as the document timestamp, `firstPacket`, `event.start`. Falls back to request time if absent. |
| `alert.period.end` | ISO 8601 string | End of the alert period. Mapped to `lastPacket` and `event.end`. Falls back to request time if absent. |
| `alert.results` | array | Raw OpenSearch query results. If present, `results[0].hits.total.value` is mapped to `event.hits`. |
| `alert.alert` | string | The OpenSearch alert ID. Mapped to `event.id`. A random ID is generated if absent. |
| `alert.error` | string | Error string from the alerting plugin, if any. |
| `alert.body` | string or object | Optional arbitrary payload. See [Custom payload via `body`](#custom-payload-via-body) below. |

## Custom payload via `body`

The `alert.body` field is the primary mechanism for including custom data in the indexed document. If present, it is parsed as JSON (or used directly if already an object) and deep-merged into the indexed document.

**Merge behavior:**

- Keys from `body` that do not exist in the document are added at the top level.
- Keys that exist in the document and whose values are both objects are merged recursively.
- Leaf-level collisions (i.e., a key in `body` whose value conflicts with a scalar already set by the handler) are preserved under a top-level `conflicts` key rather than silently dropped or overwritten.

This means you can use `body` to populate ECS-style nested fields. For example, including `{"source": {"ip": [...]}, "destination": {"ip": [...]}, "event": {"risk_score": [...], "severity_tags": [...]}}` in `body` will merge cleanly — `source` and `destination` are added directly, and the fields inside `event` are merged into the existing `event` object without clobbering handler-set fields like `event.kind` or `event.provider`.

> **Note:** The `body` value is parsed with [`python-rapidjson`](https://github.com/python-rapidjson/python-rapidjson), which tolerates trailing commas in arrays and objects. This is useful when [generating](https://docs.opensearch.org/latest/observing-your-data/alerting/actions/) `body` from an OpenSearch Alerting Mustache template, since [Mustache](https://mustache.github.io/mustache.5.html) has no native mechanism to suppress the trailing comma after the last iteration of a loop.

## OpenSearch Alerting integration

This endpoint is designed to be used as a custom webhook destination in OpenSearch Alerting. A Mustache message template targeting this endpoint might look like:

{% raw %}
```json
{
  "alert": {
    "monitor": {"name": "{{ctx.monitor.name}}"},
    "trigger": {"name": "{{ctx.trigger.name}}","severity": {{ctx.trigger.severity}}},
    "period": {"start": "{{ctx.periodStart}}","end": "{{ctx.periodEnd}}"},
    "body": "{\"source\":{\"ip\":[{{#ctx.results.0.aggregations.suspicious_pairs.buckets}}\"{{key.source_ip}}\",{{/ctx.results.0.aggregations.suspicious_pairs.buckets}}]},\"destination\":{\"ip\":[{{#ctx.results.0.aggregations.suspicious_pairs.buckets}}\"{{key.destination_ip}}\",{{/ctx.results.0.aggregations.suspicious_pairs.buckets}}]}}",
    "alert": "{{ctx.alert.id}}",
    "error": "{{ctx.error}}"
  }
}
```
{% endraw %}

The `body` field is a JSON-encoded string containing the aggregation results from the monitor query. The trailing commas produced by Mustache iteration are handled transparently by the parser.

## Indexed document structure

Regardless of input format, every indexed document includes the following fields set by the handler:

| Field | Value |
|---|---|
| `ecs.version` | `1.6.0` |
| `event.kind` | `alert` |
| `event.provider` | `malcolm` |
| `event.dataset` | `alerting` |
| `event.module` | `alerting` |
| `event.url` | `/dashboards/app/alerting#/dashboard` |
| `event.ingested` | Request timestamp (UTC) |
| `event.severity_tags` | `Alert` |

## Example input

```json
{
  "alert": {
    "monitor": {
      "name": "High Risk Traffic Monitor"
    },
    "trigger": {
      "name": "risk_score >= 100",
      "severity": 1
    },
    "period": {
      "start": "2022-03-08T18:03:30.576Z",
      "end": "2022-03-08T18:04:30.576Z"
    },
    "body": "{\"source\":{\"ip\":[\"10.9.0.215\",]},\"destination\":{\"ip\":[\"10.9.0.216\",]},\"event\":{\"risk_score\":[101.0,],\"severity_tags\":[\"Suricata Alert\",]}}",
    "alert": "PLauan8BaL6eY1yCu9Xj",
    "error": ""
  }
}
```

## Example output

```json
{
  "_index": "arkime_sessions3-220308",
  "_type": "_doc",
  "_id": "220308-PLauan8BaL6eY1yCu9Xj",
  "_version": 4,
  "result": "updated",
  "_shards": {
    "total": 1,
    "successful": 1,
    "failed": 0
  },
  "_seq_no": 9045,
  "_primary_term": 1
}
```
