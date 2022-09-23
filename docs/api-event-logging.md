# Event Logging

`POST` - /mapi/event

A webhook that accepts alert data to be reindexed into OpenSearch as session records for viewing in Malcolm's [dashboards](dashboards.md#Dashboards). See [Alerting](alerting.md#Alerting) for more details and an example of how this API is used.

**Example input:**

```json
{
  "alert": {
    "monitor": {
      "name": "Malcolm API Loopback Monitor"
    },
    "trigger": {
      "name": "Malcolm API Loopback Trigger",
      "severity": 4
    },
    "period": {
      "start": "2022-03-08T18:03:30.576Z",
      "end": "2022-03-08T18:04:30.576Z"
    },
    "results": [
      {
        "_shards": {
          "total": 5,
          "failed": 0,
          "successful": 5,
          "skipped": 0
        },
        "hits": {
          "hits": [],
          "total": {
            "value": 697,
            "relation": "eq"
          },
          "max_score": null
        },
        "took": 1,
        "timed_out": false
      }
    ],
    "body": "",
    "alert": "PLauan8BaL6eY1yCu9Xj",
    "error": ""
  }
}
```

**Example output:**

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