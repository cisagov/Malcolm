# Version Information

`GET` - /mapi/version

Returns version information about Malcolm and version/[health](https://opensearch.org/docs/latest/opensearch/rest-api/cluster-health/) information about the underlying OpenSearch instance.

**Example output:**

```json
{
    "built": "2022-01-18T16:10:39Z",
    "opensearch": {
        "cluster_name": "docker-cluster",
        "cluster_uuid": "TcSiEaOgTdO_l1IivYz2gA",
        "name": "opensearch",
        "tagline": "The OpenSearch Project: https://opensearch.org/",
        "version": {
            "build_date": "2021-12-21T01:36:21.407473Z",
            "build_hash": "8a529d77c7432bc45b005ac1c4ba3b2741b57d4a",
            "build_snapshot": false,
            "build_type": "tar",
            "lucene_version": "8.10.1",
            "minimum_index_compatibility_version": "6.0.0-beta1",
            "minimum_wire_compatibility_version": "6.8.0",
            "number": "7.10.2"
        }
    },
    "opensearch_health": {
        "active_primary_shards": 29,
        "active_shards": 29,
        "active_shards_percent_as_number": 82.85714285714286,
        "cluster_name": "docker-cluster",
        "delayed_unassigned_shards": 0,
        "discovered_master": true,
        "initializing_shards": 0,
        "number_of_data_nodes": 1,
        "number_of_in_flight_fetch": 0,
        "number_of_nodes": 1,
        "number_of_pending_tasks": 0,
        "relocating_shards": 0,
        "status": "yellow",
        "task_max_waiting_in_queue_millis": 0,
        "timed_out": false,
        "unassigned_shards": 6
    },
    "sha": "8ddbbf4",
    "version": "5.2.0"
}
```
