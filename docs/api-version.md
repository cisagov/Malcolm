# Version Information

`GET` - /mapi/version

Returns version information about Malcolm and version/[health](https://opensearch.org/docs/latest/opensearch/rest-api/cluster-health/) information about the underlying OpenSearch instance.

**Example output:**

```json
{
  "built": "2024-01-10T15:27:31Z",
  "mode": "opensearch-remote",
  "opensearch": {
    "cluster_name": "opensearch-cluster",
    "cluster_uuid": "4QK51McnS96aAvuj5qQKXA",
    "health": {
      "active_primary_shards": 5,
      "active_shards": 10,
      "active_shards_percent_as_number": 100,
      "cluster_name": "opensearch-cluster",
      "delayed_unassigned_shards": 0,
      "discovered_cluster_manager": true,
      "discovered_master": true,
      "initializing_shards": 0,
      "number_of_data_nodes": 2,
      "number_of_in_flight_fetch": 0,
      "number_of_nodes": 4,
      "number_of_pending_tasks": 0,
      "relocating_shards": 0,
      "status": "green",
      "task_max_waiting_in_queue_millis": 0,
      "timed_out": false,
      "unassigned_shards": 0
    },
    "name": "opensearch-node1",
    "tagline": "The OpenSearch Project: https://opensearch.org/",
    "version": {
      "build_date": "2023-10-13T02:55:55.511945994Z",
      "build_hash": "4dcad6dd1fd45b6bd91f041a041829c8687278fa",
      "build_snapshot": false,
      "build_type": "tar",
      "distribution": "opensearch",
      "lucene_version": "9.7.0",
      "minimum_index_compatibility_version": "7.0.0",
      "minimum_wire_compatibility_version": "7.10.0",
      "number": "2.11.0"
    }
  },
  "sha": "77574975",
  "version": "24.01.0"
}
```
