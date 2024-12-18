# Version Information

`GET` - /mapi/version

Returns version information about Malcolm and version/[health](https://opensearch.org/docs/latest/opensearch/rest-api/cluster-health/) information about the underlying OpenSearch instance.

**Example output:**

```json
{
  "boot_time": "2024-05-20T14:15:01Z",
  "built": "2024-06-03T14:23:38Z",
  "machine": "x86_64",
  "mode": "opensearch-local",
  "opensearch": {
    "cluster_name": "docker-cluster",
    "cluster_uuid": "D6uCu7DNRC6WPFlu_SHalg",
    "health": {
      "active_primary_shards": 19,
      "active_shards": 19,
      "active_shards_percent_as_number": 95.0,
      "cluster_name": "docker-cluster",
      "delayed_unassigned_shards": 0,
      "discovered_cluster_manager": true,
      "discovered_master": true,
      "initializing_shards": 0,
      "number_of_data_nodes": 1,
      "number_of_in_flight_fetch": 0,
      "number_of_nodes": 1,
      "number_of_pending_tasks": 0,
      "relocating_shards": 0,
      "status": "green",
      "task_max_waiting_in_queue_millis": 0,
      "timed_out": false,
      "unassigned_shards": 1
    },
    "name": "opensearch",
    "tagline": "The OpenSearch Project: https://opensearch.org/",
    "version": {
      "build_date": "2024-05-09T18:51:00.973564994Z",
      "build_hash": "aaa555453f4713d652b52436874e11ba258d8f03",
      "build_snapshot": false,
      "build_type": "tar",
      "distribution": "opensearch",
      "lucene_version": "9.10.0",
      "minimum_index_compatibility_version": "7.0.0",
      "minimum_wire_compatibility_version": "7.10.0",
      "number": "2.14.0"
    }
  },
  "sha": "dad18b1",
  "version": "{{ site.malcolm.version }}"
}
```
