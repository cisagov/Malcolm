# Malcolm Services Readiness Status

`GET` - /mapi/ready

Returns `true` or `false` indicating the readiness status of various Malcolm services.

**Example output:**

```json
{
  "arkime": true,
  "dashboards": true,
  "dashboards_maps": true,
  "filebeat_tcp": false,
  "freq": true,
  "logstash_lumberjack": true,
  "logstash_pipelines": true,
  "netbox": true,
  "opensearch": true,
  "pcap_monitor": true,
  "zeek_extracted_file_logger": true,
  "zeek_extracted_file_monitor": true
}
```
