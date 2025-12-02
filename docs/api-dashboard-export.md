# Dashboard Export

`GET` or `POST` - /mapi/dashboard-export/`<dashid>`

Uses the [OpenSearch Dashboards](https://opensearch.org/docs/latest/dashboards/) or [Elastic Kibana](https://www.elastic.co/guide/en/kibana/current/dashboard-api-export.html) API to export the JSON document representing a dashboard (identified by `dashid`). If the query parameter `replace` is not set to `false`, this API will also perform some modifications on the dashboard as described in the [**Adding new visualizations and dashboards**](contributing-dashboards.md#DashboardsNewViz) section of the [contributor guide](contributing-guide.md).

Parameters:

* `dashid` (URL parameter) - the [ID of the dashboard]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/dashboards/dashboards/) to be exported (e.g., `0ad3d7c2-3441-485e-9dfe-dbb22e84e576`)
* `replace` (query parameter) - whether or not to perform the index pattern name replacements as described above (default: `true`)

Example (response truncated for brevity's sake):

```
/mapi/dashboard-export/0ad3d7c2-3441-485e-9dfe-dbb22e84e576
```

```json
{

  "version": "1.3.1",
  "objects": [
    {
      "id": "0ad3d7c2-3441-485e-9dfe-dbb22e84e576",
      "type": "dashboard",
      "namespaces": [
        "default"
      ],
      "updated_at": "2024-04-29T15:49:16.000Z",
      "version": "WzEzNjIsMV0=",
      "attributes": {
        "title": "Overview"
…
}
```