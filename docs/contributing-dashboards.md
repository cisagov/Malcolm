# <a name="dashboards"></a>OpenSearch Dashboards

[OpenSearch Dashboards](https://opensearch.org/docs/latest/dashboards/index/) is an open-source fork of [Kibana](https://www.elastic.co/kibana/), which is [no longer open-source software]({{ site.github.repository_url }}/releases/tag/v5.0.0).

## <a name="DashboardsNewViz"></a>Adding new visualizations and dashboards

Visualizations and dashboards can be [easily created](dashboards.md#BuildDashboard) in OpenSearch Dashboards using its drag-and-drop WYSIWIG tools. Assuming users have created a new dashboard to package with Malcolm, the dashboard and its visualization components can be exported using the following steps:

1. Identify the ID of the dashboard (found in the URL: e.g., for `/dashboards/app/dashboards#/view/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` the ID would be `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)
1. Export the dashboard with that ID and save it in the `./dashboards./dashboards/` directory with the following command:
   ```
    export DASHID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx && \
      docker-compose exec dashboards curl -XGET \
      "http://localhost:5601/dashboards/api/opensearch-dashboards/dashboards/export?dashboard=$DASHID" > \
      ./dashboards/dashboards/$DASHID.json
    ```
1. It is preferrable for Malcolm to dynamically create the `arkime_sessions3-*` index template rather than including it in imported dashboards, so edit the `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.json` that was generated, carefully locating and removing the section with the `id` of `arkime_sessions3-*` and the `type` of `index-pattern` (including the comma preceding it):
    ```
        ,
        {
          "id": "arkime_sessions3-*",
          "type": "index-pattern",
          "namespaces": [
            "default"
          ],
          "updated_at": "2021-12-13T18:21:42.973Z",
          "version": "Wzk3MSwxXQ==",
          …
          "references": [],
          "migrationVersion": {
            "index-pattern": "7.6.0"
          }
        }
    ```
1. Include the new dashboard either by using a [bind mount](contributing-local-modifications.md#Bind) for the `./dashboards/dashboards/` directory or by [rebuilding](development.md#Build) the `dashboards-helper` Docker image. Dashboards are imported the first time Malcolm starts up.

## <a name="DashboardsPlugins"></a>OpenSearch Dashboards plugins

The [dashboards.Dockerfile]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/Dockerfiles/dashboards.Dockerfile) installs the OpenSearch Dashboards plugins used by Malcolm (search for `opensearch-dashboards-plugin install` in that file). Additional Dashboards plugins could be installed by modifying this Dockerfile and [rebuilding](development.md#Build) the `dashboards` Docker image.

Third-party or community plugins developed for Kibana will not install into OpenSearch dashboards without source code modification. Depending on the plugin, this could range from very smiple to very complex. As an illustrative example, the changes required to port the Sankey diagram visualization plugin from Kibana to OpenSearch Dashboards compatibility can be [viewed on GitHub](https://github.com/mmguero-dev/osd_sankey_vis/compare/edacf6b...main).
