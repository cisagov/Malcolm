# <a name="IndexManagement"></a>OpenSearch index management

Malcolm releases prior to v6.2.0 used environment variables to configure OpenSearch [Index State Management](https://opensearch.org/docs/latest/im-plugin/ism/index/) [policies](https://opensearch.org/docs/latest/im-plugin/ism/policies/).

Since then, OpenSearch Dashboards has developed and released plugins with UIs for [Index State Management](https://opensearch.org/docs/latest/im-plugin/ism/index/) and [Snapshot Management](https://opensearch.org/docs/latest/opensearch/snapshots/sm-dashboards/). Because these plugins provide a more comprehensive and user-friendly interface for these features, the old environment variable-based configuration code has been removed from Malcolm, with a few exceptions. See [**Managing disk usage**](malcolm-config.md#DiskUsage) for more information.


# <a name="ArkimeIndexPolicies"></a> Using ILM/ISM with Arkime

Arkime allows setting [index management policies](https://arkime.com/faq#ilm) with its sessions and history indices. The Malcolm environment variables for configuring this behavior are set in [`arkime.env`](malcolm-config.md#MalcolmConfigEnvVars). These variables can be used for both [OpenSearch and Elasticsearch instances](opensearch-instances.md#OpenSearchInstance) (OpenSearch [Index State Management (ISM)](https://opensearch.org/docs/latest/im-plugin/ism/index/) and [Elasticsearch Index Lifecycle Management (ILM)](https://www.elastic.co/guide/en/elasticsearch/reference/current/index-lifecycle-management.html), respectively).