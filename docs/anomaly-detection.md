# <a name="AnomalyDetection"></a>Anomaly Detection

Malcolm uses the Anomaly Detection plugins for [OpenSearch](https://github.com/opensearch-project/anomaly-detection) and [OpenSearch Dashboards](https://github.com/opensearch-project/anomaly-detection-dashboards-plugin) to identify anomalous log data in near real-time using the [Random Cut Forest](https://api.semanticscholar.org/CorpusID:927435) (RCF) algorithm. This can be paired with [Alerting](alerting.md#Alerting) to automatically notify when anomalies are found. See [Anomaly detection](https://opensearch.org/docs/latest/monitoring-plugins/ad/index/) in the OpenSearch documentation for usage instructions on how to create detectors for any of the many fields Malcolm supports.

A fresh installation of Malcolm configures [several detectors]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/dashboards/anomaly_detectors) for anomalous network traffic:
    
* **network_protocol** - Detects anomalies based on application protocol (`network.protocol`)
* **action_result_user** - Detects anomalies in action (`event.action`), result (`event.result`) and user (`related.user`) within application protocols (`network.protocol`)
* **file_mime_type** - Detects anomalies based on transferred file type (`file.mime_type`)
* **total_bytes** - Detects anomalies based on traffic size (sum of `network.bytes`)

These detectors are disabled by default, but may be enabled for anomaly detection over streaming or [historical data](https://aws.amazon.com/about-aws/whats-new/2022/01/amazon-opensearch-service-elasticsearch-anomaly-detection/).