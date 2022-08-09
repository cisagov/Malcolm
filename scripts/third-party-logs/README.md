# Forwarding Third-Party Logs to Malcolm

Malcolm uses [OpenSearch](https://opensearch.org/) and [OpenSearch Dashboards](https://opensearch.org/docs/latest/dashboards/index/) for data storage, search and visualization, and [Logstash](https://www.elastic.co/logstash/) for log processing. Because these tools are data agnostic, Malcolm can be configured to accept various host logs and other third-party logs sent from log forwaders such as [Fluent Bit](https://fluentbit.io/) and [Beats](https://www.elastic.co/beats/). Some examples of the types of logs these forwarders might send include:

* System resource utilization metrics (CPU, memory, disk, network, etc.)
* System temperatures
* Linux system logs
* Windows event logs
* Process or service health status
* Logs appended to textual log files (e.g., `tail`-ing a log file)
* The output of an external script or program
* Messages in the form of MQTT control packets
* many more...

## Configuring Malcolm

The environment variables in [`docker-compose.yml`](../../README.md#DockerComposeYml) for configuring how Malcolm accepts external logs are prefixed with `FILEBEAT_TCP_…`. These values can be specified during Malcolm configuration (i.e., when running [`./scripts/install.py --configure`](../../README.md#ConfigAndTuning)), as can be seen from the following excerpt from the [Installation example](../../README.md#InstallationExample):

```
…
Expose Filebeat TCP port to external hosts? (y/N): y
1: json
2: raw
Select log format for messages sent to Filebeat TCP listener (json): 1

Source field to parse for messages sent to Filebeat TCP listener (message): message

Target field under which to store decoded JSON fields for messages sent to Filebeat TCP listener (miscbeat): miscbeat

Field to drop from events sent to Filebeat TCP listener (message): message

Tag to apply to messages sent to Filebeat TCP listener (_malcolm_beats): _malcolm_beats
…
```

The variables corresponding to these questions can be found in the `filebeat-variables` section of`docker-compose.yml`:

* `FILEBEAT_TCP_LISTEN` - whether or not to expose a [filebeat TCP input listener](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-tcp.html) to which logs may be sent (the default TCP port is `5045`: you may need to adjust your firewall accordingly)
* `FILEBEAT_TCP_LOG_FORMAT` - log format expected for logs sent to the filebeat TCP input listener (`json` or `raw`)
* `FILEBEAT_TCP_PARSE_SOURCE_FIELD` - source field name to parse (when `FILEBEAT_TCP_LOG_FORMAT` is `json`) for logs sent to the filebeat TCP input listener
* `FILEBEAT_TCP_PARSE_TARGET_FIELD` - target field name to store decoded JSON fields (when `FILEBEAT_TCP_LOG_FORMAT` is `json`) for logs sent to the filebeat TCP input listener
* `FILEBEAT_TCP_PARSE_DROP_FIELD` - name of field to drop (if it exists) in logs sent to the filebeat TCP input listener
* `FILEBEAT_TCP_TAG` - tag to append to events sent to the filebeat TCP input listener

These variables' values will depend on your forwarder and the format of the data it sends. Note that unless you are creating your own [Logstash pipeline](../../docs/contributing/README.md#LogstashNewSource), you probably want to choose the default `_malcolm_beats` for `FILEBEAT_TCP_TAG` in order for your logs to be picked up and ingested through Malcolm's `beats` pipeline.

In order to maintain the integrity and confidentiality of your data, Malcolm's default is to require connections from external forwarders to be encrypted using TLS. When [`./scripts/auth_setup`](../../README.md#AuthSetup) is run, self-signed certificates are generated which may be used by remote log forwarders. Located in the `filebeat/certs/` directory, the certificate authority and client certificate and key files should be copied to the host on which your forwarder is running and used when defining its settings for connecting to Malcolm.

## Fluent Bit

[Fluent Bit](https://fluentbit.io/) is a fast and lightweight logging and metrics processor and forwarder that works well with Malcolm. It is [well-documented](https://docs.fluentbit.io/manual), supports a number of [platforms](https://docs.fluentbit.io/manual/installation/getting-started-with-fluent-bit) including [Linux](https://docs.fluentbit.io/manual/installation/linux), [Microsoft Windows](https://docs.fluentbit.io/manual/installation/windows), macOS (either built [via source](https://docs.fluentbit.io/manual/installation/macos) or installed with [Homebrew](https://formulae.brew.sh/formula/fluent-bit#default)) and more. It provides many [data sources](https://docs.fluentbit.io/manual/pipeline/inputs) (inputs).

### Convenience Script for Linux/macOS

### Convenience Script for Windows


## Beats


## Visualization


AuthSetup