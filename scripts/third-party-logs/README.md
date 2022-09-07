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

The types of third-party logs and metrics discussed in this document are *not* the same as the network session metadata provided by Arkime, Zeek and Suricata. Please refer to the [Malcolm Contributor Guide](../../docs/contributing/README.md) for information on integrating a new network traffic analysis provider.

## <a name="TableOfContents"></a>Table of Contents

* [Configuring Malcolm](#Malcolm)
    - [Secure communication](#MalcolmTLS)
* [Fluent Bit](#FluentBit)
    - [Convenience Script for Linux/macOS](#FluentBitBash)
    - [Convenience Script for Windows](#FluentBitPowerShell)
* [Beats](#Beats)
* [Data Format and Visualization](#Data)
* [Document Indices](#Indices)

## <a name="Malcolm"></a>Configuring Malcolm

The environment variables in [`docker-compose.yml`](../../README.md#DockerComposeYml) for configuring how Malcolm accepts external logs are prefixed with `FILEBEAT_TCP_…`. These values can be specified during Malcolm configuration (i.e., when running [`./scripts/install.py --configure`](../../README.md#ConfigAndTuning)), as can be seen from the following excerpt from the [Installation example](../../README.md#InstallationExample):

```
…
Expose Logstash port to external hosts? (y/N): y
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

* `FILEBEAT_TCP_LISTEN` - whether or not to expose a [Filebeat TCP input listener](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-tcp.html) to which logs may be sent (the default TCP port is `5045`: you may need to adjust your firewall accordingly)
* `FILEBEAT_TCP_LOG_FORMAT` - log format expected for logs sent to the Filebeat TCP input listener (`json` or `raw`)
* `FILEBEAT_TCP_PARSE_SOURCE_FIELD` - source field name to parse (when `FILEBEAT_TCP_LOG_FORMAT` is `json`) for logs sent to the Filebeat TCP input listener
* `FILEBEAT_TCP_PARSE_TARGET_FIELD` - target field name to store decoded JSON fields (when `FILEBEAT_TCP_LOG_FORMAT` is `json`) for logs sent to the Filebeat TCP input listener
* `FILEBEAT_TCP_PARSE_DROP_FIELD` - name of field to drop (if it exists) in logs sent to the Filebeat TCP input listener
* `FILEBEAT_TCP_TAG` - tag to append to events sent to the Filebeat TCP input listener

These variables' values will depend on your forwarder and the format of the data it sends. Note that unless you are creating your own [Logstash pipeline](../../docs/contributing/README.md#LogstashNewSource), you probably want to choose the default `_malcolm_beats` for `FILEBEAT_TCP_TAG` in order for your logs to be picked up and ingested through Malcolm's `beats` pipeline.

### <a name="MalcolmTLS"></a>Secure communication

In order to maintain the integrity and confidentiality of your data, Malcolm's default (set via the `BEATS_SSL` environment variable in `docker-compose.yml`) is to require connections from external forwarders to be encrypted using TLS. When [`./scripts/auth_setup`](../../README.md#AuthSetup) is run, self-signed certificates are generated which may be used by remote log forwarders. Located in the `filebeat/certs/` directory, the certificate authority and client certificate and key files should be copied to the host on which your forwarder is running and used when defining its settings for connecting to Malcolm.

## <a name="FluentBit"></a>Fluent Bit

[Fluent Bit](https://fluentbit.io/) is a fast and lightweight logging and metrics processor and forwarder that works well with Malcolm. It is [well-documented](https://docs.fluentbit.io/manual), supports a number of [platforms](https://docs.fluentbit.io/manual/installation/getting-started-with-fluent-bit) including [Linux](https://docs.fluentbit.io/manual/installation/linux), [Microsoft Windows](https://docs.fluentbit.io/manual/installation/windows), macOS (either built [via source](https://docs.fluentbit.io/manual/installation/macos) or installed with [Homebrew](https://formulae.brew.sh/formula/fluent-bit#default)) and more. It provides many [data sources](https://docs.fluentbit.io/manual/pipeline/inputs) (inputs).

### <a name="FluentBitBash"></a>Convenience Script for Linux/macOS

[`fluent-bit-setup.sh`](./fluent-bit-setup.sh) is a Bash script to help install and configure Fluent Bit on Linux and macOS systems. After configuring Malcolm to accept and parse forwarded logs as described above, run `fluent-bit-setup.sh` as illustrated in the examples below:

Linux example:

```
$ ~/Malcolm/scripts/third-party-logs/fluent-bit-setup.sh 
0   ALL
1   InstallFluentBit
2   GetMalcolmConnInfo
3   GetFluentBitFormatInfo
4   CreateFluentbitService
Operation: 0
Install fluent-bit via GitHub/fluent install script [Y/n]? y
================================
 Fluent Bit Installation Script 
================================
This script requires superuser access to install packages.
You will be prompted for your password by sudo.
…
Installation completed. Happy Logging!

Choose input plugin and enter parameters. Leave parameters blank for defaults.
  see https://docs.fluentbit.io/manual/pipeline/inputs
1   collectd
2   cpu
3   disk
4   docker
5   docker_events
6   dummy
7   dummy_thread
8   exec
9   fluentbit_metrics
10  forward
11  head
12  health
13  http
14  kmsg
15  mem
16  mqtt
17  netif
18  nginx_metrics
19  node_exporter_metrics
20  opentelemetry
21  proc
22  prometheus_scrape
23  random
24  serial
25  statsd
26  stdin
27  syslog
28  systemd
29  tail
30  tcp
31  thermal
Input plugin: 2
cpu Interval_Sec:  10
cpu Interval_NSec:  
cpu PID:  
Enter Malcolm host or IP address (172.16.0.20): 172.16.0.20
Enter Malcolm Filebeat TCP port (5045): 5045
Enter fluent-bit output format (json_lines): json_lines
Nest values under field: cpu
Add "module" value: cpu

/usr/local/bin/fluent-bit -R /etc/fluent-bit/parsers.conf -i cpu -p Interval_Sec=10 -o tcp://172.16.0.20:5045 -p tls=on -p tls.verify=off -p tls.ca_file=/home/user/Malcolm/filebeat/certs/ca.crt -p tls.crt_file=/home/user/Malcolm/filebeat/certs/client.crt -p tls.key_file=/home/user/Malcolm/filebeat/certs/client.key -p format=json_lines -F nest -p Operation=nest -p Nested_under=cpu -p WildCard='*' -m '*' -F record_modifier -p 'Record=module cpu' -m '*' -f 1

Configure service to run fluent-bit [y/N]? y
Enter .service file prefix: fluentbit_cpu
Configure systemd service as user "user" [Y/n]? y
[sudo] password for user: 
Created symlink /home/user/.config/systemd/user/default.target.wants/fluentbit_cpu.service → /home/user/.config/systemd/user/fluentbit_cpu.service.
● fluentbit_cpu.service
     Loaded: loaded (/home/user/.config/systemd/user/fluentbit_cpu.service; enabled; vendor preset: enabled)
     Active: active (running) since Tue 2022-08-09 09:19:43 MDT; 5s ago
   Main PID: 105521 (fluent-bit)
      Tasks: 5 (limit: 76711)
     Memory: 24.7M
        CPU: 8ms
     CGroup: /user.slice/user-1000.slice/user@1000.service/app.slice/fluentbit_cpu.service
             └─105521 /usr/local/bin/fluent-bit -R /etc/fluent-bit/parsers.conf -i cpu -p Interval_Sec=10 -o tcp://172.16.0.20:5045 -p tls=on -p tls.verify=off -p tls.ca_fil…

Aug 09 09:19:43 localhost fluent-bit[105521]: Fluent Bit v1.9.6
…
Aug 09 09:19:43 localhost fluent-bit[105521]: [2022/08/09 09:19:43] [ info] [output:tcp:tcp.0] worker #0 started
Aug 09 09:19:43 localhost fluent-bit[105521]: [2022/08/09 09:19:43] [ info] [output:tcp:tcp.0] worker #1 started
```

macOS example:

```
$ bash fluent-bit-setup.sh 
0       ALL
1       InstallFluentBit
2       GetMalcolmConnInfo
3       GetFluentBitFormatInfo
4       CreateFluentbitService
Operation: 0
Install fluent-bit via Homebrew [Y/n]? y
==> Downloading https://ghcr.io/v2/homebrew/core/fluent-bit/manifests/1.9.6
…
Choose input plugin and enter parameters. Leave parameters blank for defaults.
  see https://docs.fluentbit.io/manual/pipeline/inputs
1       collectd
2       dummy
3       dummy_thread
4       exec
5       fluentbit_metrics
6       forward
7       head
8       health
9       http
10      mqtt
11      nginx_metrics
12      opentelemetry
13      prometheus_scrape
14      random
15      serial
16      statsd
17      stdin
18      syslog
19      tail
20      tcp
Input plugin: 14
random Samples:  10
random Interval_Sec:  30
random Internal_NSec:  
Enter Malcolm host or IP address (127.0.0.1): 172.16.0.20
Enter Malcolm Filebeat TCP port (5045): 5045
Enter fluent-bit output format (json_lines): json_lines
Nest values under field: random
Add "module" value: random

/usr/local/bin/fluent-bit -R /usr/local/etc/fluent-bit/parsers.conf -i random -p Samples=10 -p Interval_Sec=30 -o tcp://172.16.0.20:5045 -p tls=on -p tls.verify=off -p tls.ca_file=/Users/user/forwarder/ca.crt -p tls.crt_file=/Users/user/forwarder/client.crt -p tls.key_file=/Users/user/forwarder/client.key -p format=json_lines -F nest -p Operation=nest -p Nested_under=random -p WildCard='*' -m '*' -F record_modifier -p 'Record=module random' -m '*' -f 1

Configure service to run fluent-bit [y/N]? n
```

### <a name="FluentBitPowerShell"></a>Convenience Script for Windows

[fluent-bit-setup.ps1](./fluent-bit-setup.ps1) is a PowerShell script to help install and configure Fluent Bit on Microsoft Windows systems.

```
PS C:\work> .\fluent-bit-setup.ps1

Download fluent-bit
Would you like to download fluent-bit (zip) to C:\work?
[Y] Yes  [N] No  [?] Help (default is "Y"): y

Select input plugin (https://docs.fluentbit.io/manual/pipeline/inputs):
1. dummy
2. dummy_thread
3. fluentbit_metrics
4. forward
5. nginx_metrics
6. opentelemetry
7. prometheus_scrape
8. random
9. statsd
10. tail
11. tcp
12. windows_exporter_metrics
13. winevtlog
14. winlog
15. winstat
Make a selection: 13

Enter parameters for winevtlog. Leave parameters blank for defaults.
  see https://docs.fluentbit.io/manual/pipeline/inputs

winevtlog Channels: Application,Security,Setup,Windows PowerShell
winevtlog Interval_Sec:
winevtlog Interval_NSec:
winevtlog Read_Existing_Events:
winevtlog DB:
winevtlog String_Inserts:
winevtlog Render_Event_As_XML:
winevtlog Use_ANSI:
Enter Malcolm host or IP address: 172.16.0.20
Enter Malcolm Filebeat TCP port (5045): 5045
Enter fluent-bit output format (json_lines): json_lines
Nest values under field (winevtlog): winevtlog
Add "module" value (winevtlog): winevtlog

C:\work\bin\fluent-bit.exe -c "C:\work\winevtlog_172.16.0.20_1660062217.cfg"

Install fluent-bit Service
Install Windows service for winevtlog to 172.16.0.20:5045?
[Y] Yes  [N] No  [?] Help (default is "N"): Y
Enter name for service: fluentbit_winevtlog
Enter account name to run service (DOMAIN\user): DOMAIN\user

Status   Name               DisplayName
------   ----               -----------
Stopped  fluentbit_winev... fluentbit_winevtlog

Start fluent-bit Service
Start Windows service for winevtlog to 172.16.0.20:5045?
[Y] Yes  [N] No  [?] Help (default is "Y"): y

Status   Name               DisplayName
------   ----               -----------
Running  fluentbit_winev... fluentbit_winevtlog
```

## <a name="Beats"></a>Beats

Elastic [Beats](https://www.elastic.co/beats/) can also be used to forward data to Malcolm's Filebeat TCP listener. Follow the [Get started with Beats](https://www.elastic.co/guide/en/beats/libbeat/current/getting-started.html) documentation for configuring Beats on your system.

In contrast to Fluent Bit, Beats forwarders write to Malcolm's Logstash input over TCP port 5044 (rather than its Filebeat TCP input). Answer `Y` when prompted `Expose Logstash port to external hosts?` during Malcolm configuration (i.e., when running [`./scripts/install.py --configure`](../../README.md#ConfigAndTuning)) to allow external remote Beats forwarders to send logs to Logstash.

Your Beat's [configuration YML file](https://www.elastic.co/guide/en/beats/libbeat/current/config-file-format.html) file might look something like this sample [filebeat.yml](https://www.elastic.co/guide/en/beats/filebeat/current/configuring-howto-filebeat.html) file:


```yml
filebeat.inputs:
- type: log
  paths:
    - /home/user/logs/*.log

processors:
  - add_tags:
      tags: [_malcolm_beats]

output.logstash:
  hosts: ["172.16.0.20:5044"]
  ssl.enabled: true
  ssl.certificate_authorities: ["/home/user/Malcolm/filebeat/certs/ca.crt"]
  ssl.certificate: "/home/user/Malcolm/filebeat/certs/client.crt"
  ssl.key: "/home/user/Malcolm/filebeat/certs/client.key"
  ssl.supported_protocols: "TLSv1.2"
  ssl.verification_mode: "none"
```

The important bits to note in this example are the settings under [`output.logstash`](https://www.elastic.co/guide/en/beats/filebeat/current/logstash-output.html) (including the TLS-related files described above in **Configuring Malcolm**) and the `_malcolm_beats` value in [`tags`](https://www.elastic.co/guide/en/beats/filebeat/current/add-tags.html): unless you are creating your own [Logstash pipeline](../../docs/contributing/README.md#LogstashNewSource), you probably want to use `_malcolm_beats` in order for your logs to be picked up and ingested through Malcolm's `beats` pipeline. This parts should apply regardless of the specific Beats forwarder you're using (e.g., Filebeat, Metricbeat, Winlogbeat, etc.).

Most Beats forwarders can use [processors](https://www.elastic.co/guide/en/beats/filebeat/current/defining-processors.html) to filter, transform and enhance data prior to sending it to Malcolm. Consult each forwarder's [documentation](https://www.elastic.co/beats/) to learn more about what processors are available and how to configure them. Use the [Console output](https://www.elastic.co/guide/en/beats/filebeat/current/console-output.html) for debugging and experimenting with how Beats forwarders format the logs they generate.

## <a name="Data"></a>Data Format and Visualization

Because Malcolm could receive logs or metrics from virtually any provider, Malcolm most likely does not have prebuilt dashboards and visualizations for your third-party logs. Luckily, [OpenSearch Dashboards](https://opensearch.org/docs/latest/dashboards/index/) provides visualization tools that can be used with whatever data is stored in Malcolm's OpenSearch document store. Here are some resources to help you get started understanding OpenSearch Dashboards and building custom visualizations for your data:

* [OpenSearch Dashboards](../../README.md#Dashboards) in the Malcolm documentation
* [OpenSearch Dashboards](https://opensearch.org/docs/latest/dashboards/index/) documentation
* [Kibana User Guide](https://www.elastic.co/guide/en/kibana/7.10/index.html) (OpenSearch Dashboards is an open-source fork of Kibana, so much of its documentation also applies to OpenSearch Dashboards)
    - [Discover](https://www.elastic.co/guide/en/kibana/7.10/discover.html)
    - [Searching Your Data](https://www.elastic.co/guide/en/kibana/7.10/search.html)
    - [Kibana Dashboards](https://www.elastic.co/guide/en/kibana/7.10/dashboard.html)
    - [TimeLine](https://www.elastic.co/guide/en/kibana/7.12/timelion.html)
* [Search Queries in Arkime and OpenSearch](../../README.md#SearchCheatSheet)

## <a name="Indices"></a>Document Indices

Third-party logs ingested into Malcolm as outlined in this document will be indexed into the `malcolm_beats_*` index pattern (unless you've created your own [Logstash pipeline](../../docs/contributing/README.md#LogstashNewSource)), which can be selected in the OpenSearch Dashboards' Discover view or when specifying the log source for a new visualization. 

Because these documents are indexed by OpenSearch dynamically as they are ingested by Logstash, their component fields will not show up as searchable in OpenSearch Dashboards visualizations until its copy of the field list is refreshed. Malcolm periodically refreshes this list, but if fields are missing from your visualizations you may wish to do it manually.

After Malcolm ingests your data (or, more specifically, after it has ingested a new log type it has not seen before) you may manually refresh OpenSearch Dashboards's field list by clicking **Management** → **Index Patterns**, then selecting the index pattern (`malcolm_beats_*`) and clicking the reload **🗘** button near the upper-right of the window.
