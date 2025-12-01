# <a name="LiveAnalysis"></a>Live analysis

* [Live analysis](#LiveAnalysis)
    - [Using a network sensor appliance](#Hedgehog)
    - [Monitoring local network interfaces](#LocalPCAP)
        + ["Hedgehog" run profile](#Profiles)
    - [Manually forwarding logs from an external source](#ExternalForward)
    - [Tuning](#LiveAnalysisTuning)
        + [Zeek](#LiveAnalysisTuningZeek)
        + [Arkime](#LiveAnalysisTuningArkime)
        + [Suricata](#LiveAnalysisTuningSuricata)

## <a name="Hedgehog"></a>Using a network sensor appliance

A dedicated network sensor appliance is the recommended method for capturing and analyzing live network traffic when performance and throughput is of utmost importance. [Hedgehog Linux](hedgehog.md) is a custom Debian-based operating system built to:

* monitor network interfaces
* capture packets to PCAP files
* detect file transfers in network traffic and extract and scan those files for threats
* generate and forward Zeek and Suricata logs, Arkime sessions, and other information to [Malcolm]({{ site.github.repository_url }})

Please see the [Hedgehog Linux README](hedgehog.md) for more information.

## <a name="LocalPCAP"></a>Monitoring local network interfaces

The options for monitoring traffic on local network interfaces can be [configured](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig) by running [`./scripts/configure`](malcolm-config.md#ConfigAndTuning).

Malcolm's `pcap-capture`, `suricata-live` and `zeek-live` containers can monitor one or more local network interfaces, specified by the `PCAP_IFACE` environment variable in [`pcap-capture.env`](malcolm-config.md#MalcolmConfigEnvVars). These containers are started with additional privileges to allow opening network interfaces in promiscuous mode for capture.

The instances of Zeek and Suricata (in the `suricata-live` and `zeek-live` containers when the `SURICATA_LIVE_CAPTURE` and `ZEEK_LIVE_CAPTURE` [environment variables](malcolm-config.md#MalcolmConfigEnvVars) are set to `true`, respectively) analyze traffic on-the-fly and generate log files containing network session metadata. These log files are in turn scanned by [Filebeat](https://www.elastic.co/products/beats/filebeat) and forwarded to [Logstash](https://www.elastic.co/products/logstash) for enrichment and indexing into the [OpenSearch](https://opensearch.org/) document store.

In contrast, the `pcap-capture` container buffers traffic to PCAP files and periodically rotates these files for processing (by Arkime's `capture` utlity in the `arkime` container) according to the thresholds defined by the `PCAP_ROTATE_MEGABYTES` and `PCAP_ROTATE_MINUTES` environment variables in [`pcap-capture.env`](malcolm-config.md#MalcolmConfigEnvVars). If for some reason (e.g., a low resources environment) you also want Zeek and Suricata to process these intermediate PCAP files rather than monitoring the network interfaces directly, you can set `SURICATA_ROTATED_PCAP`/`ZEEK_ROTATED_PCAP` to `true` and `SURICATA_LIVE_CAPTURE`/`ZEEK_LIVE_CAPTURE` to false. The only exception to this behavior (i.e., the creation of intermediate PCAP files by `netsniff-ng` or `tcpdump` in the `pcap-capture` which are periodically rolled over for processing by Arkime) is when running the ["Hedgehog" run profile](#Profiles), when using [a remote OpenSearch or Elasticsearch instance](opensearch-instances.md#OpenSearchInstance), or in a [Kubernetes-based deployment](kubernetes.md#Kubernetes). In those configurations, users may choose to have Arkime's `capture` tool monitor live traffic on the network interface without using the intermediate PCAP file.

Note that Microsoft Windows and Apple macOS platforms currently run Docker inside of a virtualized environment. Live traffic capture and analysis on those platforms would require additional configuration of virtual interfaces and port forwarding in Docker, which is outside of the scope of this document.

### <a name="Profiles"></a>"Hedgehog" run profile

Another configuration for monitoring local network interfaces is to use the `hedgehog` run profile. During [Malcolm configuration](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig) users are prompted "**Run with Malcolm (all containers) or Hedgehog (capture only) profile?**" Docker Compose can use [profiles](https://docs.docker.com/compose/profiles/) to selectively start services. While the `malcolm` run profile runs all of Malcolm's containers (OpenSearch, Dashboards, LogStash, etc.), the `hedgehog` profile runs *only* the containers necessary for traffic capture.

When configuring the `hedgehog` profile, users must provide connection details for another Malcolm instance to which to forward its network traffic logs.

## <a name="ExternalForward"></a>Manually forwarding logs from an external source

Malcolm's Logstash instance can also be configured to accept logs from a [remote forwarder](https://www.elastic.co/products/beats/filebeat). Select `Y` for **Expose Malcolm Service Ports** (or `customize` and **Expose Logstash**) during [Malcolm configuration](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfigItems) to allow external remote forwarders to send logs to Logstash. Enabling encrypted transport of these log files is discussed in [Configure authentication](authsetup.md#AuthSetup) and the description of the `BEATS_SSL` environment variable in [`beats-common.env`](malcolm-config.md#MalcolmConfigEnvVars).

Configuring Filebeat to forward Zeek logs to Malcolm might look something like this example [`filebeat.yml`](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-reference-yml.html):
```
filebeat.inputs:
- type: log
  paths:
    - /var/zeek/*.log
  fields_under_root: true
  compression_level: 0
  exclude_lines: ['^\s*#']
  scan_frequency: 10s
  clean_inactive: 180m
  ignore_older: 120m
  close_inactive: 90m
  close_renamed: true
  close_removed: true
  close_eof: false
  clean_renamed: true
  clean_removed: true

output.logstash:
  hosts: ["192.0.2.123:5044"]
  ssl.enabled: true
  ssl.certificate_authorities: ["/foo/bar/ca.crt"]
  ssl.certificate: "/foo/bar/client.crt"
  ssl.key: "/foo/bar/client.key"
  ssl.supported_protocols: "TLSv1.2"
  ssl.verification_mode: "none"
```

## <a name="LiveAnalysisTuning"></a>Tuning

For environments where high-performance capture is desired, some manual tuning of the parameters of Arkime, Zeek, and Suricata will be necessary. These parameters will vary from situation to situation depending on network traffic characteristics and hardware resources, and may require adjustments over time to get the best performance possible. The following sections can help users know which settings to adjust for individual circumstances. Users should take particular care when determining the number of CPUs to use to read from network interfaces (e.g., `ZEEK_LB_PROCS_WORKER_DEFAULT` for [Zeek](#LiveAnalysisTuningZeek), `ARKIME_TPACKETV3_NUM_THREADS` and `ARKIME_PACKET_THREADS` for [Arkime](#LiveAnalysisTuningArkime), and `SURICATA_AF_PACKET_IFACE_THREADS` for [Suricata](#LiveAnalysisTuningSuricata)) to determine the appropriate balance between these tools with regards to the system's available CPU resources.

### <a name="LiveAnalysisTuningZeek"></a>Zeek

Zeek's resource utilization and performance can be tuned using [environment variables](malcolm-config.md#MalcolmConfigEnvVars) that can be added or modified in [`zeek-live.env`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/config/zeek-live.env.example).

Malcolm uses [Zeek's support](https://github.com/zeek/zeek-af_packet-plugin) for [AF_Packet sockets](https://man7.org/linux/man-pages/man7/packet.7.html) for packet capture. Review Zeek's documentation on [cluster setup](https://docs.zeek.org/en/master/cluster-setup.html#af-packet) to better understand the parameters discussed below.

The relevant environment variables related to tuning Zeek for live packet capture are:

- `ZEEK_AF_PACKET_BUFFER_SIZE` - AF_Packet [ring buffer size](https://docs.zeek.org/en/master/scripts/builtin-plugins/Zeek_AF_Packet/init.zeek.html#id-AF_Packet::buffer_size) in bytes (default `67108864`)
- `ZEEK_AF_PACKET_FANOUT_MODE` - AF_Packet [fanout mode](https://docs.zeek.org/en/master/scripts/base/bif/plugins/Zeek_AF_Packet.af_packet.bif.zeek.html#type-AF_Packet::FanoutMode) (default `FANOUT_HASH`)
- `ZEEK_LB_PROCS_WORKER_DEFAULT` - ["Zeek is not multithreaded, so once the limitations of a single processor core are reached the only option currently is to spread the workload across many cores"](https://docs.zeek.org/en/master/cluster-setup.html#cluster-architecture). This value defines the number of processors to be assigned to each group of [workers](https://docs.zeek.org/en/master/frameworks/cluster.html#worker) created for each capture interface for [load balancing](https://docs.zeek.org/en/master/cluster-setup.html#load-balancing) (default `2`). A value of `0` means "autocalculate based on the number of CPUs present in the system."
- `ZEEK_LB_PROCS_WORKER_n` - Explicitly defines the number of processor to be assigned to the group of workers for the *n*-th capture interface. If unspecified this defaults to the number of CPUs `ZEEK_PIN_CPUS_WORKER_n` if defined, or `ZEEK_LB_PROCS_WORKER_DEFAULT` otherwise.
- `ZEEK_LB_PROCS_LOGGER` - Defines the number of processors to be assigned to the [loggers](https://docs.zeek.org/en/master/frameworks/cluster.html#logger) (default `1`)
- `ZEEK_LB_PROCS_PROXY` - Defines the number of processors to be assigned to the [proxies](https://docs.zeek.org/en/master/frameworks/cluster.html#proxy) (default `1`)
- `ZEEK_LB_PROCS_CPUS_RESERVED` - If `ZEEK_LB_PROCS_WORKER_DEFAULT` is `0` ("autocalculate"), exclude this number of CPUs from the autocalculation (defaults to `1` (kernel) + `1` (manager) + `ZEEK_LB_PROCS_LOGGER` + `ZEEK_LB_PROCS_PROXY`)
- `ZEEK_PIN_CPUS_WORKER_AUTO` - Automatically [pin worker CPUs](https://en.wikipedia.org/wiki/Processor_affinity) (default `false`)
- `ZEEK_PIN_CPUS_WORKER_n` - Explicitly defines the processor IDs to be to be assigned to the group of workers for the *n*-th capture interface (e.g., `0` means "the first CPU"; `12,13,14,15` means "the last four CPUs" on a 16-core system)
- `ZEEK_PIN_CPUS_OTHER_AUTO` - automatically pin CPUs for manager, loggers, and proxies if possible (default `false`)
- `ZEEK_PIN_CPUS_MANAGER` - list of CPUs to pin for the [manager](https://docs.zeek.org/en/master/frameworks/cluster.html#manager) process (default is unset; only used if `ZEEK_PIN_CPUS_OTHER_AUTO` is `false`)
- `ZEEK_PIN_CPUS_LOGGER` - list of CPUs to pin for the logger processes (default is unset; only used if `ZEEK_PIN_CPUS_OTHER_AUTO` is `false`)
- `ZEEK_PIN_CPUS_PROXY` - list of CPUs to pin for the proxy processes (default is unset; only used if `ZEEK_PIN_CPUS_OTHER_AUTO` is `false`)

### <a name="LiveAnalysisTuningArkime"></a>Arkime

Arkime's `capture` process is controlled by [settings](https://arkime.com/settings) in its `config.ini` file. Arkime's documentation on [High Performance Settings](https://arkime.com/settings#high-performance-settings) outlines the settings that most influence performance and resource utilization.

Malcolm's default values for Arkime's live traffic capture are mostly already configured for high-performance traffic capture. Some other parameters that influence Arkime's resource utilization and performance can be tuned using [environment variables](malcolm-config.md#MalcolmConfigEnvVars) that can be modified in [`arkime-live.env`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/config/arkime-live.env.example).

On Hedgehog Linux (and other Malcolm installations running the ["Hedgehog" run profile](#Profiles)), when using [a remote OpenSearch or Elasticsearch instance](opensearch-instances.md#OpenSearchInstance), or in a [Kubernetes-based deployment](kubernetes.md#Kubernetes), users may choose to have Arkime's `capture` tool monitor live traffic on the network interface without using an intermediate PCAP file so that the `arkime-live` container will use [its environment variables]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/config/arkime-live.env.example) in its [entrypoint]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/interface/sensor_ctl/supervisor.init/arkime/scripts/docker_entrypoint.sh) to populate [`config.ini`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/arkime/etc/config.ini).

In contrast, when Malcolm is capturing traffic on it's own local network interfaces, the issue becomes a bit more complicated: as [described above](#LocalPCAP) in the section that references the `pcap-capture` capture, most container-based Malcolm deployments don't actually use Arkime's `capture` to generate Arkime sessions. Instead, intermediate PCAP files are generated by `netsniff-ng` or `tcpdump` are periodically rolled over for "offline" processing by Arkime `capture`. This being the case, most of the settings dealing with traffic capture don't apply, since (from it's point of view) `capture` isn't running against "live" traffic.

The relevant environment variables related to tuning Arkime for live packet capture are:

- `ARKIME_COMPRESSION_TYPE` - the type of [seekable compression](https://arkime.com/settings#simpleCompression) to use when creating PCAP files (`none`, `zstd` or `gzip`)
- `ARKIME_COMPRESSION_LEVEL` - the compression level if `ARKIME_COMPRESSION_TYPE` is [`gzip`](https://arkime.com/settings#simpleGzipLevel) or [`zstd`](https://arkime.com/settings#simpleZstdLevel)
- `ARKIME_DB_BULK_SIZE` - approximate [size of bulk indexing](https://arkime.com/settings#dbBulkSize) requests to send to OpenSearch/Elasticsearch
- `ARKIME_MAGIC_MODE` - ["magicking" mode](https://arkime.com/settings#dbBulkSize) for HTTP/SMTP bodies
- `ARKIME_MAX_PACKETS_IN_QUEUE` - the [number of packets per packet](https://arkime.com/settings#maxPacketsInQueue) thread that can be waiting to be processed (Arkime will start dropping packets if the queue fills up)
- `ARKIME_PACKET_THREADS` - the [number of packet threads](https://arkime.com/settings#packetThreads) used to process packets after the reader has received the packets (default `2`)
- `ARKIME_PCAP_WRITE_METHOD` - [how packets are written](https://arkime.com/settings#pcapWriteMethod) to disk
- `ARKIME_PCAP_WRITE_SIZE` - [buffer size](https://arkime.com/settings#pcapWriteSize) to use when writing PCAP files
- `ARKIME_PCAP_READ_METHOD` - [how packets are read from network cards](https://arkime.com/settings#pcapReadMethod) (`tpacketv3` indicates AF_Packet should be used)
- `ARKIME_TPACKETV3_NUM_THREADS` - [the number of threads](https://arkime.com/settings#tpacketv3NumThreads) used to read packets from each network interface (default `2`)
- `ARKIME_TPACKETV3_BLOCK_SIZE` - [the block size in bytes](https://arkime.com/settings#tpacketv3BlockSize) used for reads from each interface

Aside from the settings mentioned above, to quote the Arkime documentation, often issues with traffic capture performance "are **not** a problem with Arkime, but usually an issue with either the hardware or the packet rate exceeding what the hardware can save to disk." Please read [**Why am I dropping packets? (and Disk Q issues)**](https://arkime.com/faq#why-am-i-dropping-packets) from the Arkime FAQ.

### <a name="LiveAnalysisTuningSuricata"></a>Suricata

Suricata's resource utilization and performance can be tuned using [environment variables](malcolm-config.md#MalcolmConfigEnvVars) that can be added or modified in [`suricata-live.env`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/config/suricata-live.env.example).

Upon starting, Malcolm's [`suricata_config_populate.py`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/config/shared/bin/suricata_config_populate.py) script generates the `suricata.yaml` configuration file (see (see [`suricata.yaml.in`](https://github.com/OISF/suricata/blob/master/suricata.yaml.in) and the [Suricata documentation](https://suricata.readthedocs.io/en/latest/configuration/suricata-yaml.html)). The `suricata_config_populate.py` script can use **many** environment variables when generating `suricata.yaml`. See the `DEFAULT_VARS` array in the script for a full list. Note that the environment variables must be prefixed with `SURICATA_` when defined in `suricata-live.env`.

The following environment variables related to tuning Suricata for live packet capture may be of particular interest, but this list is by no means exhaustive:

- `SURICATA_AF_PACKET_IFACE_THREADS` - the number of threads used to read packets via the AF_Packet interface (default `2`); a vaule of `auto` means to use the same number of threads as CPU cores
- [`SURICATA_MAX_PENDING_PACKETS`](https://docs.suricata.io/en/latest/performance/tuning-considerations.html#max-pending-packets-number) - the number simultaneous packets that the engine can handle; "setting this higher generally keeps the threads more busy, but setting it too high will lead to degradation" (default `10000`)
- [`SURICATA_AF_PACKET_RING_SIZE`](https://docs.suricata.io/en/latest/performance/tuning-considerations.html#ring-size) - the buffer size (in packets) per-thread; if this is set to `0` (the default), it will be "computed with respect to `max_pending_packets` and the number of threads"

See the Suricata documentation on [Tuning Considerations](https://docs.suricata.io/en/latest/performance/tuning-considerations.html#tuning-considerations) and [High Performance](https://docs.suricata.io/en/latest/performance/high-performance-config.html) for a more in-depth treatment of this topic, then cross-reference tuning parameters of interest with the variables in the `DEFAULT_VARS` array in `suricata_config_populate.py` to identify which variables correspond.

Note that for some variables (e.g., something with a sequence like `HOME_NET`) Suricata wants values to be quoted. To accomplish that in the `suricata.env` or `suricata-live.env` environment variable files, use outer single quotes with inner double quotes, like this:

  * `SURICATA_HOME_NET='"[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"'`
