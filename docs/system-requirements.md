# <a name="SystemRequirements"></a>Recommended system requirements

Malcolm runs on top of [Docker](https://www.docker.com/), which runs on recent releases of Linux, Apple [macOS](host-config-macos.md#HostSystemConfigMac), and [Microsoft Windows](host-config-windows.md#HostSystemConfigWindows) 10 and up. Malcolm can also be deployed with [Podman](https://podman.io), or in the cloud [with Kubernetes](kubernetes.md#Kubernetes).

## <a name="ResourceEstimator"></a>Estimating storage before deployment

Use the [resource estimator](../scripts/estimate_resources.py) to calculate PCAP and OpenSearch storage targets from your *observed* average traffic, retention and indexing workload. For example:

```bash
python3 scripts/estimate_resources.py \
  --traffic-mbps 100 --capture-percent 20 --pcap-days 7 \
  --indexed-gib-per-day 30 --index-days 30 --headroom-percent 25
```

The traffic rate is in **decimal Mbps** averaged across the day, and capture percentage is the fraction retained as PCAP. You can use `--indexed-to-pcap-ratio` instead of `--indexed-gib-per-day` if you have measured a representative ratio of OpenSearch index growth to captured PCAP size. If neither index input is provided, the script reports only the PCAP estimate rather than inventing an indexing ratio. Use `--index-replicas` for additional index copies and `--json` for machine-readable output.

The free-space reserve defaults to 25% **of available capacity**. Estimates cover retained PCAP and indexed data only. Provide additional capacity for the OS, temporary processing, snapshots, backups, filesystem overhead and growth. Bandwidth averages hide traffic bursts; CPU and memory need separate validation under expected peak ingest loads. The published minimum and recommended CPU/RAM requirements below are starting points, not a model of throughput performance.



To quote the [Elasticsearch documentation](https://www.elastic.co/guide/en/elasticsearch/guide/current/hardware.html), "If there is one resource that you will run out of first, it will likely be memory." Malcolm requires a minimum of 8 CPU cores and 24 gigabytes of RAM on a dedicated server, but Malcolm developers recommend 16+ CPU cores and 32+ gigabytes of RAM for an optimal experience. Users will want as much available disk storage as possible (preferably solid state storage), as the amount of PCAP data a machine can analyze and store will be limited by available storage space.

Arkime's wiki has documents ([here](https://github.com/arkime/arkime#hardware-requirements) and [here](https://github.com/arkime/arkime/wiki/FAQ#what-kind-of-capture-machines-should-we-buy) and [here](https://github.com/arkime/arkime/wiki/FAQ#how-many-elasticsearch-nodes-or-machines-do-i-need) and a [calculator here](https://arkime.com/estimators)) that may be helpful, although not everything in those documents will apply to a containerized setup such as Malcolm.

