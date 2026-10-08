# <a name="Logstash"></a>Logstash

## <a name="LogstashNewSource"></a>Parsing a new log data source

To continue with the example of the `cooltool` service added in the [PCAP processors](contributing-pcap.md#PCAP) section, assuming that `cooltool` generates some textual log files to be parsed and indexed into Malcolm.

Users will have configured `cooltool` in the `cooltool.Dockerfile` and its section in the `docker-compose` files to write logs into a subdirectory or subdirectories in a shared folder - [bind mounted](contributing-local-modifications.md#Bind) in such a way that both the `cooltool` and `filebeat` containers can access. Referring to the `zeek` container as an example, this is how the `./zeek-logs` folder is handled; both the `filebeat` and `zeek` services have `./zeek-logs` in their `volumes:` section:

```
$ grep -P "^(      - ./zeek-logs|  [\w-]+:)" docker-compose.yml | grep -B1 "zeek-logs"
  filebeat:
      - ./zeek-logs:/data/zeek
--
  zeek:
      - ./zeek-logs/upload:/zeek/upload
…
```

Access to the `cooltool` logs must be provided in a similar fashion.

Next, tweak [`filebeat-logs.yml`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/filebeat/filebeat-logs.yml) by adding a new log input path pointing to the `cooltool` logs to send them along to the `logstash` container. Ensure you add a unique tag to this new input: it will be used by Logstash to route the logs to the correct parse pipeline (e.g., `tags: ["_cooltool"]`; see `tags` in the existing inputs for examples). This modified `filebeat-logs.yml` will need to be reflected in the `filebeat` container via [bind mount](contributing-local-modifications.md#Bind) or by [rebuilding](development.md#Build) it.

Logstash can then be easily extended to add more [`logstash/pipelines`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/pipelines). At the time of this writing (as of the [v5.0.0 release]({{ site.github.repository_url }}/releases/tag/v5.0.0)), the Logstash pipelines basically look like this:

* input (from `filebeat`) sends logs to 1..*n* **parse pipelines**
* each **parse pipeline** does what it needs to do to parse its logs then sends them to the [**enrichment pipeline**](#LogstashEnrichments)
* the [**enrichment pipeline**]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/pipelines/enrichment) performs common lookups to the fields that have been normalized and indexes the logs into the OpenSearch data store

In order to add a new **parse pipeline** for `cooltool` after tweaking [`filebeat-logs.yml`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/filebeat/filebeat-logs.yml) as described above, create a `cooltool` directory under [`logstash/pipelines`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/pipelines) that follows the same pattern as the `zeek` parse pipeline. This directory will have an input file (tiny; minimally it should include the parse pipeline name, e.g., `pipeline { address => "cooltool-parse" }`), a filter file (possibly large), and an output file (tiny). In the filter file, be sure to set the field [`event.hash`](https://www.elastic.co/guide/en/ecs/master/ecs-event.html#field-event-hash) to a unique value to identify indexed documents in OpenSearch; the [fingerprint filter](https://www.elastic.co/guide/en/logstash/current/plugins-filters-fingerprint.html) may be useful for this.

Finally, in [`./logstash/maps/parse_pipelines.yaml`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/maps/parse_pipelines.yaml), add a new `cooltool` mapping which maps the new parse pipeline name to the unique tag associated with the logs in the FileBeat configuration as described above, e.g.:

```yaml
cooltool-parse:
  - _cooltool
```

This modified `parse_pipelines.yaml` will need to be reflected in the `logstash` container via [bind mount](contributing-local-modifications.md#Bind) (similar to the bind for `malcolm_severity.yaml` in the `docker-compose` files) or by [rebuilding](development.md#Build) it.

## <a name="LogstashZeek"></a>Parsing new Zeek logs

The following modifications must be made in order for Malcolm to parse new Zeek log files:

1. Add a parsing filter file named so that it sorts after [`logstash/pipelines/zeek/1001_zeek_parse.conf`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/pipelines/zeek/1001_zeek_parse.conf) but before [`logstash/pipelines/zeek/1199_zeek_unknown.conf`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/pipelines/zeek/1199_zeek_unknown.conf)
    * Follow patterns for existing log files as an example
    * For common Zeek fields such as the `id` four-tuple, timestamp, etc., use the same convention used by existing Zeek logs in that file (e.g., `ts`, `uid`, `orig_h`, `orig_p`, `resp_h`, `resp_p`)
    * The [`logstash/scripts/logstash-start.sh`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/scripts/logstash-start.sh) Logstash container startup script should automatically fix any issues with parsing the Zeek tab delimiter (e.g., converting spaces in the `dissect` and `split` filters to tabs)
2. If necessary, perform log normalization in [`logstash/pipelines/zeek/1300_zeek_normalize.conf`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/pipelines/zeek/1300_zeek_normalize.conf) for values such as action (`event.action`), result (`event.result`), application protocol version (`network.protocol_version`), etc.
3. If necessary, define conversions for floating point or integer values in [`logstash/pipelines/zeek/1400_zeek_convert.conf`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/pipelines/zeek/1400_zeek_convert.conf)
4. If necessary, define custom source fields for fingerprinting (to ensure a unique and reproducible hash is created for the new logs) in [`logstash/pipelines/zeek/2000_fingerprint.conf`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/pipelines/zeek/2000_fingerprint.conf). Only use repeatable fields in the fingerprint source (e.g., *not* `uid` or `fuid` fields, as they are randomly generated). See [cisagov/Malcolm#715](https://github.com/cisagov/Malcolm/issues/715) for more information on why this is needed.
5. Identify the new fields and add them as described in [Adding new log fields](contributing-new-log-fields.md#NewFields)

The script [`scripts/zeek_script_to_malcolm_boilerplate.py`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/scripts/zeek_script_to_malcolm_boilerplate.py) may help by autogenerating these filters.

## <a name="LogstashEnrichments"></a>Enrichments

Malcolm's Logstash instance will do a lot of enrichments automatically: see the [enrichment pipeline]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/pipelines/enrichment), including MAC address to vendor by OUI, GeoIP, ASN, and a few others. In order to take advantage of these enrichments that are already in place, normalize new fields to use the same standardized field names Malcolm uses for things such as IP addresses, MAC addresses, etc. Additional enrichments may be added by creating new `.conf` files containing [Logstash filters](https://www.elastic.co/guide/en/logstash/7.10/filter-plugins.html) in the [enrichment pipeline]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/pipelines/enrichment) directory and using either of the techniques in the [Local modifications](contributing-local-modifications.md#LocalMods) section to implement those changes in the `logstash` container.

## <a name="LogstashBenchmark"></a>Measuring enrichment overhead

The read-only [enrichment benchmark tool]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/scripts/benchmark_enrichment.py) captures two measurements from **running** Malcolm containers:

- Allocated OpenSearch data-directory size, using `du -sk /usr/share/opensearch/data`.
- Each Logstash pipeline's processed-event count and each filter's event counts and cumulative processing time, from `/_node/stats/pipelines`.

Use a **disposable test deployment** and the same PCAP files for every experiment. Reset the indexes through the normal Malcolm maintenance workflow and restart Logstash between variants; do not wipe or reset a production deployment. Wait for ingestion to finish before recording each snapshot.

For example, compare the existing NetBox dataset setting `LOGSTASH_NETBOX_ENRICHMENT_DATASETS=default` with `LOGSTASH_NETBOX_ENRICHMENT_DATASETS=all`, keeping `NETBOX_ENRICHMENT` and other settings identical:

```bash
# After ingesting the test dataset under the default configuration
python3 scripts/benchmark_enrichment.py snapshot --label netbox-default --output /tmp/netbox-default.json

# After resetting the disposable deployment, restarting Logstash, changing the setting and re-ingesting the SAME dataset
python3 scripts/benchmark_enrichment.py snapshot --label netbox-all --output /tmp/netbox-all.json

# Show allocated storage and normalized per-filter processing time
python3 scripts/benchmark_enrichment.py compare /tmp/netbox-default.json /tmp/netbox-all.json --filter netbox
```

Repeat for other flags such as `LOGSTASH_OUI_LOOKUP`, `LOGSTASH_SEVERITY_SCORING`, `LOGSTASH_REVERSE_DNS`, or `FREQ_LOOKUP`. Run the capture commands from the Malcolm repository root, or specify `--project-dir` with the `snapshot` command.

The snapshots preserve the raw per-filter count and duration metrics for review. Comparisons report **milliseconds per 1,000 filter input events** alongside pipeline event counts to help detect mismatched workloads. Logstash counters accumulate from process startup, and OpenSearch `du` measures allocated disk space rather than just logical index bytes. Both require equivalent ingestion workloads and reset conditions for meaningful comparisons.

## <a name="LogstashPlugins"></a>Logstash plugins

The [logstash.Dockerfile]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/Dockerfiles/logstash.Dockerfile) installs the Logstash plugins used by Malcolm (search for `logstash-plugin install` in that file). Additional Logstash plugins could be installed by modifying this Dockerfile and [rebuilding](development.md#Build) the `logstash` image.