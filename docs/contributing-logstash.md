# <a name="Logstash"></a>Logstash

## <a name="LogstashNewSource"></a>Parsing a new log data source

To continue with the example of the `cooltool` service added in the [PCAP processors](contributing-pcap.md#PCAP) section, assuming that `cooltool` generates some textual log files to be parsed and indexed into Malcolm.

Users will have have configured `cooltool` in the `cooltool.Dockerfile` and its section in the `docker-compose` files to write logs into a subdirectory or subdirectories in a shared folder - [bind mounted](contributing-local-modifications.md#Bind) in such a way that both the `cooltool` and `filebeat` containers can access. Referring to the `zeek` container as an example, this is how the `./zeek-logs` folder is handled; both the `filebeat` and `zeek` services have `./zeek-logs` in their `volumes:` section:

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

Next, tweak [`filebeat.yml`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/filebeat/filebeat.yml) by adding a new log input path pointing to the `cooltool` logs to send them along to the `logstash` container. This modified `filebeat.yml` will need to be reflected in the `filebeat` container via [bind mount](contributing-local-modifications.md#Bind) or by [rebuilding](development.md#Build) it.

Logstash can then be easily extended to add more [`logstash/pipelines`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/pipelines). At the time of this writing (as of the [v5.0.0 release]({{ site.github.repository_url }}/releases/tag/v5.0.0)), the Logstash pipelines basically look like this:

* input (from `filebeat`) sends logs to 1..*n* **parse pipelines**
* each **parse pipeline** does what it needs to do to parse its logs then sends them to the [**enrichment pipeline**](#LogstashEnrichments)
* the [**enrichment pipeline**]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/pipelines/enrichment) performs common lookups to the fields that have been normalized and indexes the logs into the OpenSearch data store

In order to add a new **parse pipeline** for `cooltool` after tweaking [`filebeat.yml`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/filebeat/filebeat.yml) as described above, create a `cooltool` directory under [`logstash/pipelines`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/pipelines) that follows the same pattern as the `zeek` parse pipeline. This directory will have an input file (tiny), a filter file (possibly large), and an output file (tiny). In the filter file, be sure to set the field [`event.hash`](https://www.elastic.co/guide/en/ecs/master/ecs-event.html#field-event-hash) to a unique value to identify indexed documents in OpenSearch; the [fingerprint filter](https://www.elastic.co/guide/en/logstash/current/plugins-filters-fingerprint.html) may be useful for this.

Finally, in the [`./config/logstash.env` file](malcolm-config.md#MalcolmConfigEnvVars), set a new `LOGSTASH_PARSE_PIPELINE_ADDRESSES` environment variable to `cooltool-parse,zeek-parse,suricata-parse,beats-parse` (assuming the pipeline address from the previous step was named `cooltool-parse`) so that logs sent from `filebeat` to `logstash` are forwarded to all parse pipelines.

## <a name="LogstashZeek"></a>Parsing new Zeek logs

The following modifications must be made in order for Malcolm to parse new Zeek log files:

1. Add a parsing section to [`logstash/pipelines/zeek/11_zeek_parse.conf`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/pipelines/zeek/11_zeek_parse.conf)
    * Follow patterns for existing log files as an example
    * For common Zeek fields such as the `id` four-tuple, timestamp, etc., use the same convention used by existing Zeek logs in that file (e.g., `ts`, `uid`, `orig_h`, `orig_p`, `resp_h`, `resp_p`)
    * Take care, especially when copy-pasting filter code, the Zeek delimiter isn't modified from a tab character to a space character (see "*zeek's default delimiter is a literal tab, MAKE SURE YOUR EDITOR DOESN'T SCREW IT UP*" warnings in that file)
1. If necessary, perform log normalization in [`logstash/pipelines/zeek/12_zeek_normalize.conf`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/pipelines/zeek/12_zeek_normalize.conf) for values such as action (`event.action`), result (`event.result`), application protocol version (`network.protocol_version`), etc.
1. If necessary, define conversions for floating point or integer values in [`logstash/pipelines/zeek/11_zeek_parse.conf`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/pipelines/zeek/14_zeek_convert.conf)
1. Identify the new fields and add them as described in [Adding new log fields](contributing-new-log-fields.md#NewFields)

The script [`scripts/zeek_script_to_malcolm_boilerplate.py`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/scripts/zeek_script_to_malcolm_boilerplate.py) may help by autogenerating these filters.

## <a name="LogstashEnrichments"></a>Enrichments

Malcolm's Logstash instance will do a lot of enrichments automatically: see the [enrichment pipeline]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/pipelines/enrichment), including MAC address to vendor by OUI, GeoIP, ASN, and a few others. In order to take advantage of these enrichments that are already in place, normalize new fields to use the same standardized field names Malcolm uses for things such as IP addresses, MAC addresses, etc. Additional enrichments may be added by creating new `.conf` files containing [Logstash filters](https://www.elastic.co/guide/en/logstash/7.10/filter-plugins.html) in the [enrichment pipeline]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/pipelines/enrichment) directory and using either of the techniques in the [Local modifications](contributing-local-modifications.md#LocalMods) section to implement those changes in the `logstash` container.

## <a name="LogstashPlugins"></a>Logstash plugins

The [logstash.Dockerfile]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/Dockerfiles/logstash.Dockerfile) installs the Logstash plugins used by Malcolm (search for `logstash-plugin install` in that file). Additional Logstash plugins could be installed by modifying this Dockerfile and [rebuilding](development.md#Build) the `logstash` Docker image.