# <a name="ZeekIntel"></a>Zeek Intelligence Framework

* [Zeek Intelligence Framework](#ZeekIntel)
    - [STIX™ and TAXII™](#ZeekIntelSTIX)
    - [MISP](#ZeekIntelMISP)

To quote Zeek's [Intelligence Framework](https://docs.zeek.org/en/master/frameworks/intel.html) documentation, "The goals of Zeek’s Intelligence Framework are to consume intelligence data, make it available for matching, and provide infrastructure to improve performance and memory utilization. Data in the Intelligence Framework is an atomic piece of intelligence such as an IP address or an e-mail address. This atomic data will be packed with metadata such as a freeform source field, a freeform descriptive field, and a URL which might lead to more information about the specific item." Zeek [intelligence](https://docs.zeek.org/en/master/scripts/base/frameworks/intel/main.zeek.html) [indicator types](https://docs.zeek.org/en/master/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Type) include IP addresses, URLs, file names, hashes, email addresses, and more.

Malcolm doesn't come bundled with intelligence files from any particular feed, but they can be easily included into a local instance. On [startup]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/shared/bin/zeek_intel_setup.sh), Malcolm's `ghcr.io/idaholab/malcolm/zeek` docker container enumerates the subdirectories under `./zeek/intel` (which is [bind mounted](https://docs.docker.com/storage/bind-mounts/) into the container's runtime) and configures Zeek so those intelligence files will be automatically included in its local policy. Subdirectories under `./zeek/intel` that contain their own `__load__.zeek` file will be `@load`-ed as-is, while subdirectories containing "loose" intelligence files will be [loaded](https://docs.zeek.org/en/master/frameworks/intel.html#loading-intelligence) automatically with a `redef Intel::read_files` directive.

Note that Malcolm does not manage updates for these intelligence files. Users use the update mechanism suggested by the feeds' maintainers to keep intelligence files up to date, or use a [TAXII](#ZeekIntelSTIX) or [MISP](#ZeekIntelMISP) feed as described below.

Adding and deleting intelligence files under this directory will take effect upon [restarting Malcolm](running.md#StopAndRestart). Alternately, users can use the `ZEEK_INTEL_REFRESH_CRON_EXPRESSION` environment variable containing a [cron expression](https://en.wikipedia.org/wiki/Cron#CRON_expression) to specify the interval at which the intel files should be refreshed. This can also be done manually without restarting Malcolm by running the following command from the Malcolm installation directory:

```
docker compose exec --user $(id -u) zeek /usr/local/bin/entrypoint.sh true
```

For a public example of Zeek intelligence files, see Critical Path Security's [repository](https://github.com/CriticalPathSecurity/Zeek-Intelligence-Feeds), which aggregates data from various other threat feeds into Zeek's format.

## <a name="ZeekIntelSTIX"></a>STIX™ and TAXII™

In addition to loading Zeek intelligence files on startup, Malcolm will [automatically generate]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/shared/bin/zeek_intel_from_threat_feed.py) a Zeek intelligence file for all [Structured Threat Information Expression (STIX™)](https://oasis-open.github.io/cti-documentation/stix/intro.html) [v2.0](https://docs.oasis-open.org/cti/stix/v2.0/stix-v2.0-part1-stix-core.html)/[v2.1](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html) JSON files found under `./zeek/intel/STIX`.

Additionally, if a special text file named `.stix_input.txt` is found in `./zeek/intel/STIX`, that file will be read and processed as a list of [TAXII™](https://oasis-open.github.io/cti-documentation/taxii/intro.html) [2.0](http://docs.oasis-open.org/cti/taxii/v2.0/cs01/taxii-v2.0-cs01.html)/[2.1](https://docs.oasis-open.org/cti/taxii/v2.1/csprd02/taxii-v2.1-csprd02.html) feeds, one per line, according to the following format (the username and password are optional):

```
taxii|version|discovery_url|collection_name|username|password
```

For example:

```
taxii|2.0|http://example.org/taxii/|IP Blocklist|guest|guest
taxii|2.1|https://example.com/taxii/api2/|URL Blocklist
…
```

Malcolm will attempt to query the TAXII feed(s) for `indicator` STIX objects and convert them to the Zeek intelligence format as described above. There are publicly available TAXII 2.x-compatible services provided by a number of organizations including [Anomali Labs](https://www.anomali.com/resources/limo) and [MITRE](https://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/attck%E2%84%A2-content-available-in-stix%E2%84%A2-20-via); or users may choose from several open-source offerings to roll their own TAXII 2 server (e.g., [oasis-open/cti-taxii-server](https://github.com/oasis-open/cti-taxii-server), [freetaxii/server](https://github.com/freetaxii/server), [StephenOTT/TAXII-Server](https://github.com/StephenOTT/TAXII-Server), etc.).

Note that only **indicators** of [**cyber-observable objects**](https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_mlbmudhl16lr) matched with the **equals (`=`)** [comparison operator](https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_t11hn314cr7w) against a **single value** can be expressed as Zeek intelligence items. More complex STIX indicators will be silently ignored.

## <a name="ZeekIntelMISP"></a>MISP

In addition to loading Zeek intelligence files on startup, Malcolm will [automatically generate]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/shared/bin/zeek_intel_from_threat_feed.py) a Zeek intelligence file for all [Malware Information Sharing Platform (MISP)](https://www.misp-project.org/datamodels/) JSON files found under `./zeek/intel/MISP`.

Additionally, if a special text file named `.misp_input.txt` is found in `./zeek/intel/MISP`, that file will be read and processed as a list of [MISP feed](https://misp.gitbooks.io/misp-book/content/managing-feeds/#feeds) URLs, one per line, according to the following format:

```
misp|misp_url|auth_key (optional)
```

For example:

```
misp|https://example.com/data/feed-osint/manifest.json|df97338db644c64fbfd90f3e03ba8870
misp|https://example.com/doc/misp/|
misp|https://example.com/attributes|a943f5ff506ee6198e996333e0b672b1
misp|https://example.com/events|a943f5ff506ee6198e996333e0b672b1
…
```

Malcolm will attempt to connect to the MISP feed(s) and retrieve [`Attribute`](https://www.misp-standard.org/rfc/misp-standard-core.html#name-attribute) objects of MISP events and convert them to the Zeek intelligence format as described above. There are publicly available [MISP feeds](https://www.misp-project.org/feeds/) and [communities](https://www.misp-project.org/communities/), or users [may run](https://github.com/MISP/misp-docker) their [own MISP instance](https://www.misp-project.org/2019/09/25/hostev-vs-own-misp.html/).

Upon Malcolm connects to the URLs for the MISP feeds in `.misp_input.txt`, it will attempt to determine the format of the data served and process it accordingly. This could be presented as:

* a manifest JSON file
* a directory listing containing a file named `manifest.json`
* a directory listing of JSON files without a `manifest.json` file
* a list of [Events](https://www.misp-project.org/openapi/#tag/Events) returned for a request via the [MISP Automation API](https://www.misp-project.org/openapi/) made to a MISP platform's [`/events` endpoint](https://www.misp-project.org/openapi/#tag/Events/operation/restSearchEvents)
* a list of [Attributes](https://www.misp-project.org/openapi/#tag/Attributes) returned for a request via the [MISP Automation API](https://www.misp-project.org/openapi/) made to a MISP platform's [`/attributes` endpoint](https://www.misp-project.org/openapi/#tag/Attributes/operation/restSearchAttributes)

Note that only a subset of MISP [attribute types](https://www.misp-project.org/datamodels/#attribute-categories-vs-types) can be expressed with the Zeek intelligence [indicator types](https://docs.zeek.org/en/master/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Type). MISP attributes with other types will be silently ignored.