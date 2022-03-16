# Malcolm Contributor Guide

The purpose of this document is to provide some direction for those willing to modify Malcolm, whether for local customization or for contribution to the Malcolm project.

## <a name="TableOfContents"></a>Table of Contents

* [Local modifications](#LocalMods)
    + [Docker bind mounts](#Bind)
    + [Building Malcolm's Docker images](#Build)
* [Adding a new service (Docker image)](#NewImage)
    + [Networking and firewall](#NewImageFirewall)
* [Adding new log fields](#NewFields)
- [Zeek](#Zeek)
    + [`local.zeek`](#LocalZeek)
    + [Adding a new Zeek package](#ZeekPackage)
    + [Zeek Intelligence Framework](#ZeekIntel)
* [PCAP processors](#PCAP)
* [Logstash](#Logstash)
    + [Parsing a new log data source](#LogstashNewSource)
    + [Parsing new Zeek logs](#LogstashZeek)
    + [Enrichments](#LogstashEnrichments)
    + [Logstash plugins](#LogstashPlugins)
* [OpenSearch Dashboards](#dashboards)
    + [Adding new visualizations and dashboards](#DashboardsNewViz)
    + [OpenSearch Dashboards plugins](#DashboardsPlugins)
* [Carved file scanners](#Scanners)
* [Style](#Style)

## <a name="LocalMods"></a>Local modifications

There are several ways to customize Malcolm's runtime behavior via local changes to configuration files. Many commonly-tweaked settings are discussed in the project [README](../../README.md) (see [`docker-compose.yml` parameters](../../README.md#docker-composeyml-parameters) and [Customizing event severity scoring](../../README.md#customizing-event-severity-scoring) for some examples).

### <a name="Bind"></a>Docker bind mounts

Some configuration changes can be put in place by modifying local copies of configuration files and then use a [Docker bind mount](https://docs.docker.com/storage/bind-mounts/) to overlay the modified file onto the running Malcolm container. This is already done for many files and directories used to persist Malcolm configuration and data. For example, the default list of bind mounted files and directories for each Malcolm service is as follows:

```
$ grep -P "^(      - ./|  \w+:)" docker-compose-standalone.yml
opensearch:
    - ./opensearch/opensearch.keystore:/usr/share/opensearch/config/opensearch.keystore:rw
    - ./nginx/ca-trust:/usr/share/opensearch/ca-trust:ro
    - ./opensearch:/usr/share/opensearch/data:delegated
    - ./opensearch-backup:/opt/opensearch/backup:delegated
dashboards-helper:
    - ./index-management-policy.json:/data/index-management-policy.json:ro
dashboards:
logstash:
    - ./logstash/certs/logstash.keystore:/usr/share/logstash/config/logstash.keystore:rw
    - ./logstash/maps/malcolm_severity.yaml:/etc/malcolm_severity.yaml:ro
    - ./nginx/ca-trust:/usr/share/logstash/ca-trust:ro
    - ./logstash/certs/ca.crt:/certs/ca.crt:ro
    - ./logstash/certs/server.crt:/certs/server.crt:ro
    - ./logstash/certs/server.key:/certs/server.key:ro
    - ./cidr-map.txt:/usr/share/logstash/config/cidr-map.txt:ro
    - ./host-map.txt:/usr/share/logstash/config/host-map.txt:ro
    - ./net-map.json:/usr/share/logstash/config/net-map.json:ro
filebeat:
    - ./zeek-logs:/data/zeek
    - ./filebeat/certs/ca.crt:/certs/ca.crt:ro
    - ./filebeat/certs/client.crt:/certs/client.crt:ro
    - ./filebeat/certs/client.key:/certs/client.key:ro
arkime:
    - ./auth.env
    - ./pcap:/data/pcap
    - ./arkime-logs:/opt/arkime/logs
    - ./arkime-raw:/opt/arkime/raw
zeek:
    - ./pcap:/pcap
    - ./zeek-logs/upload:/zeek/upload
    - ./zeek-logs/extract_files:/zeek/extract_files
file-monitor:
    - ./zeek-logs/extract_files:/data/zeek/extract_files
    - ./zeek-logs/current:/data/zeek/logs
    - ./yara/rules:/yara-rules/custom:ro
pcap-capture:
    - ./pcap/upload:/pcap
pcap-monitor:
    - ./zeek-logs:/zeek
    - ./pcap:/pcap
upload:
    - ./auth.env
    - ./pcap/upload:/var/www/upload/server/php/chroot/files
htadmin:
    - ./htadmin/config.ini:/var/www/htadmin/config/config.ini:rw
    - ./htadmin/metadata:/var/www/htadmin/config/metadata:rw
    - ./nginx/htpasswd:/var/www/htadmin/config/htpasswd:rw
freq:
name-map-ui:
    - ./cidr-map.txt:/var/www/html/maps/cidr-map.txt:ro
    - ./host-map.txt:/var/www/html/maps/host-map.txt:ro
    - ./net-map.json:/var/www/html/maps/net-map.json:rw
nginx-proxy:
    - ./nginx/nginx_ldap.conf:/etc/nginx/nginx_ldap.conf:ro
    - ./nginx/htpasswd:/etc/nginx/.htpasswd:ro
    - ./nginx/ca-trust:/etc/nginx/ca-trust:ro
    - ./nginx/certs:/etc/nginx/certs:ro
    - ./nginx/certs/dhparam.pem:/etc/nginx/dhparam/dhparam.pem:ro
```

So, for example, if you wanted to make a change to the `nginx-proxy` container's `nginx.conf` file, you could add the following line to the `volumes:` section of the `nginx-proxy` service in your `docker-compose.yml` file:

```
- ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
```

The change would take effect after stopping and starting Malcolm.

See the documentation on [Docker bind mount](https://docs.docker.com/storage/bind-mounts/) for more information on this technique.

### <a name="Build"></a>Building Malcolm's Docker images

Another method for modifying your local copies of Malcolm's services' containers is to [build your own](../../README.md#Build) containers with the modifications baked-in.

For example, say you wanted to create a Malcolm container which includes a new dashboard for OpenSearch Dashboards and a new enrichment filter `.conf` file for Logstash. After placing these files under `./dashboards/dashboards` and `./logstash/pipelines/enrichment`, respectively, in your Malcolm working copy, run `./build.sh dashboards-helper logstash` to build just those containers. After the build completes, you can run `docker images` and see you have fresh images for `malcolmnetsec/dashboards-helper` and `malcolmnetsec/logstash-oss`. You may need to review the contents of the [Dockerfiles](../../Dockerfiles) to determine the correct service and filesystem location within that service's Docker image depending on what you're trying to accomplish.

Alternately, if you have forked Malcolm on GitHub, [workflow files](../../.github/workflows/) are provided which contain instructions for GitHub to build the docker images and [sensor](#Hedgehog) and [Malcolm](#ISO) installer ISOs. The resulting images are named according to the pattern `ghcr.io/owner/malcolmnetsec/image:branch` (e.g., if you've forked Malcolm with the github user `romeogdetlevjr`, the `arkime` container built for the `main` would be named `ghcr.io/romeogdetlevjr/malcolmnetsec/arkime:main`). To run your local instance of Malcolm using these images instead of the official ones, you'll need to edit your `docker-compose.yml` file(s) and replace the `image:` tags according to this new pattern, or use the bash helper script `./shared/bin/github_image_helper.sh` to pull and re-tag the images.

## <a name="NewImage"></a>Adding a new service (Docker image)

A new service can be added to Malcolm by following the following steps:

1. Create a new subdirectory for the service (under the Malcolm working copy base directory) containing whatever source or configuration files are necessary to build and run the service
1. Create the service's Dockerfile in the [Dockerfiles](../../Dockerfiles) directory of your Malcolm working copy
1. Add a new section for your service under `services:` in the `docker-compose.yml` and `docker-compose-standalone.yml` files
1. If you want to enable automatic builds for your service on GitHub, create a new [workflow](../../.github/workflows/), using an existing workflow as an example

### <a name="NewImageFirewall"></a>Networking and firewall

If your service needs to expose a web interface to the user, you'll need to adjust the following files:

* Ensure your service's section in the `docker-compose` files uses the `expose` directive to indicate which ports its providing
* Add the service to the `depends_on` section of the `nginx-proxy` service in the `docker-compose` files
* Modify the configuration of the `nginx-proxy` container (in [`nginx/nginx.conf`](../../nginx/nginx.conf)) to define `upstream` and `location` directives to point to your service

Avoid publishing ports directly from your container to the host machine's network interface if at all possible. The `nginx-proxy` container handles encryption and authentication and should sit in front of any user-facing interface provided by Malcolm.

## <a name="NewFields"></a>Adding new log fields

As several of the sections in this document will reference adding new data source fields, we'll cover that here at the beginning.

Although OpenSearch is a NoSQL database and as-such is "unstructured" and "schemaless," in order to add a new data source field you'll need to define that field in a few places in order for it to show up and be usable throughout Malcolm. Minimally, you'll probably want to do it in these three files

* [`arkime/etc/config.ini`](../../arkime/etc/config.ini) - follow existing examples in the `[custom-fields]` and `[custom-views]` sections in order for [Arkime](https://arkime.com) to be aware of your new fields
* [`arkime/wise/source.zeeklogs.js`](../../arkime/wise/source.zeeklogs.js) - add new fields to the `allFields` array for Malcolm to create Arkime [value actions](https://arkime.com/settings#right-click) for your fields
* [`dashboards/malcolm_template.json`](../../arkime/wise/source.zeeklogs.js) - add new fields to the giant list of fields in this document in order for them to be defined as part of the `arkime_sessions3-*` [index template](https://opensearch.org/docs/latest/opensearch/index-templates/) used by Arkime and OpenSearch Dashboards in Malcolm

When possible, I recommend you to use (or at least take inspiration from) the [Elastic Common Schema (ECS) Reference](https://www.elastic.co/guide/en/ecs/current/index.html) when deciding how to define new field names.

## <a name="Zeek"></a>Zeek

### <a name="LocalZeek"></a>`local.zeek`

Some Zeek behavior can be tweaked without having to manually edit configuration files through the use of environment variables: search for `ZEEK` in the [`docker-compose.yml` parameters](../../README.md#docker-composeyml-parameters) section of the documentation.

Other changes to Zeek's behavior could be made by modifying [local.zeek](../../zeek/config/local.zeek) and either using a [bind mount](#Bind) or [rebuilding](#Build) the `zeek` Docker image with the modification. See the [Zeek documentation](https://docs.zeek.org/en/master/quickstart.html#local-site-customization) for more information on customizing a Zeek instance. Note that changing Zeek's behavior could result in changes to the format of the logs Zeek generates, which could break Malcolm's parsing of those logs, so exercise caution.

### <a name="ZeekPackage"></a>Adding a new Zeek package

The easiest way to add a new Zeek package to Malcolm is to add the git URL of that package to the `ZKG_GITHUB_URLS` array in [zeek_install_plugins.sh](../../shared/bin/zeek_install_plugins.sh) script and then [rebuilding](#Build) the `zeek` Docker image. This will cause your package to be installed (via the [`zkg`](https://docs.zeek.org/projects/package-manager/en/stable/zkg.html) command-line tool). See [Parsing new Zeek logs](#LogstashZeek) on how to process any new `.log` files if your package generates them.

### <a name="ZeekIntel"></a>Zeek Intelligence Framework

See [Zeek Intelligence Framework](../../README.md#ZeekIntel) in the Malcolm README for information on how to use Zeek's [Intelligence Framework](https://docs.zeek.org/en/master/frameworks/intel.html) with Malcolm.

## <a name="PCAP"></a>PCAP processors

When a PCAP is uploaded (either through Malcolm's [upload web interface](../../README.md#Upload) or just copied manually into the `./pcap/upload/` directory), the `pcap-monitor` container has a script that picks up those PCAP files and publishes to a [ZeroMQ](https://zeromq.org/) topic that can be subscribed to by any other process that wants to analyze that PCAP. In Malcolm at the time of this writing (as of the [v5.0.0 release](https://github.com/idaholab/Malcolm/releases/tag/v5.0.0)), there are two of those: the `zeek` container and the `arkime` container. In Malcolm, they actually both share the [same script](../../shared/bin/pcap_arkime_and_zeek_processor.py) to read from that topic and run the PCAP through Zeek and Arkime, respectively. If you're looking for an example to follow, the `zeek` container is the less complicated of the two. So, if you were looking to integrate a new  PCAP processing tool into Malcolm (named `cooltool` for this example), the process would be something like:

1. Define your service as instructed in the [Adding a new service](#NewImage) section
    * Note how the existing `zeek` and `arkime` services use [bind mounts](#Bind) to access the local `./pcap` directory
1. Write a script (modelled after [the one](../../shared/bin/pcap_arkime_and_zeek_processor.py) `zeek` and `arkime` use, if you like) which subscribes to the PCAP topic port (`30441` as defined in [pcap_utils.py](../../shared/bin/pcap_utils.py)) and handles the PCAP files published there, each PCAP file represented by a JSON dictionary with `name`, `tags`, `size`, `type` and `mime` keys (search for `FILE_INFO_` in [pcap_utils.py](../../shared/bin/pcap_utils.py)). This script should be added to and run by your `cooltool.Dockerfile`-generated container.
1. Add whatever other logic needed to get your tool's data into Malcolm, whether by writing it directly info OpenSearch or by sending log files for parsing and enrichment by [Logstash](#Logstash) (especially see the section on [Parsing a new log data source](#LogstashNewSource))

While that might be a bit of hand-waving, these general steps take care of the PCAP processing piece: you shouldn't have to really edit any *existing* code to add a new PCAP processor. You're just creating a new container for the Malcolm appliance to the ZeroMQ topic and handle the PCAPs your tool receives. 

The `PCAP_PIPELINE_DEBUG` and `PCAP_PIPELINE_DEBUG_EXTRA` environment variables in the `docker-compose` files can be set to `true` to enable verbose debug logging from the output of the Docker containers involved in the PCAP processing pipeline.

## <a name="Logstash"></a>Logstash

### <a name="LogstashNewSource"></a>Parsing a new log data source

Let's continue with the example of the `cooltool` service we added in the [PCAP processors](#PCAP) section above, assuming that `cooltool` generates some textual log files we want to parse and index into Malcolm. 

You'd have configured `cooltool` in your `cooltool.Dockerfile` and its section in the `docker-compose` files to write logs into a subdirectory or subdirectories in a shared folder [bind mounted](#Bind) in such a way that both the `cooltool` and `filebeat` containers can access. Referring to the `zeek` container as an example, this is how the `./zeek-logs` folder is handled; both the `filebeat` and `zeek` services have `./zeek-logs` in their `volumes:` section:

```
$ grep -P "^(      - ./zeek-logs|  [\w-]+:)" docker-compose.yml | grep -B1 "zeek-logs"
  filebeat:
      - ./zeek-logs:/data/zeek
--
  zeek:
      - ./zeek-logs/upload:/zeek/upload
…
```

You'll need to provide access to your `cooltool` logs in a similar fashion.

Next, tweak [`filebeat.yml`](../../filebeat/filebeat.yml) by adding a new log input path pointing to the `cooltool` logs to send them along to the `logstash` container. This modified `filebeat.yml` will need to be reflected in the `filebeat` container via [bind mount](#Bind) or by [rebuilding](#Build) it.

Logstash can then be easily extended to add more [`logstash/pipelines`](../../logstash/pipelines). At the time of this writing (as of the [v5.0.0 release](https://github.com/idaholab/Malcolm/releases/tag/v5.0.0)), the Logstash pipelines basically look like this:

* input (from `filebeat`) sends logs to 1..*n* **parse pipelines** (today it's just `zeek`)
* each **parse pipeline** does what it needs to do to parse its logs then sends them to the [**enrichment pipeline**](#LogstashEnrichments)
* the [**enrichment pipeline**](../../logstash/pipelines/enrichment) performs common lookups to the fields that have been normalized and indexes the logs into the OpenSearch data store

So, in order to add a new **parse pipeline** for `cooltool` after tweaking [`filebeat.yml`](../../filebeat/filebeat.yml) as described above, create a `cooltool` directory under [`logstash/pipelines`](../../logstash/pipelines) which follows the same pattern as the `zeek` parse pipeline. This directory will have an input file (tiny), a filter file (possibly large), and an output file (tiny).

Finally, in your `docker-compose` files, set a new `LOGSTASH_PARSE_PIPELINE_ADDRESSES` environment variable under `logstash-variables` to `cooltool-parse,zeek-parse` (assuming you named the pipeline address from the previous step `cooltool-parse`) so that logs sent from `filebeat` to `logstash` are forwarded to both parse pipelines.

### <a name="LogstashZeek"></a>Parsing new Zeek logs

The following modifications must be made in order for Malcolm to be able to parse new Zeek log files:

1. Add a parsing section to [`logstash/pipelines/zeek/11_zeek_logs.conf`](../../logstash/pipelines/zeek/11_zeek_logs.conf)
    * Follow patterns for existing log files as an example
    * For common Zeek fields like the `id` four-tuple, timestamp, etc., use the same convention used by existing Zeek logs in that file (e.g., `ts`, `uid`, `orig_h`, `orig_p`, `resp_h`, `resp_p`)
    * Take care, especially when copy-pasting filter code, that the Zeek delimiter isn't modified from a tab character to a space character (see "*zeek's default delimiter is a literal tab, MAKE SURE YOUR EDITOR DOESN'T SCREW IT UP*" warnings in that file)
1. If necessary, perform log normalization in [`logstash/pipelines/zeek/12_zeek_normalize.conf`](../../logstash/pipelines/zeek/12_zeek_normalize.conf) for values like action (`event.action`), result (`event.result`), application protocol version (`network.protocol_version`), etc.
1. If necessary, define conversions for floating point or integer values in [`logstash/pipelines/zeek/11_zeek_logs.conf`](../../logstash/pipelines/zeek/13_zeek_convert.conf)
1. Identify the new fields and add them as described in [Adding new log fields](#NewFields)

### <a name="LogstashEnrichments"></a>Enrichments

Malcolm's Logstash instance will do a lot of enrichments for you automatically: see the [enrichment pipeline](../../logstash/pipelines/enrichment), including MAC address to vendor by OUI, GeoIP, ASN, and a few others. In order to take advantage of these enrichments that are already in place, normalize new fields to use the same standardized field names Malcolm uses for things like IP addresses, MAC addresses, etc. You can add your own additional enrichments by creating new `.conf` files containing [Logstash filters](https://www.elastic.co/guide/en/logstash/7.10/filter-plugins.html) in the [enrichment pipeline](../../logstash/pipelines/enrichment) directory and using either of the techniques in the [Local modifications](#LocalMods) section to implement your changes in the `logstash` container

### <a name="LogstashPlugins"></a>Logstash plugins

The [logstash.Dockerfile](../../Dockerfiles/logstash.Dockerfile) installs the Logstash plugins used by Malcolm (search for `logstash-plugin install` in that file). Additional Logstash plugins could be installed by modifying this Dockerfile and [rebuilding](#Build) the `logstash` Docker image.

## <a name="dashboards"></a>OpenSearch Dashboards

[OpenSearch Dashboards](https://opensearch.org/docs/latest/dashboards/index/) is an open-source fork of [Kibana](https://www.elastic.co/kibana/), which is [no longer open-source software](https://github.com/idaholab/Malcolm/releases/tag/v5.0.0).

### <a name="DashboardsNewViz"></a>Adding new visualizations and dashboards

Visualizations and dashboards can be [easily created](../../README.md#BuildDashboard) in OpenSearch Dashboards using its drag-and-drop WYSIWIG tools. Assuming you've created a new dashboard you wish to package with Malcolm, the dashboard and its visualization components can be exported using the following steps:

1. Identify the ID of the dashboard (found in the URL: e.g., for `/dashboards/app/dashboards#/view/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` the ID would be `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)
1. Export the dashboard with that ID and save it in the `./dashboards./dashboards/` directory with the following command:
   ```
    export DASHID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx && \
      docker-compose exec dashboards curl -XGET \
      "http://localhost:5601/dashboards/api/opensearch-dashboards/dashboards/export?dashboard=$DASHID" > \
      ./dashboards/dashboards/$DASHID.json
    ```
1. It's preferrable for Malcolm to dynamically create the `arkime_sessions3-*` index template rather than including it in imported dashboards, so edit the `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.json` that was generated, and carefully locate and remove the section with the `id` of `arkime_sessions3-*` and the `type` of `index-pattern` (including the comma preceding it):
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
1. Include the new dashboard either by using a [bind mount](#Bind) for the `./dashboards./dashboards/` directory or by [rebuilding](#Build) the `dashboards-helper` Docker image. Dashboards are imported the first time Malcolm starts up.

### <a name="DashboardsPlugins"></a>OpenSearch Dashboards plugins

The [dashboards.Dockerfile](../../Dockerfiles/dashboards.Dockerfile) installs the OpenSearch Dashboards plugins used by Malcolm (search for `opensearch-dashboards-plugin install` in that file). Additional Dashboards plugins could be installed by modifying this Dockerfile and [rebuilding](#Build) the `dashboards` Docker image.

Third-party or community plugisn developed for Kibana will not install into OpenSearch dashboards without source code modification. Depending on the plugin, this could range from very smiple to very complex. As an illustrative example, the changes that were required to port the Sankey diagram visualization plugin from Kibana to OpenSearch Dashboards compatibility can be [viewed on GitHub](https://github.com/mmguero-dev/osd_sankey_vis/compare/edacf6b...main).

## <a name="Scanners"></a>Carved file scanners

Similar to the [PCAP processing pipeline](#PCAP) described above, new tools can plug into Malcolm's [automatic file extraction and scanning](../../README.md#ZeekFileExtraction) to examine file transfers carved from network traffic.

When Zeek extracts a file it observes being transfered in network traffic, the `file-monitor` container picks up those extracted files and publishes to a [ZeroMQ](https://zeromq.org/) topic that can be subscribed to by any other process that wants to analyze that extracted file. In Malcolm at the time of this writing (as of the [v5.0.0 release](https://github.com/idaholab/Malcolm/releases/tag/v5.0.0)), currently implemented file scanners include ClamAV, YARA, capa and VirusTotal, all of which are managed by the `file-monitor` container. The scripts involved in this code are:

* [shared/bin/zeek_carve_watcher.py](../../shared/bin/zeek_carve_watcher.py) - watches the directory to which Zeek extracts files and publishes information about those files to the ZeroMQ ventilator on port 5987
* [shared/bin/zeek_carve_scanner.py](../../shared/bin/zeek_carve_scanner.py) - subscribes to `zeek_carve_watcher.py`'s topic and performs file scanning for the ClamAV, YARA, capa and VirusTotal engines and sends "hits" to another ZeroMQ sync on port 5988
* [shared/bin/zeek_carve_logger.py](../../shared/bin/zeek_carve_logger.py) - subscribes to `zeek_carve_scanner.py`'s topic and logs hits to a "fake" Zeek signatures.log file which is parsed and ingested by Logstash
* [shared/bin/zeek_carve_utils.py](../../shared/bin/zeek_carve_utils.py) - various variables and classes related to carved file scanning

Additional file scanners could either be added to the `file-monitor` service, or to avoid coupling with Malcolm's code you could simply define a new service as instructed in the [Adding a new service](#NewImage) section and write your own scripts to subscribe and publish to the topics as described above. While that might be a bit of hand-waving, these general steps take care of the plumbing around extracting the file and notifying your tool, as well as handling the logging of "hits": you shouldn't have to really edit any *existing* code to add a new carved file scanner.

The `EXTRACTED_FILE_PIPELINE_DEBUG` and `EXTRACTED_FILE_PIPELINE_DEBUG_EXTRA` environment variables in the `docker-compose` files can be set to `true` to enable verbose debug logging from the output of the Docker containers involved in the carved file processing pipeline.

## <a name="Style"></a>Style

### Python

For Python code found in Malcolm, the author uses [Black: The uncompromising Python code formatter](https://github.com/psf/black) with the options `--line-length 120 --skip-string-normalization`.

## <a name="Footer"></a>Copyright

[Malcolm](https://github.com/idaholab/Malcolm) is Copyright 2022 Battelle Energy Alliance, LLC, and is developed and released through the cooperation of the [Cybersecurity and Infrastructure Security Agency](https://www.cisa.gov/) of the [U.S. Department of Homeland Security](https://www.dhs.gov/).

See [`License.txt`](../../License.txt) for the terms of its release.

### Contact information of author(s):

[malcolm@inl.gov](mailto:malcolm@inl.gov?subject=Malcolm)
