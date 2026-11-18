# <a name="ZeekParser"></a>Adding a new Zeek parser

This page walks through integrating a Zeek package that writes new logs into Malcolm, from installing the package to building its dashboard. The steps are written in the order they're usually done, and the [checklist](#ZeekParserChecklist) at the end lists every file involved.

The examples use a made-up package, `icsnpp-foo`, that writes `foo.log`, `foo_detail.log` and `foo_errors.log`. Replace `foo` with your parser's name throughout.

* [Overview](#ZeekParserOverview)
* [1. Before you start](#ZeekParserBefore)
* [2. Install the package](#ZeekParserInstall)
* [3. Configure the analyzer](#ZeekParserConfigure)
* [4. Generate the boilerplate](#ZeekParserBoilerplate)
* [5. Plan the normalization](#ZeekParserPlan)
* [6. Logstash](#ZeekParserLogstash)
* [7. Field definitions](#ZeekParserFields)
* [8. Documentation](#ZeekParserDocs)
* [9. Test and verify](#ZeekParserTest)
* [10. Dashboards](#ZeekParserDashboards)
* [11. Report problems upstream](#ZeekParserUpstream)
* [Checklist](#ZeekParserChecklist)

## <a name="ZeekParserOverview"></a>Overview

A Zeek log goes through several stages before it shows up in Malcolm, and a new parser touches each of them:

| Stage | What you add | Where |
|---|---|---|
| Zeek | the package, its enable/disable and port settings | `zeek/zeek-packages.list`, `zeek/zeek-packages.lock`, `zeek/config/local.zeek`, `config/zeek.env.example` |
| Logstash parsing | turning each log line into fields | `logstash/pipelines/zeek/10xx_zeek_foo.conf` |
| Logstash normalization | shared fields, ECS fields, value cleanup, timestamps, document IDs | `logstash/pipelines/zeek/1200_zeek_mutate.conf`, `1300_zeek_normalize.conf`, `1400_zeek_convert.conf`, `2000_fingerprint.conf`, `logstash/maps/*.yaml`, `logstash/pipelines/enrichment/20_enriched_to_ecs.conf` |
| Field definitions | field types and how Arkime shows them | `dashboards/templates/composable/component/zeek.json` or `zeek_ot.json`, `arkime/etc/config.ini`, `arkime/wise/source.zeeklogs.js` |
| Documentation | the protocol and its settings | `docs/protocols.md`, `docs/malcolm-config.md` |
| Tests | capture files and expected datasets | [Malcolm-Test-Artifacts](https://github.com/idaholab/Malcolm-Test-Artifacts), [Malcolm-Test](https://github.com/idaholab/Malcolm-Test) |
| Dashboards | a dashboard and its navigation link | `dashboards/dashboards/`, `dashboards/dashboards/navigation.md` |

Most of the parsing and field definitions can be generated from the package's Zeek scripts with [`scripts/zeek_script_to_malcolm_boilerplate.py`](#ZeekParserBoilerplate). The rest of the work is deciding how the parser's fields fit into Malcolm's data model, and checking the result against real traffic.

## <a name="ZeekParserBefore"></a>1. Before you start

**Check that the package is a good fit.** Malcolm pins and builds every third-party package it ships, so review the package against the [standards of trust for upstream code](contributing-guide-code-provenance.md#StandardsOfTrustForProvidersOfUpstreamCode) before investing time in it.

**Read the package's Zeek scripts.** You'll need to know:

* which `record` types are written to logs (look for `Log::create_stream` and its `$columns` and `$path`), and which of their fields have the `&log` attribute
* whether the analyzer is a Spicy analyzer (it has an `.evt` file declaring a `protocol analyzer ... over TCP` or `over UDP`) or a compiled plugin, since they're disabled differently
* whether the package exposes its ports as a `&redef` set (e.g., `const foo_ports = { 1234/tcp } &redef;`) and registers its analyzer for those ports, which is what makes the ports configurable
* what each field means, including its units and its possible values. Read the code that sets the fields, not just the package's documentation: a field documented as epoch seconds might hold milliseconds for some rows, or one field might carry two unrelated vocabularies depending on the row. These details decide how you normalize the field later.

**Find captures to test with.** Many packages ship their own test traces (often under `testing/traces/`), along with baseline outputs that show what the logs should contain. Real-world captures are better still if you can find them. To check whether a capture actually contains the protocol, `tshark` helps; for example, for a protocol carried over MMS:

```bash
tshark -r capture.pcap -Y 'mms' | wc -l
tshark -r capture.pcap -q -z conv,tcp      # which connections and ports
tshark -r capture.pcap -q -z io,phs        # which protocols Wireshark recognizes
```

If the traffic is on a port Wireshark doesn't associate with the protocol, tell it with `-d` (e.g., `-d tcp.port==10102,tpkt`).

**Run the package in Zeek by itself first.** Before touching Malcolm, run Zeek with the package loaded against your captures and look at the logs it writes. This is the reference you'll compare Malcolm's results against in [Test and verify](#ZeekParserTest). Keep these logs.

## <a name="ZeekParserInstall"></a>2. Install the package

Zeek packages are installed when the `zeek` image is built, from two files:

* [`zeek/zeek-packages.list`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/zeek/zeek-packages.list) is edited by hand. Each line is `url|ref|env|method`, where everything after the URL is optional: the branch, tag or commit to track (when empty, the latest GitHub release, else the highest version tag, else the default branch, matching `zkg`'s own choice); semicolon-separated environment variables for the install (e.g., `CMAKE_BUILD_TYPE=Debug`); and `clone:<path>` for repositories that aren't installed with `zkg` but checked out to a path under the Zeek directory. For example:

```
https://github.com/cisagov/icsnpp-foo|main
```

* [`zeek/zeek-packages.lock`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/zeek/zeek-packages.lock) is generated. It pins each entry in the list to an exact commit, and the build installs only what it names.

After editing the list, generate the lock entry and review the diff:

```bash
GITHUB_TOKEN=... ./scripts/update_pins.py --zeek-packages --apply
git diff zeek/zeek-packages.lock
```

See [Version Pinning](contributing-guide-code-provenance.md#VersionPinning) and [Updating a Pin](contributing-guide-code-provenance.md#UpdatingAPin) for more on how pins work. The install itself is done by [`zeek/scripts/zeek_install_plugins.sh`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/zeek/scripts/zeek_install_plugins.sh); if a package needs extra `zkg` arguments (such as `--user-var`), add them in its `zkg_install_pinned` function. Then [rebuild](development.md#Build) the `zeek` image.

Packages are loaded with `@load packages` in [`local.zeek`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/zeek/config/local.zeek), so an installed package is active without any further changes. Packages installed with `clone:` aren't zkg packages, so they need their own `@load`.

## <a name="ZeekParserConfigure"></a>3. Configure the analyzer

Users control analyzers through environment variables in `config/zeek.env`, which [`local.zeek`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/zeek/config/local.zeek) reads when Zeek starts. Follow the naming already in use:

| Variable | Use |
|---|---|
| `ZEEK_DISABLE_ICS_FOO` | disables an ICS/OT analyzer (these also honor `ZEEK_DISABLE_ICS_ALL`) |
| `ZEEK_DISABLE_SPICY_FOO` | disables a non-ICS Spicy analyzer |
| `ZEEK_PORTS_FOO` | overrides the analyzer's ports, as a comma-separated list like `1234/tcp,1235/udp` |
| `ZEEK_FOO_<OPTION>` | any other setting specific to the parser (e.g., `ZEEK_FOO_DETAILED`) |

### Disabling the analyzer

In `local.zeek`, read the variable near the other `global disable_...` lines:

```zeek
global disable_ics_foo = (getenv("ZEEK_DISABLE_ICS_FOO") == true_regex) ? T : F;
```

Then disable the analyzer in the `zeek_init` event alongside the others. The call depends on the analyzer type:

```zeek
  # Spicy analyzer: the tag comes from the .evt file's "protocol analyzer FOO_TCP over TCP"
  #   (a name declared as spicy::FOO_TCP becomes ANALYZER_SPICY_FOO_TCP)
  if (disable_ics_all || disable_ics_foo) {
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_FOO_TCP);
  }

  # compiled plugin
  if (disable_ics_all || disable_ics_foo) {
    Analyzer::disable_analyzer(Analyzer::ANALYZER_FOO);
  }
```

When you test the parser, check that setting the variable to `true` really does stop its logs.

### Configurable ports

If the package exposes a `&redef` port set, read the variable with the other `..._ports_str` globals and redefine the set at parse time, following the existing examples. `split_ports_by_protocol` separates TCP from UDP ports:

```zeek
global foo_ports_str = getenv("ZEEK_PORTS_FOO");

@if ((!disable_ics_all) && (!disable_ics_foo) && (foo_ports_str != ""))
  global split_foo_ports = split_ports_by_protocol(foo_ports_str);
  @if (|split_foo_ports$tcp| > 0)
    redef FOO::foo_ports = split_foo_ports$tcp;
  @endif
@endif
```

### Environment files and documentation

Add the variables to [`config/zeek.env.example`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/config/zeek.env.example) next to the related ones. Leave the value empty for analyzers that are on by default, or set a disable variable to `true` for analyzers that should be off by default. Describe each new variable in [`docs/malcolm-config.md`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/docs/malcolm-config.md).

These variables aren't exposed in Malcolm's configuration UI; users set them in the `.env` file. For Kubernetes deployments, the [Malcolm Helm chart](https://github.com/idaholab/Malcolm-Helm) has its own copy of them: once the parser is in a Malcolm release, add the variables to the chart's `values.yaml` (under `zeek_env`; ports go under `zeek_env.zeek_ports`) and `templates/malcolm_configmaps.yaml`, and submit them as a pull request to that repository.

### Script optimization (ZAM)

Malcolm can run Zeek with its ZAM script optimizer (`ZEEK_ZAM_ENABLED`). ZAM compiles every loaded script when Zeek starts, and a large package can make that compile very slow. [`scripts/zeek-zam-bench.sh`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/scripts/zeek-zam-bench.sh) installs each package from the lock file in a fresh container and times Zeek startup with and without ZAM:

```bash
./scripts/zeek-zam-bench.sh -p capture.pcap -l zeek/zeek-packages.lock -f 'icsnpp-foo'
```

If startup with ZAM takes far longer for the new package than for the others, or times out, note it in the documentation and [report it upstream](#ZeekParserUpstream).

## <a name="ZeekParserBoilerplate"></a>4. Generate the boilerplate

[`scripts/zeek_script_to_malcolm_boilerplate.py`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/scripts/zeek_script_to_malcolm_boilerplate.py) reads the package's `.zeek` scripts and generates a starting point for the Logstash parse filters, Arkime field definitions and views, OpenSearch template mappings and WISE field list. It needs the `zeekscript` and `python-slugify` Python packages, and `malcolm_utils.py` from the same directory:

```bash
python3 -m pip install zeekscript python-slugify
./scripts/zeek_script_to_malcolm_boilerplate.py \
  -i ~/src/icsnpp-foo/scripts/*.zeek \
  -p tcp \
  -s foo \
  -u https://github.com/cisagov/icsnpp-foo \
  -g zeek_foo \
  -l foo.logstash.conf \
  -a foo.arkime.ini \
  -x foo.template.json \
  -w foo.wise.txt
```

* `-i` takes the package's `.zeek` scripts. Pass all of them (e.g., `scripts/*.zeek`), not just the one defining the records: the log names come from the `Log::create_stream` calls, which are often in a different file (such as `main.zeek`).
* `-p` and `-s` set the `proto` and `service` values added to each log. Malcolm turns `service` into `network.protocol`, so always set it.
* `-g` puts every field in one Arkime field group, which is the usual choice for a parser with several logs. Without it, each log gets its own group.
* `-u` adds a reference URL to the generated comments.

Review the output before using it:

* **Log names.** Each log's name comes from the `$path` in its `Log::create_stream` call. If the script can't find one for a record, it warns and uses the record's name instead, which will be wrong for `log_source`, the field names and the plugin IDs.
* **Plugin IDs.** Logstash plugin IDs must be unique across the whole pipeline. Check that each generated `id` contains the log's name, not a generic record name like `info`.
* **Types.** Zeek `int` and `count` are both mapped to `long`. Zeek `time` fields are mapped to `date`, and the Logstash output ends with a list of them to add to [`1400_zeek_convert.conf`](#ZeekParserConvert). Everything else becomes a `keyword`.

The generated files cover the parse filters and the first version of the field definitions. Everything else in this guide is done by hand.

## <a name="ZeekParserPlan"></a>5. Plan the normalization

Before writing more configuration, decide how the parser's fields fit into Malcolm's data model. It's easier to settle this once than to rework it across seven files later.

### Fields shared across logs

Parsers that write several logs often repeat the same fields across them: a request ID, an object name, a connection phase, an error code. If those are moved to one shared location, analysts can filter on one field and see every log where the value appears. Malcolm puts them under the namespace of the parser's main log. For example, a field that appears in `foo.log` and `foo_detail.log` is stored as `zeek.foo.request_id` for both, not as `zeek.foo.request_id` and `zeek.foo_detail.request_id`.

To find candidates, list every `&log` field in every record and look for names that appear in more than one. Then check each one:

* **The meaning has to match, not just the name.** Read the code that sets the field in each log. Two fields both called `timestamp` might be a point's timestamp in one log and a report's timestamp in another; those stay separate, and one of them should get a more specific name.
* **The types have to match.** A field can only have one mapping.
* **Different names can be the same field.** Two fields with different names but the same values and meaning (e.g., `pairing_status` and `result_pairing_status`) can be merged into one.

Keep a short list of every rename and merge you decide on. It drives the Logstash renames, the template, the Arkime definitions and the WISE list.

### ECS fields

Malcolm fills in a few [ECS](https://www.elastic.co/guide/en/ecs/current/index.html) fields for every protocol, and dashboards such as Actions and Results depend on them:

* `event.action`: the operation, e.g., `read`, `write`, `select`
* `event.result`: the outcome, e.g., `Success`, an error class, a status name
* `network.protocol_version`: the protocol version, when the traffic reveals it
* `zeek.software.*`: vendor, product and version, when the protocol identifies them

Read the parser's code to find which fields carry these and what values they can take. Pay attention to fields that mix kinds of values: a field that holds the operation name plus a stage (e.g., `write_request`, `write_response`) should feed only its base action into `event.action`, and lifecycle markers like `requested` may not belong in `event.result` at all. Make a first decision now and revisit it once you can see real data.

### Protocol labeling

`network.protocol` comes from the log's `service`. If the parser handles more than one protocol (for example, a parser that also recognizes a protocol it's layered on), decide whether some rows should be labeled with the other protocol, and which field tells you.

## <a name="ZeekParserLogstash"></a>6. Logstash

Zeek logs go through the Zeek parse pipeline in [`logstash/pipelines/zeek/`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/pipelines/zeek), whose files run in name order. See [Logstash](contributing-logstash.md#LogstashZeek) for an overview of each stage.

### <a name="ZeekParserParse"></a>Parse filters: `10xx_zeek_foo.conf`

Create a file for the parser, named so it sorts after `1001_zeek_parse.conf` and before `1199_zeek_unknown.conf` (e.g., `1070_zeek_foo.conf`), and put the generated Logstash boilerplate in it. Keep this file to parsing: one block per log that splits the line into `[zeek_cols]` fields and adds `proto` and `service`. Normalization belongs in the later stages.

The common Zeek fields (`ts`, `uid`, the `id` four-tuple, `is_orig`, `service` and so on) are renamed to their standard locations at the top of `1200_zeek_mutate.conf` for every log, so the parser doesn't need to handle them.

### Maps

Three maps in [`logstash/maps/`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/maps) need entries, in alphabetical order:

* `zeek_log_ecs_categories.yaml`: the `event.category` values for **every** log the parser writes, e.g., `"foo_detail": ["ot", "network"]` for an OT protocol
* `zeek_log_transport.yaml`: the transport for every log, e.g., `foo_detail: tcp`
* `service_ports.yaml`: the service's default ports. If another service already uses the same port, check how the two analyzers interact in [Test and verify](#ZeekParserTest).

For an OT protocol, also add its `network.protocol` values to the OT list in [`logstash/pipelines/enrichment/20_enriched_to_ecs.conf`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/pipelines/enrichment/20_enriched_to_ecs.conf). That list categorizes other logs (such as `conn.log`) as OT based on their protocol. If the parser relabels some rows with a different protocol, add that value too.

### <a name="ZeekParserMutate"></a>Shared fields and cleanup: `1200_zeek_mutate.conf`

Add a branch for the parser to the `[log_source]` chain in `1200_zeek_mutate.conf`, in alphabetical order:

```
  } else if ([log_source] =~ /^foo/) {
    #############################################################################################################################
    # foo*.log specific logic
```

Do the renames from your plan in a single `mutate` at the start of the branch, so everything after it can use the final field names:

```
    mutate {
      id => "mutate_rename_foo_normalized_fields"
      rename => { "[zeek][foo_detail][request_id]" => "[zeek][foo][request_id]"
                  "[zeek][foo_errors][request_id]" => "[zeek][foo][request_id]"
                  "[zeek][foo][result_pairing_status]" => "[zeek][foo][pairing_status]" }
    }
```

A `rename` only needs to become a `merge` if two source fields in the same log land on the same target. If a rename only applies to some rows, put a conditional `rename` before the main one, while the field still has its original name.

After the renames, add any cleanup the values need:

* **Floating-point values.** OpenSearch rejects `NaN` and infinity in a `float` field, and the whole document fails to index. If a parser can log those, remove them with a `ruby` filter.
* **Units.** If a field's units vary between rows, convert them here. For example, epoch timestamps over `10000000000` can only be milliseconds.
* **Software.** If the protocol identifies vendors or products, copy them into `zeek.software.name`, `software_type` and `unparsed_version`.
* **Protocol labeling.** If you decided some rows should get a different `network.protocol`, change it here. By this point, `network.protocol` may be an array.

Wrap filters that only apply to some rows in a conditional, so Logstash doesn't run them for every event.

### <a name="ZeekParserNormalize"></a>ECS fields: `1300_zeek_normalize.conf`

`1300_zeek_normalize.conf` has sections for `network.protocol_version`, `event.action` and `event.result`, each listing the logs alphabetically. Add the parser's fields to each section that applies, following the existing patterns:

```
  if ([zeek][foo][operation])                 { mutate { id => "mutate_merge_normalize_zeek_foo_operation"
                                                        merge => { "[event][action]" => "[zeek][foo][operation]" } } }
```

For coded values, translate them to names with an inline dictionary, with the raw value as the fallback:

```
  if ([zeek][foo][error_code]) {
    translate {
      id => "translate_zeek_foo_error_code"
      source => "[zeek][foo][error_code]"
      target => "[@metadata][zeek_foo_error_code]"
      dictionary => {
        "0" => "Success"
        "1" => "Access denied"
      }
      fallback => "%{[zeek][foo][error_code]}"
    }
    mutate { id => "mutate_merge_zeek_foo_error_code"
             merge => { "[event][result]" => "[@metadata][zeek_foo_error_code]" } }
  }
```

When a value combines an action with a stage, derive the base action (e.g., with a small `ruby` filter) and merge that into `event.action`, leaving the original field as it is.

### <a name="ZeekParserConvert"></a>Timestamps: `1400_zeek_convert.conf`

Zeek writes timestamps as epoch seconds. For any timestamp field other than `ts`, add its final field name (after renames) to the `@zeek_time_fields` list in `1400_zeek_convert.conf`. The generated boilerplate lists the `time` fields it found. Fields stored as integer epoch seconds need the same treatment, but the generator can't detect those, so look for them in the parser's documentation and code.

Each of these fields needs a `date` mapping in the template and `kind:termfield` in Arkime. The converter drops values of 0 or less, and values greater than `10000000000`, as invalid, so make sure the values really are seconds by the time they reach this stage.

### <a name="ZeekParserFingerprint"></a>Document IDs: `2000_fingerprint.conf`

Each document's ID is a hash of some of its fields, computed in `2000_fingerprint.conf`. Because the hash only uses fields derived from the traffic, reprocessing the same capture produces the same IDs and overwrites the existing documents instead of duplicating them (see [cisagov/Malcolm#715](https://github.com/cisagov/Malcolm/issues/715)). The catch is that two different rows with the same values in those fields also get the same ID, and the later one silently replaces the earlier one.

Logs without a branch of their own use the default fingerprint, which hashes the timestamp, the connection's addresses and ports, `event.action`, `event.result` and a few other fields. That's enough for logs that write one row per connection or transaction. A parser needs its own branch if it can write several rows that share those values, for example:

* one row per protocol layer for the same packet
* one row per result or item in a single message
* separate rows for the request and response of the same exchange, which share the connection's addresses and ports
* rows written within the same millisecond, since `[zeek][ts]` only has millisecond precision by the time the fingerprint is computed

To build a branch, start from the base fields every Zeek branch uses, then add the fields that identify a row in that log:

```
  } else if ([event][dataset] == "foo_detail") {
    fingerprint {
      id => "fingerprint_zeek_foo_detail"
      source => [ "[event][provider]",
                  "[event][dataset]",
                  "[zeek][ts]",
                  "[source][ip]",
                  "[source][port]",
                  "[destination][ip]",
                  "[destination][port]",
                  "[event][action]",
                  "[event][result]",
                  "[network][is_orig]",
                  "[zeek][foo][request_id]",
                  "[zeek][foo_detail][item_index]" ]
      concatenate_sources => true
      # uses event.hash
      ecs_compatibility => "v8"
      method => "MURMUR3_128"
      base64encode => true
    }
```

* **Use only fields derived from the traffic.** Zeek's `uid` and `fuid` are random on every run, so including them breaks reprocessing. Fields that come from the packets, positions within a message and the parser's state labels are all fine.
* **Prefer structural fields over values.** A request ID separates concurrent requests, and an index separates the items in one message by definition. Those are better keys than a list of value fields, which only happens to work on your test data.
* **Include `[network][is_orig]`** if the parser writes both request and response rows. The connection's addresses and ports don't change with direction.
* **Add branches in alphabetical order**, one per log, keeping the shared namespace fields first and each group in alphabetical order.

You can check whether a branch is needed, and whether a candidate list of fields is enough, before indexing anything. Count the distinct rows in the raw Zeek logs while ignoring the `uid` column, and compare that with the number of distinct combinations of your fingerprint fields. If the second number is smaller, some rows will collide. [Test and verify](#ZeekParserTest) shows how to confirm it after indexing.

## <a name="ZeekParserFields"></a>7. Field definitions

Every field needs a definition in three places for Malcolm to index it correctly and show it in Arkime. [Adding new log fields](contributing-new-log-fields.md#NewFields) describes each file in detail. For a Zeek parser:

* **OpenSearch template.** Zeek fields for OT/ICS parsers go in [`zeek_ot.json`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/dashboards/templates/composable/component/zeek_ot.json); other Zeek fields go in [`zeek.json`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/dashboards/templates/composable/component/zeek.json). Add each log under `zeek` in alphabetical order. Apply your plan: fields that moved to the shared namespace are defined once under `zeek.foo`, and removed from the other logs.
* **Arkime.** Add the field definitions and session views to [`arkime/etc/config.ini`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/arkime/etc/config.ini). Define the shared fields once, under the main log. In each child log's view, list the shared fields first, then the log's own fields.
* **WISE.** Add every field name to the `allFields` array in [`arkime/wise/source.zeeklogs.js`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/arkime/wise/source.zeeklogs.js), in sorted order.

All three must list the same fields. A quick script that extracts the field names from each file and compares the sets catches typos and missed renames before you test.

## <a name="ZeekParserDocs"></a>8. Documentation

* Add a row for the protocol to the table in [`docs/protocols.md`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/docs/protocols.md), with links to a description of the protocol, its specification (a freely available one, if there is one, alongside the official standard) and the Zeek package.
* Describe the new environment variables in [`docs/malcolm-config.md`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/docs/malcolm-config.md).
* If the package has known limitations, such as slow startup with ZAM, document them with the relevant setting.

## <a name="ZeekParserTest"></a>9. Test and verify

Process your test captures through Malcolm, then compare what was indexed against the Zeek logs you kept from [Before you start](#ZeekParserBefore).

### Processing captures

Upload each capture separately. Combining captures into one file with `mergecap` is convenient, but synthetic test traces often reuse the same addresses, ports and timestamps, and merging them makes Zeek treat several traces as one connection. If you do merge captures:

* check every file's link type first (`capinfos -E`). `libpcap` can't read a `pcapng` file whose interfaces have different link types, so files with an unusual link type have to be processed on their own.
* check for reused connections (`tshark -q -z conv,tcp`) and give each trace its own ports and time offset before merging (e.g., with `tcprewrite --portmap` and `editcap -t`)
* after merging, check the packet count, the number of connections and the checksums against the inputs

### Logstash

The Logstash node stats show how many events went through each of the parser's filters, and how long each took:

```bash
docker compose exec logstash curl -sSL -XGET http://localhost:9600/_node/stats/pipelines | \
  jq -r '.. | .filters? // empty | .[] | objects | select (.events.in > 0) | [.id, .events.in, .events.out, .events.duration_in_millis] | join (";")' | \
  sort -n -t ';' -k4 | grep foo
```

Check that:

* the parse filter for each log saw the expected number of lines (the fallback `mutate_split` and `ruby_zip` filters only show up if a line failed to dissect)
* every normalization filter you wrote ran at least once. A filter that never appears either has nothing to act on in your captures or has a condition that doesn't match. Find out which.

### OpenSearch

Run these in OpenSearch Dashboards' Dev Tools. `arkime_sessions3-*` is Malcolm's default network index pattern.

**Document counts.** Compare these with the number of distinct rows in the raw logs, ignoring `uid` (rows that differ only in `uid` get the same ID, which is intended). A shortfall usually means a fingerprint collision:

```
GET arkime_sessions3-*/_search
{"size":0,"track_total_hits":true,"query":{"prefix":{"event.dataset":"foo"}},
 "aggs":{"dataset":{"terms":{"field":"event.dataset","size":20}},
         "failures":{"filter":{"bool":{"should":[{"prefix":{"tags":"_rubyexception"}},{"prefix":{"tags":"_dissect"}},{"prefix":{"tags":"_dateparse"}}]}}}}}
```

`failures` should be 0. For TSV logs, the distinct row count is `grep -v '^#' foo.log | cut -f1,3- | sort -u | wc -l`, which drops the second column (`uid`).

**Unexpected fields.** Every field should come from the template. Anything else was mapped dynamically, which usually means a missed rename:

```
GET arkime_sessions3-*/_field_caps?fields=zeek.foo*
```

**ECS values.** Look at what actually landed in the ECS fields, and adjust [the normalization](#ZeekParserNormalize) if the values don't make sense:

```
GET arkime_sessions3-*/_search
{"size":0,"query":{"prefix":{"event.dataset":"foo"}},
 "aggs":{"action":{"terms":{"field":"event.action","size":50}},
         "result":{"terms":{"field":"event.result","size":50}},
         "proto":{"terms":{"field":"network.protocol","size":10}},
         "version":{"terms":{"field":"network.protocol_version","size":10}},
         "category":{"terms":{"field":"event.category","size":10}}}}
```

**Dates.** Use `min` and `max` aggregations on each date field. Dates in 1970, or far in the future, mean the units are wrong.

**Stable IDs.** Reprocess the same captures without deleting anything. The document counts shouldn't change.

If you change a fingerprint and reprocess, delete the parser's existing documents first (e.g., `POST arkime_sessions3-*/_delete_by_query` with the same `prefix` query). Otherwise the documents indexed under the old IDs stay, and everything is counted twice.

### Arkime and behavior checks

* Open a session from each log in Arkime and check that its view shows the expected fields.
* Set the disable variable to `true`, process a capture and check that no logs come out.
* If the parser's default port is shared with another protocol, process a capture of the other protocol and check that the parser doesn't write logs for it.
* If you have JSON-format Zeek logs, process one capture that way too. The TSV and JSON paths parse differently.

### System tests

Malcolm's system tests run against real captures, and new parsers should be added to them:

1. Submit a pull request to [Malcolm-Test-Artifacts](https://github.com/idaholab/Malcolm-Test-Artifacts) adding a capture under `pcap/protocols/`, ideally one capture per protocol (e.g., `pcap/protocols/FOO.pcap`).
2. Submit a pull request to [Malcolm-Test](https://github.com/idaholab/Malcolm-Test) adding the capture's path to `UPLOAD_ARTIFACTS` and the parser's datasets to `EXPECTED_DATASETS`, in `src/maltest/tests/test_ot_protocols.py` for OT/ICS protocols or `src/maltest/tests/test_common_protocols.py` for others.

See [`malcolm-test`: Malcolm System Tests](contributing-malcolm-test.md#MalcolmTest) for how to run them.

## <a name="ZeekParserDashboards"></a>10. Dashboards

Build a dashboard for the protocol, export it into `dashboards/dashboards/` as described in [Adding new visualizations and dashboards](contributing-dashboards.md#DashboardsNewViz), and add a link to it in the [navigation pane](contributing-dashboards.md#DashboardsNavigation) shared by all dashboards ([`dashboards/dashboards/navigation.md`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/dashboards/dashboards/navigation.md)). Protocol dashboards go on the **ICS/IoT Protocols** or **Common Protocols** line, in alphabetical order, separated by `   ●   `:

```
[Foo](#/dashboard/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
```

## <a name="ZeekParserUpstream"></a>11. Report problems upstream

Integrating a parser often turns up problems in the package itself: documentation that doesn't match the code, fields whose units vary between rows, one field carrying unrelated values, or very slow startup under ZAM. Report them to the package's maintainers with the evidence (the code location, the log rows and the captures that show it). If Malcolm needs a workaround in the meantime, add a comment next to it linking to the upstream issue, so it can be removed once the package is fixed.

## <a name="ZeekParserChecklist"></a>Checklist

* Zeek
    - [ ] `zeek/zeek-packages.list` entry, and `zeek/zeek-packages.lock` regenerated with `update_pins.py --zeek-packages --apply`
    - [ ] `zeek/config/local.zeek`: disable variable, and port variable if the package supports it
    - [ ] `config/zeek.env.example`: the new variables
    - [ ] ZAM startup checked with `scripts/zeek-zam-bench.sh`
* Logstash
    - [ ] `logstash/pipelines/zeek/10xx_zeek_foo.conf`: parse filters with unique plugin IDs
    - [ ] `logstash/maps/zeek_log_ecs_categories.yaml` and `zeek_log_transport.yaml`: every log
    - [ ] `logstash/maps/service_ports.yaml`: the service's ports
    - [ ] `logstash/pipelines/enrichment/20_enriched_to_ecs.conf`: OT protocol values, if OT
    - [ ] `logstash/pipelines/zeek/1200_zeek_mutate.conf`: shared-field renames and value cleanup
    - [ ] `logstash/pipelines/zeek/1300_zeek_normalize.conf`: version, action and result
    - [ ] `logstash/pipelines/zeek/1400_zeek_convert.conf`: timestamp fields
    - [ ] `logstash/pipelines/zeek/2000_fingerprint.conf`: a branch per log, if needed
* Field definitions
    - [ ] `dashboards/templates/composable/component/zeek_ot.json` or `zeek.json`
    - [ ] `arkime/etc/config.ini`: field definitions and views
    - [ ] `arkime/wise/source.zeeklogs.js`: field names
* Documentation
    - [ ] `docs/protocols.md`
    - [ ] `docs/malcolm-config.md`
* Testing
    - [ ] counts, failures, fields, ECS values and dates checked in OpenSearch
    - [ ] disable variable and port overlaps checked
    - [ ] pull requests to Malcolm-Test-Artifacts and Malcolm-Test
* Dashboards
    - [ ] dashboard exported to `dashboards/dashboards/`
    - [ ] link in `dashboards/dashboards/navigation.md`
* After the release
    - [ ] new environment variables in the [Malcolm Helm chart](https://github.com/idaholab/Malcolm-Helm)
