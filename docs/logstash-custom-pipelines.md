# Custom Logstash filters and lookup files

Malcolm can stage administrator-supplied Logstash files from a read-only bind mount at `/usr/share/logstash/malcolm-pipelines.available`. Each immediate subdirectory names a pipeline. Its files are overlaid on the matching runtime directory under `/usr/share/logstash/malcolm-pipelines` before Logstash starts.

Nested lookup tables, Ruby scripts, and other regular files are copied along with the filters. Existing bundled files are retained unless a custom file has the same relative name. Only top-level `*.conf` files are loaded as pipeline configuration, so YAML dictionaries and other assets are not parsed as Logstash configuration.

## Directory layout

For an additional site-specific enrichment, create the following files under the Malcolm directory:

```text
custom-pipelines/
  enrichment/
    25_site_asset_name.conf
    lookups/
      asset_names.yaml
```

The example below assumes your input records already contain a custom `site.asset_reference` field. Replace that source field with the actual field used in your deployment:

```conf
filter {
  if [site][asset_reference] {
    translate {
      id => "site_asset_name_lookup"
      source => "[site][asset_reference]"
      target => "[labels][asset_name]"
      dictionary_path => "/usr/share/logstash/malcolm-pipelines/enrichment/lookups/asset_names.yaml"
      exact => true
    }
  }
}
```

The `lookups/asset_names.yaml` file contains your site's reference-to-name mapping:

```yaml
"IED1/LLN0$ST$Beh$stVal": "Bay 1 protection relay status"
```

Use a unique filter `id`, and choose the `.conf` filename to run at the desired position in the pipeline's alphabetical ordering. Pipeline directory names may contain letters, digits, underscores, periods, and hyphens, and must start with a letter or digit. Symlinks are not staged or followed.

## Bind mount

Add this bind mount to your existing Compose override for the `logstash` service, using the same Compose files and project name as your normal deployment:

```yaml
services:
  logstash:
    volumes:
      - type: bind
        source: ./custom-pipelines
        target: /usr/share/logstash/malcolm-pipelines.available
        read_only: true
        bind:
          create_host_path: false
```

Create the source files before starting the service, and make them readable by the configured container user. The runtime copies are owner-writable for Malcolm's startup transformations; the source bind mount remains unchanged.

Recreate the Logstash container after adding or removing files. Staging is additive and does not delete bundled runtime files, so a simple process restart can retain an old custom file that has been removed from the bind mount. Read-only lookup sources are copied at startup; editing a source dictionary does not automatically update the runtime copy.

## New pipelines

A new subdirectory can also provide a complete pipeline, including its input and output `.conf` files. Adding a new data source still requires the input tags and routing described in [Parsing a new log data source](contributing-logstash.md#LogstashNewSource). This staging mechanism does not infer routing or install additional Logstash gems.

Only mount trusted, administrator-controlled filters and scripts. They execute inside the Logstash process with its permissions. This facility supports local customization and does not provide isolation for untrusted plugins.
