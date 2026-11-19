# <a name="NewFields"></a>Adding new log fields

Although OpenSearch is a NoSQL database and as-such is "unstructured" and "schemaless," adding a new data source field requires it be defined in several places in order for it to show up and be usable throughout Malcolm. Minimally, this involves three files:

* an OpenSearch [composable index template](https://opensearch.org/docs/latest/opensearch/index-templates/#composable-index-templates) component in [`dashboards/templates/composable/component/`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/dashboards/templates/composable/component/), which defines the field's type
* [`arkime/etc/config.ini`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/arkime/etc/config.ini), which makes [Arkime](https://arkime.com) aware of the field and how to show it
* [`arkime/wise/source.zeeklogs.js`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/arkime/wise/source.zeeklogs.js), where adding the field to the `allFields` array creates Arkime [value actions](https://arkime.com/settings#right-click) for it

All three must list the same fields. When possible, it is recommended to use (or at least take inspiration from) the [Elastic Common Schema (ECS) Reference](https://www.elastic.co/guide/en/ecs/current/index.html) when deciding how to define new field names.

If new log fields are coming from a Zeek script where they are defined in a [`record`](https://docs.zeek.org/en/master/script-reference/types.html#type-record) as `&log` fields, the script [`scripts/zeek_script_to_malcolm_boilerplate.py`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/scripts/zeek_script_to_malcolm_boilerplate.py) generates the parts of all three files. See [Adding a new Zeek parser](contributing-zeek-parser.md#ZeekParser) for the whole process.

## <a name="NewFieldsTemplate"></a>OpenSearch index templates

Each file in [`dashboards/templates/composable/component/`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/dashboards/templates/composable/component/) is imported as a component template named `custom_<filename>` (by [`dashboards/scripts/shared-object-creation.sh`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/dashboards/scripts/shared-object-creation.sh)). The index templates list the components they're built from in `composed_of`:

* [`malcolm_template.json`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/dashboards/templates/malcolm_template.json) is used for network traffic metadata, the `arkime_sessions3-*` indices that Arkime and OpenSearch Dashboards use
* [`malcolm_beats_template.json`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/dashboards/templates/malcolm_beats_template.json) is used for other logs, such as host and system logs

Add fields to the component that matches their source:

* Zeek fields for OT/ICS protocols go in `zeek_ot.json`
* other Zeek fields go in `zeek.json`
* fields from an existing data source go in its component (e.g., `suricata.json`)

A new component file is only needed for a new data source. When you add one, also add `custom_<filename>` to `composed_of` in the index template that should use it.

Within a component, fields are nested under `template.mappings.properties`, e.g., `zeek.foo.request_id` is under `zeek`, then `foo`, then `request_id`. Keep each level in alphabetical order. The types used are `keyword` for strings, `long` or `integer` for integers, `float` for floating-point values and `date` for timestamps. A `long` is the safe choice for Zeek's `int` and `count`, which are both 64-bit: if a value doesn't fit a field's mapping, OpenSearch rejects the whole document, not just that field. Fields mapped as `date` must contain dates when they're indexed (see [`1400_zeek_convert.conf`](contributing-zeek-parser.md#ZeekParserConvert) for Zeek logs).

The index templates limit the number of fields an index can have (`mapping.total_fields.limit`), counting the fields from every component they're composed of. Keep an eye on it when adding a large number of fields.

Malcolm compares a hash of all the template files at startup and re-imports them if anything has changed. Changed mappings only apply to indices created after the import, so test new fields in a fresh index.

## <a name="NewFieldsArkime"></a>Arkime

### Field definitions

Fields are defined in the `[custom-fields]` section of [`arkime/etc/config.ini`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/arkime/etc/config.ini), one per line:

```ini
zeek.foo.request_id=db:zeek.foo.request_id;group:zeek_foo;kind:integer;viewerOnly:true;friendly:request_id;help:request_id
```

* `db` is the field's name in OpenSearch.
* `group` decides which category the field is listed under wherever Arkime lists fields: SPI View, the column picker on the Sessions page, the search bar's autocomplete and the Fields help page. Fields from the same parser usually share one group (e.g., `zeek_foo` for all of `foo.log`, `foo_detail.log` and so on), so analysts find them together.
* `kind` is `integer` for integers and `termfield` for everything else, including dates and floating-point values.
* `friendly` and `help` are the field's display name and description.

The definitions for each log go together, under a comment naming the log.

### Session views

The `[custom-views]` section defines the sections of Arkime's session detail panel, one per log, sorted by name:

```ini
o_zeek_foo_detail=require:zeek.foo_detail;title:Zeek foo_detail.log;fields:zeek.foo.request_id,zeek.foo_detail.item_index,zeek.foo_detail.value
```

* Zeek views are named `o_zeek_<log>`.
* `require` is the field that has to exist on a session for the view to be shown.
* `title` is the view's heading.
* `fields` lists the fields the view shows, in order. If some of a log's fields were moved to a namespace shared by several logs, list those first.

Groups and views are independent: a view shows whatever fields it lists, whatever group they belong to.

## <a name="NewFieldsWISE"></a>WISE value actions

Add every field name to the `allFields` array in [`arkime/wise/source.zeeklogs.js`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/arkime/wise/source.zeeklogs.js), keeping the array in sorted order:

```js
      "zeek.foo.request_id",
      "zeek.foo_detail.item_index",
```
