# <a name="NewFields"></a>Adding new log fields

Although OpenSearch is a NoSQL database and as-such is "unstructured" and "schemaless," adding a new data source field requires it be defined in several places in order for it to show up and be usable throughout Malcolm. Minimally, this involves three files:

* [`arkime/etc/config.ini`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/arkime/etc/config.ini) - follow existing examples in the `[custom-fields]` and `[custom-views]` sections in order for [Arkime](https://arkime.com) to be aware of the new fields
* [`arkime/wise/source.zeeklogs.js`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/arkime/wise/source.zeeklogs.js) - add new fields to the `allFields` array for Malcolm to create Arkime [value actions](https://arkime.com/settings#right-click) for the fields
* [`dashboards/templates/composable/component/__(name)__.json`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/dashboards/templates/composable/component/) - add new fields to a new [composable index template](https://opensearch.org/docs/latest/opensearch/index-templates/#composable-index-templates) file in this directory and add its name (prefixed with `custom_`) to the `composed_of` section of [`dashboards/templates/malcolm_template.json`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/dashboards/templates/malcolm_template.json) in order for it to be included as part of the `arkime_sessions3-*` [index template](https://opensearch.org/docs/latest/opensearch/index-templates/) used by Arkime and OpenSearch Dashboards in Malcolm

When possible, it is recommended to use (or at least take inspiration from) the [Elastic Common Schema (ECS) Reference](https://www.elastic.co/guide/en/ecs/current/index.html) when deciding how to define new field names.

If new log fields are coming from a Zeek script where they are defined in a [`record`](https://docs.zeek.org/en/master/script-reference/types.html#type-record) as `&log` fields, the script [`scripts/zeek_script_to_malcolm_boilerplate.py`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/scripts/zeek_script_to_malcolm_boilerplate.py) may help by autogenerating the parts of the files mentioned above.
## Canonical user-agent fields

Zeek HTTP, GQUIC, SIP, SMTP and WebSocket user-agent values are stored in `user_agent.original`. Their original `zeek.<protocol>.user_agent` fields are removed after normalization. Required Arkime-specific fields (`http.useragent`, `quic.useragent` and `email.useragent`) are retained. An existing ECS value is preserved and combined with the incoming value instead of being overwritten.

Use `user_agent.original` in new searches, visualizations and custom rules. For a protocol-specific query, also restrict the provider and dataset, for example `event.provider:zeek AND event.dataset:http`. The five removed field names are `zeek.gquic.user_agent`, `zeek.http.user_agent`, `zeek.sip.user_agent`, `zeek.smtp.user_agent` and `zeek.websocket.user_agent`.

This change affects newly ingested documents. Existing documents and index mappings are not rewritten. Earlier Malcolm normalization already populated `user_agent.original`, so that field is the common search path for those older documents and newly ingested documents. Update custom queries that refer to the removed names or their `.text` subfields. The bundled Arkime session views use the canonical field; the removed fields are no longer registered as separate WISE fields or mapped in new Zeek index templates.

This migration covers user-agent fields only. Other Zeek-to-ECS mappings are tracked in [issue #388](https://github.com/cisagov/Malcolm/issues/388).
