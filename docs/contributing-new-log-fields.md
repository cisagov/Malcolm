# <a name="NewFields"></a>Adding new log fields

As several of the sections in this document will reference adding new data source fields, we'll cover that here at the beginning.

Although OpenSearch is a NoSQL database and as-such is "unstructured" and "schemaless," in order to add a new data source field you'll need to define that field in a few places in order for it to show up and be usable throughout Malcolm. Minimally, you'll probably want to do it in these three files

* [`arkime/etc/config.ini`](../arkime/etc/config.ini) - follow existing examples in the `[custom-fields]` and `[custom-views]` sections in order for [Arkime](https://arkime.com) to be aware of your new fields
* [`arkime/wise/source.zeeklogs.js`](../arkime/wise/source.zeeklogs.js) - add new fields to the `allFields` array for Malcolm to create Arkime [value actions](https://arkime.com/settings#right-click) for your fields
* [`dashboards/templates/composable/component/__(name)__.json`](../dashboards/templates/composable/component/) - add new fields to a new [composable index template](https://opensearch.org/docs/latest/opensearch/index-templates/#composable-index-templates) file in this directory and add its name (prefixed with `custom_`) to the `composed_of` section of [`dashboards/templates/malcolm_template.json`](../dashboards/templates/malcolm_template.json) in order for it to be included as part of the `arkime_sessions3-*` [index template](https://opensearch.org/docs/latest/opensearch/index-templates/) used by Arkime and OpenSearch Dashboards in Malcolm

When possible, I recommend you to use (or at least take inspiration from) the [Elastic Common Schema (ECS) Reference](https://www.elastic.co/guide/en/ecs/current/index.html) when deciding how to define new field names.