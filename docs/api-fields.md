# Fields

`GET` - /mapi/fields

Returns the (very long) list of fields known to Malcolm, comprised of data from Arkime's [`fields` table](https://arkime.com/apiv3#fields-api), the Malcolm [OpenSearch template]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/dashboards/templates/malcolm_template.json) and the OpenSearch Dashboards index pattern API.

**Example output:**

```json
{
    "fields": {
        "@timestamp": {
            "type": "date"
        },
…
        "zeek.x509.san_uri": {
            "description": "Subject Alternative Name URI",
            "type": "string"
        },
        "zeek.x509.san_uri.text": {
            "type": "string"
        }
    },
    "total": 2005
}
```
