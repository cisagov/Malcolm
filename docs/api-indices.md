# Indices

`GET` - /mapi/indices

Lists [information related to the underlying OpenSearch indices](https://opensearch.org/docs/latest/opensearch/rest-api/cat/cat-indices/), similar to Arkime's [esindices](https://arkime.com/apiv3#esindices-api) API.

**Example output:**

```json
{
    "malcolm_network_index_pattern": "arkime_sessions3-*",
    "malcolm_other_index_pattern": "malcolm_beats_*",
    "arkime_network_index_pattern": "arkime_sessions3-*",
    "indices": [
…
        {
            "docs.count": "2268613",
            "docs.deleted": "0",
            "health": "green",
            "index": "arkime_sessions3-210301",
            "pri": "1",
            "pri.store.size": "1.8gb",
            "rep": "0",
            "status": "open",
            "store.size": "1.8gb",
            "uuid": "w-4Q0ofBTdWO9KqeIIAAWg"
        },
…
    ]
}
```
