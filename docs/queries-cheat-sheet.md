# <a name="SearchSyntax"></a> Search Queries in Arkime and OpenSearch Dashboards

* [Query Syntax Comparison](#SearchCheatSheet)
* [Arkime Query Syntax](#ArkimeQueries)
* [OpenSearch Dashboards Query Syntax](#DashboardsQueries)
    * [Dashboards Query Language (DQL)](#DashboardsQueriesDQL)
    * [Apache Lucene Query Parser Syntax](#DashboardsQueriesLucene)
    * [SQL and PPL](#DashboardsSQLandPPL)

OpenSearch Dashboards supports two query syntaxes: the legacy [Lucene](#DashboardsQueriesLucene) syntax and [Dashboards Query Language (DQL)](#DashboardsQueriesDQL), both of which are somewhat different than [Arkime's query syntax](#ArkimeQueries). The Arkime interface is for searching and visualizing Arkime sessions, Zeek logs, and Suricata alerts. The prebuilt dashboards in the OpenSearch Dashboards interface are for searching and visualizing Zeek logs and Suricata alerts, but will not include Arkime sessions.

## <a name="SearchCheatSheet"></a>Query Syntax Comparison

Here are some common patterns used in building search query strings for Arkime and OpenSearch Dashboards, respectively. See the links provided for further documentation.

| | [Arkime Search String](#ArkimeQueries) | [OpenSearch Dashboards Search String (Lucene)](#DashboardsQueriesLucene) | [OpenSearch Dashboards Search String (DQL)](#DashboardsQueriesDQL)|
|---|:---:|:---:|:---:|
| Field exists |`event.dataset == EXISTS!`|`_exists_:event.dataset`|`event.dataset:*`|
| Field does not exist |`event.dataset != EXISTS!`|`NOT _exists_:event.dataset`|`NOT event.dataset:*`|
| Field matches a value |`port.dst == 22`|`destination.port:22`|`destination.port:22`|
| Field does not match a value |`port.dst != 22`|`NOT destination.port:22`|`NOT destination.port:22`|
| Field matches at least one of a list of values |`tags == [foo, bar]`|`tags:(foo OR bar)`|`tags:(foo or bar)`|
| Field range (inclusive) |`http.statuscode >= 200 && http.statuscode <= 300`|`http.statuscode:[200 TO 300]`|`http.statuscode >= 200 and http.statuscode <= 300`|
| Field range (exclusive) |`http.statuscode > 200 && http.statuscode < 300`|`http.statuscode:{200 TO 300}`|`http.statuscode > 200 and http.statuscode < 300`|
| Field range (mixed exclusivity) |`http.statuscode >= 200 && http.statuscode < 300`|`http.statuscode:[200 TO 300}`|`http.statuscode >= 200 and http.statuscode < 300`|
| Match all search terms (AND) |`(tags == [foo, bar]) && (http.statuscode == 401)`|`tags:(foo OR bar) AND http.statuscode:401`|`tags:(foo or bar) and http.statuscode:401`|
| Match any search terms (OR) |`(zeek.ftp.password == EXISTS!) || (zeek.http.password == EXISTS!) || (related.user == "anonymous")`|`_exists_:zeek.ftp.password OR _exists_:zeek.http.password OR related.user:"anonymous"`|`zeek.ftp.password:* or zeek.http.password:* or related.user:"anonymous"`|
| Global string search (anywhere in the document) |all Arkime search expressions are field-based|`microsoft`|`microsoft`|
| Wildcards|`host.dns == "*micro?oft*"` (`?` for single character, `*` for any characters)|`dns.host:*micro?oft*` (`?` for single character, `*` for any characters)|`dns.host:*micro*ft*` (`*` for any characters)|
| Regex |`host.http == /.*www\.f.*k\.com.*/`|`zeek.http.host:/.*www\.f.*k\.com.*/`|DQL does not support regex|
| IPv4 values |`ip == 0.0.0.0/0`|`source.ip:"0.0.0.0/0" OR destination.ip:"0.0.0.0/0"`|`source.ip:"0.0.0.0/0" OR destination.ip:"0.0.0.0/0"`|
| IPv6 values |`(ip.src == EXISTS! || ip.dst == EXISTS!) && (ip != 0.0.0.0/0)`|`(_exists_:source.ip AND NOT source.ip:"0.0.0.0/0") OR (_exists_:destination.ip AND NOT destination.ip:"0.0.0.0/0")`|`(source.ip:* and not source.ip:"0.0.0.0/0") or (destination.ip:* and not destination.ip:"0.0.0.0/0")`|
| GeoIP information available |`country == EXISTS!`|`_exists_:destination.geo OR _exists_:source.geo`|`destination.geo:* or source.geo:*`|
| Zeek log type |`event.dataset == notice`|`event.dataset:notice`|`event.dataset:notice`|
| IP CIDR Subnets |`ip.src == 172.16.0.0/12`|`source.ip:"172.16.0.0/12"`|`source.ip:"172.16.0.0/12"`|
| Search time frame |Use Arkime time bounding controls under the search bar|Use OpenSearch Dashboards time range controls in the upper right-hand corner|Use OpenSearch Dashboards time range controls in the upper right-hand corner|

When building complex queries, users are strongly recommended to enclose search terms and expressions in parentheses to control order of operations.

As Zeek logs are ingested, Malcolm parses and normalizes the logs' fields to match Arkime's underlying OpenSearch schema. A complete list of these fields can be found in the Arkime help (accessible at **https://localhost/arkime/help#fields** if connecting locally).

Whenever possible, Zeek fields are mapped to existing corresponding Arkime fields: for example, the `orig_h` field in Zeek is mapped to Arkime's `source.ip` field. The original Zeek fields are also left intact. To complicate the issue, the Arkime interface uses its own aliases to reference those fields: the source IP field is referenced as `ip.src` (Arkime's alias) in Arkime and `source.ip` or `source.ip` in OpenSearch Dashboards.

The table below shows the mapping of some of these fields.

| Field Description |Arkime Field Alias(es)|Arkime-mapped Zeek Field(s)|Zeek Field(s)|
|---|:---:|:---:|:---:|
| [Community ID](https://github.com/corelight/community-id-spec) Flow Hash ||`network.community_id`|`network.community_id`|
| Destination IP |`ip.dst`|`destination.ip`|`destination.ip`|
| Destination MAC |`mac.dst`|`destination.mac`|`destination.mac`|
| Destination Port |`port.dst`|`destination.port`|`destination.port`|
| Duration |`session.length`|`length`|`zeek.conn.duration`|
| First Packet Time |`starttime`|`firstPacket`|`zeek.ts`, `@timestamp`|
| IP Protocol |`ip.protocol`|`ipProtocol`|`network.transport`|
| Last Packet Time |`stoptime`|`lastPacket`||
| MIME Type |`email.bodymagic`, `http.bodymagic`|`http.bodyMagic`|`file.mime_type`, `zeek.files.mime_type`, `zeek.ftp.mime_type`, `zeek.http.orig_mime_types`, `zeek.http.resp_mime_types`, `zeek.irc.dcc_mime_type`|
| Protocol/Service |`protocols`|`protocol`|`network.transport`, `network.protocol`|
| Request Bytes |`databytes.src`, `bytes.src`|`source.bytes`, `client.bytes`|`zeek.conn.orig_bytes`, `zeek.conn.orig_ip_bytes`|
| Request Packets |`packets.src`|`source.packets`|`zeek.conn.orig_pkts`|
| Response Bytes |`databytes.dst`, `bytes.dst`|`destination.bytes`, `server.bytes`|`zeek.conn.resp_bytes`, `zeek.conn.resp_ip_bytes`|
| Response Packets |`packets.dst`|`destination.packets`|`zeek.con.resp_pkts`|
| Source IP |`ip.src`|`source.ip`|`source.ip`|
| Source MAC |`mac.src`|`source.mac`|`source.mac`|
| Source Port |`port.src`|`source.port`|`source.port`|
| Total Bytes |`databytes`, `bytes`|`totDataBytes`, `network.bytes`||
| Total Packets |`packets`|`network.packets`||
| Username |`user`|`user`|`related.user`|
| Zeek Connection UID|||`zeek.uid`, `event.id`|
| Zeek File UID |||`zeek.fuid`, `event.id`|
| Zeek Log Type |||`event.dataset`|

In addition to the fields listed above, Arkime provides several special field aliases for matching any field of a particular type. While these aliases do not exist in OpenSearch Dashboards *per se*, they can be approximated as illustrated below.

| Matches Any | Arkime Special Field Example | OpenSearch Dashboards/Zeek Equivalent Example |
|---|:---:|:---:|
| IP Address | `ip == 192.168.0.1` | `source.ip:192.168.0.1 OR destination.ip:192.168.0.1` |
| Port | `port == [80, 443, 8080, 8443]` | `source.port:(80 OR 443 OR 8080 OR 8443) OR destination.port:(80 OR 443 OR 8080 OR 8443)` |
| Country (code) | `country == [RU,CN]` | `destination.geo.country_code2:(RU OR CN) OR source.geo.country_code2:(RU OR CN) OR dns.GEO:(RU OR CN)` |
| Country (name) | | `destination.geo.country_name:(Russia OR China) OR source.geo.country_name:(Russia OR China)` |
| ASN | `asn == "*Mozilla*"` | `source.as.full:*Mozilla* OR destination.as.full:*Mozilla* OR dns.ASN:*Mozilla*` |
| Host | `host == www.microsoft.com` | `zeek.http.host:www.microsoft.com (or zeek.dhcp.host_name, zeek.dns.host, zeek.ntlm.host, smb.host, etc.)` |
| Protocol (layers >= 4) | `protocols == tls` | `protocol:tls` |
| User | `user == EXISTS! && user != anonymous` | `_exists_:user AND (NOT user:anonymous)` |

For details on how to filter both Zeek logs and Arkime session records for a particular connection, see [Correlating Zeek logs and Arkime sessions](arkime.md#ZeekArkimeFlowCorrelation).

## <a name="ArkimeQueries"></a>Arkime Query Syntax

A more in-depth guide to Arkime query syntax can be found in the Arkime help at **https://localhost/arkime/help#search** if connecting locally. Users may also peruse the [source code](https://github.com/arkime/arkime/blob/main/viewer/vueapp/src/components/help/Help.vue) used to generate that help page.

## <a name="DashboardsQueries"></a>OpenSearch Dashboards Query Syntax

Dashboards Query Language (DQL) and query string language (Lucene) are the two search bar language options in OpenSeach Dashboards. For a comparison between these two query languages, see the [DQL and query string query quick reference](https://docs.opensearch.org/latest/dashboards/dql/#dql-and-query-string-query-quick-reference) in the OpenSearch documentation.

### <a name="DashboardsQueriesDQL"></a>Dashboards Query Language (DQL)

DQL is the syntax OpenSearch Dashboards uses by default. See the [Dashboards Query Language (DQL)](https://docs.opensearch.org/latest/dashboards/dql/) page in the OpenSearch documentation for a discussion on the features of this language, or the [source code](https://github.com/opensearch-project/documentation-website/blob/main/_dashboards/dql.md) from which that documentation is generated.

### <a name="DashboardsQueriesLucene"></a>Apache Lucene Query Parser Syntax

OpenSearch Dashboards uses Apache Lucene query syntax to perform `query_string` queries, which "provides for creating powerful yet concise queries that can incorporate wildcards and search multiple fields."

For a full treatment of query string (Lucene) syntax, please refer to the following documents. The source code from which these documents are generated are also included for reference.

* [Query string syntax](https://docs.opensearch.org/latest/query-dsl/full-text/query-string/#query-string-syntax) in the OpenSearch documentation ([source code](https://github.com/opensearch-project/documentation-website/blob/main/_query-dsl/full-text/query-string.md))
* [Apache Lucene query syntax](https://lucene.apache.org/core/10_4_0/queryparser/org/apache/lucene/queryparser/classic/package-summary.html#query-parser-syntax-heading) ([source code](https://github.com/apache/lucene/blob/main/lucene/queryparser/src/java/org/apache/lucene/queryparser/classic/package-info.java))

### <a name="DashboardsSQLandPPL"></a>SQL and PPL

OpenSearch provides two powerful query languages that offer alternatives to DQL and Lucene: [Structured Query Language (SQL) and Piped Processing Language (PPL)](https://docs.opensearch.org/latest/sql-and-ppl/).

The OpenSearch Dashboards [Query Workbench](https://docs.opensearch.org/latest/dashboards/query-workbench/) tool can be used to run on-demand SQL and PPL queries.

* [Using SQL within OpenSearch](https://docs.opensearch.org/latest/sql-and-ppl/sql/index/)
  [SQL functions](https://docs.opensearch.org/latest/sql-and-ppl/sql/functions/)
* [Using PPL within OpenSearch](https://docs.opensearch.org/latest/sql-and-ppl/ppl/index/)
  * [PPL commands](https://docs.opensearch.org/latest/sql-and-ppl/ppl/commands/index/)
  * [PPL syntax](https://docs.opensearch.org/latest/sql-and-ppl/ppl/commands/syntax/)