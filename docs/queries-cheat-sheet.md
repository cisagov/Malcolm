# <a name="SearchCheatSheet"></a>Search Queries in Arkime and OpenSearch Dashboards

OpenSearch Dashboards supports two query syntaxes: the legacy [Lucene](https://www.elastic.co/guide/en/kibana/current/lucene-query.html) syntax and [Dashboards Query Language (DQL)](https://opensearch.org/docs/1.2/dashboards/dql/), both of which are somewhat different than Arkime's query syntax (see the help at **https://localhost/help#search** if connecting locally). The Arkime interface is for searching and visualizing both Arkime sessions and Zeek logs. The prebuilt dashboards in the OpenSearch Dashboards interface are for searching and visualizing Zeek logs, but will not include Arkime sessions. Here are some common patterns used in building search query strings for Arkime and OpenSearch Dashboards, respectively. See the links provided for further documentation.

| | [Arkime Search String](https://localhost/help#search) | [OpenSearch Dashboards Search String (Lucene)](https://www.elastic.co/guide/en/kibana/current/lucene-query.html) | [OpenSearch Dashboards Search String (DQL)](https://www.elastic.co/guide/en/kibana/current/kuery-query.html)|
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

As Zeek logs are ingested, Malcolm parses and normalizes the logs' fields to match Arkime's underlying OpenSearch schema. A complete list of these fields can be found in the Arkime help (accessible at **https://localhost/help#fields** if connecting locally).

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