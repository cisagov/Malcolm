# Malcolm Dashboard Reference

> This document provides user-focused descriptions of all available dashboards and their visualizations. Use it to understand what each dashboard monitors, what data it surfaces, and how to interpret individual panels.

---

## Common Fields

The following fields are used across nearly all dashboards and are not repeated in individual dashboard field lists below.

* `destination.ip`
* `destination.port`
* `event.action`
* `event.dataset`
* `event.id`
* `event.ingested`
* `event.module`
* `event.original`
* `event.provider`
* `event.result`
* `host.name`
* `network.direction`
* `network.is_orig`
* `network.protocol`
* `network.transport`
* `network.type`
* `related.ip`
* `source.ip`
* `source.port`
* `tags`
* timestamp
* `zeek.uid`

---

## URIs for pivoting between Malcolm tools

The following URI patterns are used to pivot between Malcolm components, such as from Arkime to OpenSearch Dashboards or from OpenSearch Dashboards to NetBox, with filters or search expressions pre-applied.

The URI patterns are grouped below by destination.

See also the [Malcolm REST APIs](api.md#API).

### OpenSearch Dashboards

Use the following URI pattern to open OpenSearch Dashboards with a field/value filter and time range applied:

```text
/idark2dash/filter?<URI parameters>
```

#### URI parameters

* `start` - beginning of the search time frame, in ISO 8601 UTC format at second precision
* `stop` - end of the search time frame, in ISO 8601 UTC format at second precision
* `field` - name of the field to filter
* `value` - value of the field to filter

#### Example

```text
/idark2dash/filter?start=2026-07-13T21:19:14&stop=2026-07-15T21:19:57&field=event.provider&value=zeek
```

### Arkime

Use the following URI pattern to open Arkime with a query expression applied:

```text
/iddash2ark/<expression>
```

`<expression>` is an Arkime search expression. For a detailed guide to Arkime query syntax, see the Arkime help page at **https://localhost/arkime/help#search** when connected locally. Users may also review the [Arkime source code](https://github.com/arkime/arkime/blob/main/viewer/vueapp/src/components/help/Help.vue) used to generate that help page.

#### Example

```text
/iddash2ark/db:event.provider == "zeek"
```

### NetBox

Use the following URI pattern to open NetBox with a search or object filter applied:

```text
/netbox/<expression>
```

`<expression>` depends on the Malcolm field being pivoted from and the type of NetBox object being searched.

| Malcolm field           | NetBox URI                                                                                              |
| ----------------------- | ------------------------------------------------------------------------------------------------------- |
| `….segment.name`        | `/netbox/search/?q=<value>&obj_types=ipam.prefix&lookup=iexact`                                         |
| `….device.name`         | `/netbox/search/?q=<value>&obj_types=dcim.device&obj_types=virtualization.virtualmachine&lookup=iexact` |
| `….device.device_type`  | `/netbox/search/?q=<value>&obj_types=dcim.devicetype`                                                   |
| `….device.manufacturer` | `/netbox/search/?q=<value>&obj_types=dcim.manufacturer`                                                 |
| `….device.role`         | `/netbox/search/?q=<value>&obj_types=dcim.devicerole`                                                   |
| `….device.site`         | `/netbox/search/?q=<value>&obj_types=dcim.site&lookup=iexact`                                           |
| `….segment.site`        | `/netbox/search/?q=<value>&obj_types=dcim.site&lookup=iexact`                                           |
| `network.name`          | `/netbox/search/?q=<value>&obj_types=ipam.prefix&lookup=iexact`                                         |
| `related.device_name`   | `/netbox/search/?q=<value>&obj_types=dcim.device&obj_types=virtualization.virtualmachine&lookup=iexact` |
| `related.device_type`   | `/netbox/search/?q=<value>&obj_types=dcim.devicetype`                                                   |
| `related.manufacturer`  | `/netbox/search/?q=<value>&obj_types=dcim.manufacturer`                                                 |
| `related.role`          | `/netbox/search/?q=<value>&obj_types=dcim.devicerole`                                                   |
| `related.site`          | `/netbox/search/?q=<value>&obj_types=dcim.site&lookup=iexact`                                           |

#### Example

```text
/netbox/search/?q=Cyberville&obj_types=dcim.site&lookup=iexact
```

### External links

Use the following URI pattern to link to an external URL. Malcolm will display a redirect prompt before leaving the Malcolm interface:

```text
/dashboards/app/refred/<external URL>
```

#### Example

```text
/dashboards/app/refred/https://example.com/
```

---

## Table of Contents

### General Network Logs

* [Actions and Results](#actions-and-results)
* [Asset Interaction Analysis](#asset-interaction-analysis)
* [Connections](#connections)
* [Connections - Destination - Originator Bytes (region map)](#connections-destination-originator-bytes-region-map)
* [Connections - Destination - Responder Bytes](#connections-destination-responder-bytes)
* [Connections - Destination - Responder Bytes (region map)](#connections-destination-responder-bytes-region-map)
* [Connections - Destination - Sum of Total Bytes](#connections-destination-sum-of-total-bytes)
* [Connections - Destination - Sum of Total Bytes (region map)](#connections-destination-sum-of-total-bytes-region-map)
* [Connections - Destination - Top Connection Duration](#connections-destination-top-connection-duration)
* [Connections - Destination - Top Connection Duration (region map)](#connections-destination-top-connection-duration-region-map)
* [Connections - Source - Originator Bytes](#connections-source-originator-bytes)
* [Connections - Source - Originator Bytes (region map)](#connections-source-originator-bytes-region-map)
* [Connections - Source - Responder Bytes (region map)](#connections-source-responder-bytes-region-map)
* [Connections - Source - Sum of Total Bytes](#connections-source-sum-of-total-bytes)
* [Connections - Source - Sum of Total Bytes (region map)](#connections-source-sum-of-total-bytes-region-map)
* [Connections - Source - Top Connection Duration](#connections-source-top-connection-duration)
* [Connections - Source - Top Connection Duration (region map)](#connections-source-top-connection-duration-region-map)
* [File Scanning](#file-scanning)
* [File Tree](#file-tree)
* [Files](#files)
* [IP Connections Tree](#ip-connections-tree)
* [Overview](#overview)
* [PE](#pe)
* [Security Overview](#security-overview)
* [Severity](#severity)
* [Signatures](#signatures)
* [Software](#software)
* [Suricata Alerts](#suricata-alerts)
* [Threat Intelligence](#threat-intelligence)
* [Zeek Known Summary](#zeek-known-summary)
* [Zeek Notices](#zeek-notices)
* [Zeek Weird](#zeek-weird)

### Common Protocols

* [DCE/RPC](#dcerpc)
* [DHCP](#dhcp)
* [DNS](#dns)
* [FTP](#ftp)
* [HTTP](#http)
* [IRC](#irc)
* [Kerberos](#kerberos)
* [LDAP](#ldap)
* [MQTT](#mqtt)
* [MySQL](#mysql)
* [NTLM](#ntlm)
* [NTP](#ntp)
* [OSPF](#ospf)
* [PostgreSQL](#postgresql)
* [QUIC](#quic)
* [RADIUS](#radius)
* [RDP](#rdp)
* [Redis](#redis)
* [RFB](#rfb)
* [SIP](#sip)
* [SMB](#smb)
* [SMTP](#smtp)
* [SNMP](#snmp)
* [SSH](#ssh)
* [SSL](#ssl)
* [STUN](#stun)
* [Syslog](#syslog)
* [Tabular Data Stream](#tabular-data-stream)
* [Tabular Data Stream - RPC](#tabular-data-stream-rpc)
* [Tabular Data Stream - SQL](#tabular-data-stream-sql)
* [Telnet, rlogin and rsh](#telnet-rlogin-and-rsh)
* [TFTP](#tftp)
* [Tunnels](#tunnels)
* [WebSocket](#websocket)
* [X.509](#x509)

### ICS/IoT Protocols

* [ANSI C12.22](#ansi-c1222)
* [BACnet](#bacnet)
* [BSAP](#bsap)
* [DNP3](#dnp3)
* [EtherCAT](#ethercat)
* [EtherNet/IP](#ethernetip)
* [GE SRTP](#ge-srtp)
* [GENISYS](#genisys)
* [HART-IP](#hart-ip)
* [ICS Best Guess](#ics-best-guess)
* [ICS/IoT Security Overview](#icsiot-security-overview)
* [Modbus](#modbus)
* [Omron FINS](#omron-fins)
* [OPCUA Binary](#opcua-binary)
* [PROFINET](#profinet)
* [ROC Plus](#roc-plus)
* [S7comm / S7comm Plus](#s7comm-s7comm-plus)
* [Synchrophasor](#synchrophasor)


---

## General Network Logs

---

### Actions and Results

* ID: [a33e0a50-afcd-11ea-993f-b7d8522a8bed](#/dashboard/a33e0a50-afcd-11ea-993f-b7d8522a8bed)

The Actions and Results dashboard provides a cross-protocol view of operation types and their outcomes across all monitored ICS and IT protocols. It aggregates event action and result fields to show what commands were issued, which succeeded or failed, and which hosts were involved. This is useful for detecting anomalous command patterns, failed authentication attempts, and unauthorized operations across protocols.

#### Visualizations

* Actions
* All Logs
* Results
* Top Actions by Service
* Top Results by Service
* Total Log Count Over Time by Application Protocol
* Total Number of Logs


---

### Asset Interaction Analysis

* ID: [677ee170-809e-11ed-8d5b-07069f823b6f](#/dashboard/677ee170-809e-11ed-8d5b-07069f823b6f)

The Asset Interaction Analysis dashboard maps the communication relationships between hosts on the network enriched with the context provided by the [NetBox asset inventory](asset-interaction-analysis.md), providing a behavioral picture of which assets talk to which. It uses connection and protocol data to surface interaction patterns, cross-segment traffic, unusual peer relationships, and potentially unauthorized lateral movement. Security teams use this dashboard to understand normal communication baselines and flag deviations that may indicate compromise or misconfiguration.

#### Visualizations

* Cross Segment Traffic
* Destination Device Log Counts
* Destination Device Role
* Destination Device Type
* Event Severity by Network Segment
* Network Site
* Notice, Alert and Signature by Network Segment
* Protocol by Network Segment
* Source Device Log Counts
* Source Device Role
* Source Device Type
* Traffic by Network Segment
* Uninventoried Internal Assets - Logs
* Uninventoried Internal Destination IPs
* Uninventoried Internal Source IPs
* Uninventoried Observed Services - Logs


#### Fields

* `destination.device.device_type`
* `destination.device.manufacturer`
* `destination.device.name`
* `destination.device.role`
* `destination.oui`
* `destination.segment.name`
* `destination.segment.site`
* `event.risk_score`
* `event.severity_tags`
* `network.bytes`
* `network.name`
* `network.packets`
* `related.site`
* `rule.category`
* `source.device.device_type`
* `source.device.manufacturer`
* `source.device.name`
* `source.device.role`
* `source.oui`
* `source.segment.name`
* `source.segment.site`


---

### Connections

* ID: [abdd7550-2c7c-40dc-947e-f6d186a158c4](#/dashboard/abdd7550-2c7c-40dc-947e-f6d186a158c4)

The Connections dashboard covers all network-layer connection records observed on the network, including TCP, UDP, and ICMP flows. It surfaces data on conversation volumes, data transfer sizes, connection durations, geographic origins and destinations, and top talkers by byte count. Users can identify chatty hosts, large data transfers, long-lived connections, and cross-border traffic that may warrant further investigation.

#### Visualizations

* Connections - Connection State
* Connections - Destination IP Address
* Connections - Destination MAC Address
* Connections - Destination MAC OUI
* Connections - Destination Port
* Connections - Log Count
* Connections - Log Count Over Time
* Connections - Logs
* Connections - Missed Bytes
* Connections - Protocol
* Connections - Responder Bytes
* Connections - Service By Destination Country
* Connections - Source Country
* Connections - Source IP Address
* Connections - Source MAC Address
* Connections - Source MAC OUI
* Connections - Top 10 - Total Bytes By Connection
* Connections - Top 10 - Total Bytes By Destination IP
* Connections - Top 10 - Total Bytes By Destination MAC OUI
* Connections - Top 10 - Total Bytes By Destination Port
* Connections - Top 10 - Total Bytes By Source IP
* Connections - Top 10 - Total Bytes By Source MAC OUI
* Connections - Total Bytes Per Source/Destination IP Pair
* Long Connections - Log Count
* Network Layer


#### Fields

* `destination.geo.country_name`
* `destination.mac`
* `destination.oui`
* `network.bytes`
* `network.community_id`
* `server.bytes`
* `source.geo.country_code2`
* `source.mac`
* `source.oui`
* `zeek.conn.conn_state_description`
* `zeek.conn.long`
* `zeek.conn.missed_bytes`


---

### Connections - Destination - Originator Bytes (region map)

* ID: [55e332d0-3f99-11e9-a58e-8bdedb0915e8](#/dashboard/55e332d0-3f99-11e9-a58e-8bdedb0915e8)

This country-level map shades destination countries by the volume of bytes sent to them by originators, on a green-to-red scale where green indicates lower volumes and red indicates higher volumes. It gives a geographic overview of where data is being directed at a national level. Useful for quickly spotting countries receiving disproportionately large volumes of traffic.

#### Visualizations

* Connections - Destination - Originator Bytes (region map)


#### Fields

* `client.bytes`
* `destination.geo.country_iso_code`
* `network.bytes`


---

### Connections - Destination - Responder Bytes

* ID: [d4fd6afd-15cb-42bf-8a25-03dd8e59b327](#/dashboard/d4fd6afd-15cb-42bf-8a25-03dd8e59b327)

This coordinate map plots destination locations as dots sized by the volume of bytes sent back by responders, pinned to city-level precision. It highlights specific geographic locations where large volumes of response data are originating. Useful for detecting concentrated sources of response traffic at a granular level.

#### Visualizations

* Connections - Destination - Responder Bytes


#### Fields

* `destination.geo.location`
* `network.bytes`
* `server.bytes`


---

### Connections - Destination - Responder Bytes (region map)

* ID: [77fc9960-3f99-11e9-a58e-8bdedb0915e8](#/dashboard/77fc9960-3f99-11e9-a58e-8bdedb0915e8)

This country-level map shades destination countries by the volume of bytes sent back by responders, on a green-to-red scale where green indicates lower volumes and red indicates higher volumes. It gives a geographic overview of which countries are generating the most response traffic back to monitored hosts. Useful for identifying national-level sources of high-volume response data.

#### Visualizations

* Connections - Destination - Responder Bytes (region map)


#### Fields

* `destination.geo.country_iso_code`
* `network.bytes`
* `server.bytes`


---

### Connections - Destination - Sum of Total Bytes

* ID: [60d78fbd-471c-4f59-a9e3-189b33a13644](#/dashboard/60d78fbd-471c-4f59-a9e3-189b33a13644)

This coordinate map plots destination locations as dots sized by total bytes in both directions, pinned to city-level precision. It highlights specific geographic locations involved in the heaviest overall data exchange. Useful for detecting geographic hotspots of combined traffic volume at a granular level.

#### Visualizations

* Connections - Destination - Sum of Total Bytes


#### Fields

* `destination.geo.location`
* `network.bytes`


---

### Connections - Destination - Sum of Total Bytes (region map)

* ID: [a16110b0-3f99-11e9-a58e-8bdedb0915e8](#/dashboard/a16110b0-3f99-11e9-a58e-8bdedb0915e8)

This country-level map shades destination countries by total bytes exchanged in both directions, on a green-to-red scale where green indicates lower volumes and red indicates higher volumes. It provides a high-level geographic summary of which countries are associated with the most overall network traffic. Useful for identifying countries with disproportionately high combined data volumes.

#### Visualizations

* Connections - Destination - Sum of Total Bytes (region map)


#### Fields

* `destination.geo.country_iso_code`
* `network.bytes`


---

### Connections - Destination - Top Connection Duration

* ID: [0aed0e23-c8ac-4f2b-9f68-d04b6e7666b0](#/dashboard/0aed0e23-c8ac-4f2b-9f68-d04b6e7666b0)

This coordinate map plots destination locations as dots sized by connection duration, pinned to city-level precision. It highlights specific geographic locations associated with the longest-lived connections. Useful for detecting persistent communication channels to unexpected destinations at a granular level.

#### Visualizations

* Connections - Destination - Top Connection Duration


#### Fields

* `destination.geo.location`
* `event.duration`
* `network.bytes`


---

### Connections - Destination - Top Connection Duration (region map)

* ID: [b9f247c0-3f99-11e9-a58e-8bdedb0915e8](#/dashboard/b9f247c0-3f99-11e9-a58e-8bdedb0915e8)

This country-level map shades destination countries by longest connection duration, on a green-to-red scale where green indicates shorter durations and red indicates longer ones. It provides a geographic overview of which nations are associated with the most long-lived outbound connections. Useful for identifying countries linked to persistent communication that may indicate C2 or ongoing exfiltration.

#### Visualizations

* Connections - Destination - Top Connection Duration (region map)


#### Fields

* `destination.geo.country_iso_code`
* `event.duration`
* `network.bytes`


---

### Connections - Source - Originator Bytes

* ID: [b50c8d17-6ed3-4de6-aed4-5181032810b2](#/dashboard/b50c8d17-6ed3-4de6-aed4-5181032810b2)

This coordinate map plots source locations as dots sized by the volume of bytes sent as an originator, pinned to city-level precision. It highlights specific geographic locations generating the most outbound data. Useful for detecting high-volume originating sources at a granular geographic level.

#### Visualizations

* Connections - Source - Originator Bytes


#### Fields

* `client.bytes`
* `network.bytes`
* `source.geo.location`


---

### Connections - Source - Originator Bytes (region map)

* ID: [d41fe630-3f98-11e9-a58e-8bdedb0915e8](#/dashboard/d41fe630-3f98-11e9-a58e-8bdedb0915e8)

This country-level map shades source countries by the volume of bytes sent as originators, on a green-to-red scale where green indicates lower volumes and red indicates higher volumes. It provides a geographic overview of which nations are generating the most outbound traffic. Useful for correlating high-volume originator activity with known threat actor regions or unexpected source countries.

#### Visualizations

* Connections - Source - Originator Bytes (region map)


#### Fields

* `client.bytes`
* `network.bytes`
* `source.geo.country_iso_code`


---

### Connections - Source - Responder Bytes (region map)

* ID: [ed8a6640-3f98-11e9-a58e-8bdedb0915e8](#/dashboard/ed8a6640-3f98-11e9-a58e-8bdedb0915e8)

This country-level map shades source countries by the volume of bytes received from responders, on a green-to-red scale where green indicates lower volumes and red indicates higher volumes. It provides a geographic overview of which source nations are receiving the most response data. Useful for identifying countries whose hosts are pulling large volumes of data from remote responders.

#### Visualizations

* Connections - Source - Responder Bytes (region map)


#### Fields

* `network.bytes`
* `server.bytes`
* `source.geo.country_iso_code`


---

### Connections - Source - Sum of Total Bytes

* ID: [f394057d-1b16-4174-b994-7045f423a416](#/dashboard/f394057d-1b16-4174-b994-7045f423a416)

This coordinate map plots source locations as dots sized by total bytes in both directions, pinned to city-level precision. It highlights specific geographic locations with the highest combined traffic volumes. Useful for surfacing geographic hotspots of overall activity at a granular level.

#### Visualizations

* Connections - Source - Sum of Total Bytes


#### Fields

* `network.bytes`
* `source.geo.location`


---

### Connections - Source - Sum of Total Bytes (region map)

* ID: [1ce42250-3f99-11e9-a58e-8bdedb0915e8](#/dashboard/1ce42250-3f99-11e9-a58e-8bdedb0915e8)

This country-level map shades source countries by total bytes exchanged in both directions, on a green-to-red scale where green indicates lower volumes and red indicates higher volumes. It provides a high-level geographic summary of which nations are the most network-active overall. Useful for identifying countries with disproportionately high combined traffic volumes.

#### Visualizations

* Connections - Source - Sum of Total Bytes (region map)


#### Fields

* `network.bytes`
* `source.geo.country_iso_code`


---

### Connections - Source - Top Connection Duration

* ID: [e09a4b86-29b5-4256-bb3b-802ac9f90404](#/dashboard/e09a4b86-29b5-4256-bb3b-802ac9f90404)

This coordinate map plots source locations as dots sized by connection duration, pinned to city-level precision. It highlights specific geographic locations where the most persistent outbound connections originate. Useful for detecting long-running sessions from unexpected locations that may indicate beaconing or C2 activity.

#### Visualizations

* Connections - Source - Top Connection Duration


#### Fields

* `event.duration`
* `network.bytes`
* `source.geo.location`


---

### Connections - Source - Top Connection Duration (region map)

* ID: [39abfe30-3f99-11e9-a58e-8bdedb0915e8](#/dashboard/39abfe30-3f99-11e9-a58e-8bdedb0915e8)

This country-level map shades source countries by longest connection duration, on a green-to-red scale where green indicates shorter durations and red indicates longer ones. It provides a geographic overview of which nations are associated with the most persistent originating connections. Useful for identifying countries linked to long-lived communication patterns that may indicate ongoing adversary activity.

#### Visualizations

* Connections - Source - Top Connection Duration (region map)


#### Fields

* `event.duration`
* `network.bytes`
* `source.geo.country_iso_code`


---

### File Scanning

* ID: [248cae60-eff9-11f0-b83f-8f35d6995138](#/dashboard/248cae60-eff9-11f0-b83f-8f35d6995138)

The File Scanning dashboard consolidates results from Malcolm's [automatic file extraction and scanning](file-scanning.md#ZeekFileExtraction) capability provided by [Strelka](https://target.github.io/strelka/#/), including those from [YARA](https://github.com/VirusTotal/yara), [ClamAV](https://www.clamav.net/), and [many others](https://target.github.io/strelka/#/?id=scanner-list). It tracks files observed in network traffic, their MIME types, the contents of archive files, and signatures and reports generated by the scanners. This dashboard is useful for hunting malware, tracking file transfers across the network, and validating whether transferred files are known-bad or suspicious. For a more general-purpose dashboard dealing with file transfers, see [Files](#files).

#### Visualizations

* File Scanning - All Scanners
* File Scanning - Destination IP
* File Scanning - File Source
* File Scanning - Hit Count
* File Scanning - Hits Over Time
* File Scanning - Logs
* File Scanning - MIME Type
* File Scanning - Scanners With Hits
* File Scanning - Severity
* File Scanning - Source IP
* File Scanning - Tactic and Technique
* File Scanning - Triggered Rules
* Files Scanned by Nesting Depth


#### Fields

* `event.risk_score`
* `event.severity_tags`
* `file.entropy`
* `file.mime_type`
* `file.name`
* `file.size`
* `file.source`
* `filescan.hits`
* `filescan.tree.depth`
* `rule.name`
* `rule.ruleset`
* `threat.tactic.name`
* `threat.technique.name`
* `zeek.files.extracted_uri`


---

### File Tree

* ID: [4ff567d0-48a6-11f1-9604-d962b9b51f3a](#/dashboard/4ff567d0-48a6-11f1-9604-d962b9b51f3a)

The File Tree dashboard presents a hierarchical breakdown of files observed in network traffic, particularly with regards to [archived files](file-scanning.md#ScanningArchivedFiles) such as ZIP files or tarballs, allowing parent/child relationships between nested files to be explored.

#### Visualizations

* File Scanning - MIME Type
* File Tree
* File Tree - Logs
* Files Scanned by Nesting Depth


#### Fields

* `file.entropy`
* `file.mime_type`
* `file.name`
* `file.size`
* `file.source`
* `filescan.hits`
* `filescan.tree.depth`
* `filescan.tree.node`
* `filescan.tree.parent`
* `filescan.tree.root`
* `firstPacket`
* `rule.name`
* `rule.ruleset`
* `zeek.files.extracted_uri`
* `zeek.files.filename`


---

### Files

* ID: [9ee51f94-3316-4fc5-bd89-93a52af69714](#/dashboard/9ee51f94-3316-4fc5-bd89-93a52af69714)

The Files dashboard provides an overview of all files observed traversing the network as captured by Zeek's [file analysis framework](file-scanning.md#ZeekFileExtraction). It covers file types by the context of the transfer (e.g., protocol), MIME type, path and filename (where applicable), transfer volumes, source and destination hosts, and file hashes. When file preservation is enabled, users have download access to the files in question. Analysts can identify unusual file types, large file transfers, and track specific files of interest across the captured traffic.

#### Visualizations

*  - Destination IP Address
* Extracted File Downloads
* Files - Files By Size (Bytes)
* Files - Log Count
* Files - Log Count Over Time
* Files - Logs
* Files - MIME Type
* Files - Paths
* Files - Source
* Files - Source IP Address


#### Fields

* `file.mime_type`
* `file.name`
* `file.path`
* `file.size`
* `file.source`
* `zeek.files.extracted_uri`
* `zeek.files.seen_bytes`


---

### IP Connections Tree

* ID: [89714140-a2d5-11f0-b5ae-e139a66d2205](#/dashboard/89714140-a2d5-11f0-b5ae-e139a66d2205)

*Trees are Malcolm analytics designed to be utilized by analysts to assist in tracking lateral movement across a network.*

The IP Connections Tree dashboard presents network connection data in a hierarchical tree structure, showing parent-child relationships between communicating hosts. It is designed to help analysts visualize communication chains and identify which hosts serve as hubs or pivots in the network topology. This view is particularly useful during incident investigations to trace lateral movement or identify command-and-control relationships.

#### Visualizations

* Connections - Logs
* Connections Tree From Destination
* Connections Tree From Source


#### Fields

* `network.bytes`
* `zeek.conn.conn_state`


---

### Overview

* ID: [0ad3d7c2-3441-485e-9dfe-dbb22e84e576](#/dashboard/0ad3d7c2-3441-485e-9dfe-dbb22e84e576)

The Overview dashboard provides a high-level summary of all network traffic and log activity across the monitored environment. It aggregates events from every data source into a single view, showing total log volume, protocol distribution, and top communicating hosts. Analysts use it as a starting point to assess overall activity levels and quickly identify unusual spikes or new protocol traffic before drilling into protocol-specific dashboards.

#### Visualizations

* Actions and Results
* All Logs
* Application Protocol
* Connections - Service By Destination Country
* DNS - Queries
* Log Source
* Log Type
* Total Log Count Over Time
* Total Number of Logs


#### Fields

* `destination.geo.country_name`
* `network.bytes`
* `network.protocol_version`
* `zeek.dns.answers`
* `zeek.dns.query`


---

### PE

* ID: [0a490422-0ce9-44bf-9a2d-19329ddde8c3](#/dashboard/0a490422-0ce9-44bf-9a2d-19329ddde8c3)

The PE (Portable Executable) dashboard provides visibility into Windows PE file analysis data observed in network traffic, covering OS targets, machine types, subsystems, section names, and capability signatures. It helps analysts understand what executable files have been observed in network traffic and identify suspicious characteristics such as unusual sections or capability flags. This dashboard is particularly useful during malware investigations to quickly characterize executables transferring across the network.

#### Visualizations

* Capa Signatures
* Executable Capabilities
* PE - Log Count
* PE - Log Count Over Time
* PE - Logs
* PE - Machine
* PE - OS
* PE - Section Name
* PE - Subsystem


#### Fields

* `rule.name`
* `zeek.pe.machine`
* `zeek.pe.os`
* `zeek.pe.section_names`
* `zeek.pe.subsystem`


---

### Security Overview

* ID: [95479950-41f2-11ea-88fa-7151df485405](#/dashboard/95479950-41f2-11ea-88fa-7151df485405)

The Security Overview dashboard offers a consolidated view of security-relevant events across all monitored protocols. It combines alert data, notice events, and categorized rule hits to give analysts an at-a-glance picture of the threat landscape. This is a useful starting point for daily triage, providing trend lines, category breakdowns, and top event sources to focus attention where it matters most.

#### Visualizations

* Clear-text Transmission of Passwords
* Connections by Destination Country (region map)
* DNS Queries by Randomness
* File Transfers
* Inbound Access By Protocol Over Time
* Inbound External Traffic by Country
* Normalized Event Category
* Notice, Alert and Signature - Summary
* Notice, Alert, and Signature - Logs
* Outbound Internal Traffic by Country
* Outdated/Insecure Application Protocols
* Vulnerabilities


#### Fields

* `destination.geo.country_code2`
* `destination.geo.country_name`
* `dns.host`
* `event.freq_score_v1`
* `event.freq_score_v2`
* `event.severity_tags`
* `file.mime_type`
* `network.bytes`
* `network.protocol_version`
* `related.user`
* `rule.category`
* `rule.name`
* `source.geo.country_name`
* `vulnerability.id`
* `zeek.dns.answers`
* `zeek.dns.query`


---

### Severity

* ID: [d2dd0180-06b1-11ec-8c6b-353266ade330](#/dashboard/d2dd0180-06b1-11ec-8c6b-353266ade330)

The Severity dashboard organizes all detected events and alerts by their assigned severity level, from informational notices through critical findings. It draws from both Zeek notices and Suricata alert data to present a ranked view of the most impactful activity in the environment. Analysts use it to prioritize response actions and track whether high-severity event counts are increasing or decreasing over time.

#### Visualizations

* Actions and Results
* File Types by Transport
* Severity - Application Protocol
* Severity - Destination IP
* Severity - Destination OUI
* Severity - Notices
* Severity - Originating Country
* Severity - Responding Country
* Severity - Socket Family
* Severity - Source IP
* Severity - Source OUI
* Severity Score Occurrences
* Severity Tags
* Severity-Scored Logs


#### Fields

* `destination.geo.country_iso_code`
* `destination.oui`
* `event.risk_score`
* `event.severity`
* `event.severity_tags`
* `file.mime_type`
* `file.path`
* `file.source`
* `rule.category`
* `rule.name`
* `source.geo.country_iso_code`
* `source.oui`
* `zeek.notice.msg`
* `zeek.notice.note`


---

### Signatures

* ID: [665d1610-523d-11e9-a30e-e3576242f3ed](#/dashboard/665d1610-523d-11e9-a30e-e3576242f3ed)

The Signatures dashboard focuses on rule-based detections, showing which signatures have fired and how frequently. It covers both Suricata alert rules and Zeek notice signatures, providing a breakdown by rule name, category, and originating host. This dashboard helps tune detection coverage—identifying which signatures generate the most noise versus those that rarely fire but may be highly significant.

#### Visualizations

* Signatures - Destination IP
* Signatures - Log Count
* Signatures - Log Count Over Time
* Signatures - Logs
* Signatures - Name
* Signatures - Source IP


#### Fields

* `rule.category`
* `rule.name`


---

### Software

* ID: [87d990cc-9e0b-41e5-b8fe-b10ae1da0c85](#/dashboard/87d990cc-9e0b-41e5-b8fe-b10ae1da0c85)

The Software dashboard tracks software versions and products observed in network traffic, as identified by Zeek's Software framework. It surfaces client and server software names, versions, and the hosts running them, enabling asset management and vulnerability correlation. This is particularly useful for identifying outdated or vulnerable software versions in use across the environment.

#### Visualizations

* Software - Log Count
* Software - Log Count Over Time
* Software - Logs
* Software - Summary


#### Fields

* `url.full`
* `zeek.software.name`
* `zeek.software.software_type`
* `zeek.software.unparsed_version`
* `zeek.software.version_major`
* `zeek.software.version_minor`


---

### Suricata Alerts

* ID: [5694ca60-cbdf-11ec-a50a-5fedd672f5c5](#/dashboard/5694ca60-cbdf-11ec-a50a-5fedd672f5c5)

The Suricata Alerts dashboard surfaces all alerts generated by the Suricata network intrusion detection engine. It presents alert volume over time, rule categories, top alert names, and the source and destination hosts triggering detections. Analysts can use it to identify active threats, track alert trends, and investigate which hosts are most involved in flagged activity.

#### Visualizations

* Alert Category
* Alerts - Destination
* Alerts - Destination Country
* Alerts - Log Count
* Alerts - Log Count Over Time
* Alerts - Name
* Alerts - Source
* Alerts - Source Country
* Alerts - Tags
* Alerts - Target
* Suricata Alerts - Logs


#### Fields

* `destination.geo.country_name`
* `rule.category`
* `rule.id`
* `rule.name`
* `source.geo.country_name`
* `vulnerability.category`


---

### Threat Intelligence

* ID: [36ed695f-edcc-47c1-b0ec-50d20c93ce0f](#/dashboard/36ed695f-edcc-47c1-b0ec-50d20c93ce0f)

The Threat Intelligence dashboard presents matches between observed network traffic and threat intelligence indicators, as detected by Zeek's Intel framework. It shows which indicators have been seen, their types (IP, domain, URL, etc.), the sources providing the intelligence, and which network hosts were involved. Analysts can use this dashboard to identify confirmed IOC matches and prioritize incident response based on indicator severity and frequency.

#### Visualizations

* Intel - Destination IP
* Intel - Indicator
* Intel - Indicator Category
* Intel - Indicator Description
* Intel - Indicator Source
* Intel - Indicator Type
* Intel - Log Count
* Intel - Log Count Over Time
* Intel - Logs
* Intel - MIME Type
* Intel - Observed In
* Intel - Source IP
* Intel - Tags
* Intel - Unique Indicators


#### Fields

* `file.mime_type`
* `threat.indicator.description`
* `threat.indicator.name`
* `threat.indicator.provider`
* `threat.indicator.reference`
* `threat.indicator.type`
* `zeek.intel.category`
* `zeek.intel.seen_where`


---

### Zeek Known Summary

* ID: [89d1cc50-974c-11ed-bb6b-3fb06c879b11](#/dashboard/89d1cc50-974c-11ed-bb6b-3fb06c879b11)

The Zeek Known Summary dashboard aggregates data from Zeek's 'known' logs, which track hosts, services, and certificates that have been observed on the network. It provides an inventory-style view of known devices, services, and software in the environment. This is useful for asset discovery, baselining normal behavior, and identifying new or unexpected hosts and services appearing on the network.

#### Visualizations

* IANA Service Name and Transport Protocol Port Number Registry
* Log Source
* Observed Device Types
* Observed Devices
* Observed Protocols Cloud
* Observed Software
* Observed Software Categories
* Uninventoried Observed Hosts
* Uninventoried Observed Services
* Unique Known IP Addresses
* Zeek Known Hosts - Logs
* Zeek Known Services - Logs
* Zeek Known Software - Logs


#### Fields

* `destination.device.uninventoried`
* `destination.segment.name`
* `network.name`
* `related.device_name`
* `related.device_type`
* `related.manufacturer`
* `related.role`
* `related.site`
* `source.device.uninventoried`
* `source.segment.name`
* `url.full`
* `zeek.known_services.iana_description`
* `zeek.known_services.iana_name`
* `zeek.software.name`
* `zeek.software.software_type`
* `zeek.software.unparsed_version`


---

### Zeek Notices

* ID: [f1f09567-fc7f-450b-a341-19d2f2bb468b](#/dashboard/f1f09567-fc7f-450b-a341-19d2f2bb468b)

The Zeek Notices dashboard displays all notice-level events raised by Zeek's detection framework, which flags potentially significant network behaviors. Notices can represent a wide range of conditions—from scanning activity and SSL anomalies to policy violations and protocol errors. This dashboard helps analysts review what Zeek has flagged, understand the distribution of notice types, and correlate notices with specific hosts.

#### Visualizations

* Notice - Destination Port
* Notice - Message Details
* Notices - Destination Country
* Notices - Destination IP Addresses
* Notices - File Description
* Notices - File MIME Type
* Notices - Log Count
* Notices - Log Count Over Time
* Notices - Logs
* Notices - Notice Type
* Notices - Notice Types by Source and Destination
* Notices - Source Country
* Notices - Source IP Addresses


#### Fields

* `destination.geo.country_name`
* `rule.category`
* `rule.name`
* `source.geo.country_name`
* `zeek.notice.file_desc`
* `zeek.notice.file_mime_type`
* `zeek.notice.msg`


---

### Zeek Weird

* ID: [1fff49f6-0199-4a0f-820b-721aff9ff1f1](#/dashboard/1fff49f6-0199-4a0f-820b-721aff9ff1f1)

The Zeek Weird dashboard captures unusual or unexpected protocol behaviors that Zeek's 'weird' log records—events that don't fit normal protocol expectations. These entries often indicate malformed packets, protocol misuse, or active reconnaissance, making them valuable early-warning indicators. Analysts can review this dashboard to surface low-level anomalies that may not trigger a full alert but still merit investigation.

#### Visualizations

* Weird - Destination
* Weird - Log Count
* Weird - Log Count Over Time
* Weird - Logs
* Weird - Name
* Weird - Source


#### Fields

* `rule.name`


---

## Common Protocols

---

### DCE/RPC

* ID: [432af556-c5c0-4cc3-8166-b274b4e3a406](#/dashboard/432af556-c5c0-4cc3-8166-b274b4e3a406)

The DCE/RPC dashboard provides visibility into [Distributed Computing Environment / Remote Procedure Call (DCE/RPC)](https://en.wikipedia.org/wiki/DCE/RPC) traffic, which underlies many Windows protocols including DCOM and WMI. It surfaces endpoint UUIDs, operations, named pipes, and the hosts involved in RPC exchanges. Security teams can use this dashboard to detect lateral movement via WMI or DCOM, identify unusual RPC service calls, and spot DCE/RPC-based reconnaissance.

#### Visualizations

* DCE/RPC - Destination IP Address
* DCE/RPC - Destination Port
* DCE/RPC - Endpoint
* DCE/RPC - Log Count
* DCE/RPC - Log Count Over Time
* DCE/RPC - Logs
* DCE/RPC - Named Pipe
* DCE/RPC - Operation
* DCE/RPC - Round Trip Time
* DCE/RPC - Source IP Address
* DCE/RPC - Summary


#### Fields

* `zeek.dce_rpc.endpoint`
* `zeek.dce_rpc.named_pipe`
* `zeek.dce_rpc.operation`
* `zeek.dce_rpc.rtt`


---

### DHCP

* ID: [2d98bb8e-214c-4374-837b-20e1bcd63a5e](#/dashboard/2d98bb8e-214c-4374-837b-20e1bcd63a5e)

The DHCP dashboard tracks [Dynamic Host Configuration Protocol (DHCP)](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol) activity observed on the network, including IP address assignments, hostname registrations, and lease activity. It provides a real-time picture of which devices are joining the network and what addresses they are receiving. Analysts can use it for asset discovery, detecting rogue DHCP servers, and correlating IP addresses with hostnames at specific points in time.

#### Visualizations

* DHCP - Client Software
* DHCP - Destination IP Address
* DHCP - Destination Port
* DHCP - IP to MAC Assignment
* DHCP - JA4D Fingerprint
* DHCP - Log Count
* DHCP - Log Count Over Time
* DHCP - Logs
* DHCP - Server Software
* DHCP - Source IP Address


#### Fields

* `dhcp.ja4d`
* `source.mac`
* `zeek.dhcp.assigned_ip`
* `zeek.dhcp.client_software`
* `zeek.dhcp.domain`
* `zeek.dhcp.host_name`
* `zeek.dhcp.msg_types`
* `zeek.dhcp.server_software`
* `zeek.dhcp.vendor_class_id`


---

### DNS

* ID: [2cf94cd0-ecab-40a5-95a7-8419f3a39cd9](#/dashboard/2cf94cd0-ecab-40a5-95a7-8419f3a39cd9)

The DNS dashboard provides a comprehensive view of [Domain Name System (DNS)](https://en.wikipedia.org/wiki/Domain_Name_System) activity observed on the network. It covers query volumes over time, top queried domains, response codes, query types, and the hosts generating DNS traffic. Analysts use it to detect DNS-based threats such as data exfiltration via DNS tunneling, domain generation algorithm (DGA) activity, and unusually high query rates.

#### Visualizations

* DNS - Answers
* DNS - Client
* DNS - Destination Port
* DNS - Log Count
* DNS - Log Count Over Time
* DNS - Logs
* DNS - Protocol
* DNS - Query Class
* DNS - Query Type
* DNS - Query/Answer
* DNS - Response Code (Name)
* DNS - Server
* DNS Queries by Randomness


#### Fields

* `dns.host`
* `event.freq_score_v1`
* `event.freq_score_v2`
* `zeek.dns.answers`
* `zeek.dns.qclass_name`
* `zeek.dns.qtype_name`
* `zeek.dns.query`
* `zeek.dns.rcode_name`


---

### FTP

* ID: [078b9aa5-9bd4-4f02-ae5e-cf80fa6f887b](#/dashboard/078b9aa5-9bd4-4f02-ae5e-cf80fa6f887b)

The FTP dashboard covers all [File Transfer Protocol (FTP)](https://en.wikipedia.org/wiki/File_Transfer_Protocol) activity observed on the network, including commands, arguments, reply codes, and transfer participants. It provides insight into file staging, unauthorized file transfers, and FTP authentication patterns. This is a useful dashboard for investigating data exfiltration over FTP and identifying misconfigured FTP servers accessible to unauthorized clients.

#### Visualizations

* FTP - Argument
* FTP - Commands and Replies
* FTP - Destination
* FTP - Log Count
* FTP - Log Count Over Time
* FTP - Logs
* FTP - Reply
* FTP - Source
* FTP - Username


#### Fields

* `related.user`
* `zeek.ftp.arg`
* `zeek.ftp.command`
* `zeek.ftp.reply_code`
* `zeek.ftp.reply_msg`


---

### HTTP

* ID: [37041ee1-79c0-4684-a436-3173b0e89876](#/dashboard/37041ee1-79c0-4684-a436-3173b0e89876)

The HTTP dashboard covers all [HTTP](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol) web traffic observed on the network, including request methods, URIs, response codes, user agents, and host headers. It provides insight into web browsing behavior, application traffic, file downloads, and server responses across the monitored network. This is a key dashboard for investigating web-based attacks, unauthorized downloads, and unusual HTTP patterns that may indicate compromise.

#### Visualizations

* HTTP  - Status and Method
* HTTP - Destination Country
* HTTP - Destination IP Address
* HTTP - Destination Port
* HTTP - File Type
* HTTP - Log Count
* HTTP - Logs
* HTTP - Method and Status
* HTTP - Referrer
* HTTP - Sites
* HTTP - Sites Hosting EXEs
* HTTP - Source IP Address
* HTTP - Status Over Time
* HTTP - URIs
* HTTP - Unique Usernames and Passwords
* HTTP - User Agent
* HTTP - Version


#### Fields

* `destination.geo.country_name`
* `file.mime_type`
* `network.protocol_version`
* `related.password`
* `related.user`
* `user_agent.original`
* `zeek.http.host`
* `zeek.http.method`
* `zeek.http.referrer`
* `zeek.http.status_msg`
* `zeek.http.uri`


---

### IRC

* ID: [76f2f912-80da-44cd-ab66-6a73c8344cc3](#/dashboard/76f2f912-80da-44cd-ab66-6a73c8344cc3)

The IRC dashboard covers [Internet Relay Chat (IRC)](https://en.wikipedia.org/wiki/Internet_Relay_Chat) protocol traffic, tracking channels, nicknames, commands, and communication hosts. IRC is frequently used as a command-and-control channel by botnets and malware, making this dashboard a useful tool for detecting C2 communication and bot activity. Analysts can identify unexpected IRC traffic in environments where it is not a legitimate business tool.

#### Visualizations

* IRC - Command
* IRC - Destination Country
* IRC - Destination IP Address
* IRC - Destination Port
* IRC - Log Count
* IRC - Log Count Over Time
* IRC - Logs
* IRC - Source IP Address


#### Fields

* `destination.geo.city_name`
* `destination.geo.country_name`
* `zeek.irc.command`
* `zeek.irc.nick`
* `zeek.irc.value`


---

### Kerberos

* ID: [82da3101-2a9c-4ae2-bb61-d447a3fbe673](#/dashboard/82da3101-2a9c-4ae2-bb61-d447a3fbe673)

The Kerberos dashboard surfaces [Kerberos](https://en.wikipedia.org/wiki/Kerberos_(protocol))) authentication traffic, covering ticket requests, error codes, service names, and participating hosts. It is useful for detecting Kerberoasting, AS-REP roasting, ticket forgery, and other Active Directory authentication abuse patterns. Analysts can use the error code breakdown to identify failed authentication spikes and unusual service ticket requests.

#### Visualizations

* Kerberos - Cipher
* Kerberos - Client
* Kerberos - Destination IP Address
* Kerberos - Destination Ports
* Kerberos - Log Count
* Kerberos - Log Count Over Time
* Kerberos - Logs
* Kerberos - Renewable Ticket Requested
* Kerberos - Request Types
* Kerberos - Server
* Kerberos - Service
* Kerberos - Source IP Address
* Kerberos - Success Status


#### Fields

* `zeek.kerberos.cipher`
* `zeek.kerberos.cname`
* `zeek.kerberos.error_msg`
* `zeek.kerberos.renewable`
* `zeek.kerberos.request_type`
* `zeek.kerberos.sname`
* `zeek.kerberos.success`


---

### LDAP

* ID: [05e3e000-f118-11e9-acda-83a8e29e1a24](#/dashboard/05e3e000-f118-11e9-acda-83a8e29e1a24)

The LDAP dashboard tracks [Lightweight Directory Access Protocol (LDAP)](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol) queries and responses, covering bind operations, search queries, object targets, and results. It is particularly useful for identifying Active Directory enumeration, unauthorized directory queries, and LDAP injection attempts. Analysts can review top querying hosts and common search targets to baseline legitimate directory usage against anomalous activity.

#### Visualizations

* LDAP - Bind
* LDAP - Destination IP
* LDAP - Log Count
* LDAP - Log Count Over Time
* LDAP - Logs
* LDAP - Operation
* LDAP - Result Code
* LDAP - Search Scope
* LDAP - Source IP
* LDAP Search - Logs


#### Fields

* `network.protocol_version`
* `zeek.ldap.argument`
* `zeek.ldap.message_id`
* `zeek.ldap.object`
* `zeek.ldap.version`
* `zeek.ldap_search.base_object`
* `zeek.ldap_search.filter`
* `zeek.ldap_search.message_id`
* `zeek.ldap_search.result_count`
* `zeek.ldap_search.scope`


---

### MQTT

* ID: [87a32f90-ef58-11e9-974e-9d600036d105](#/dashboard/87a32f90-ef58-11e9-974e-9d600036d105)

The MQTT dashboard covers [MQ Telemetry Transport (MQTT)](https://en.wikipedia.org/wiki/MQTT) protocol traffic, widely used in IoT devices and lightweight machine-to-machine communication. It tracks topic names, QoS levels, client IDs, and broker/client communication patterns observed on the network. This dashboard is useful for asset discovery in IoT environments, detecting unauthorized MQTT brokers, and identifying sensitive topics being published or subscribed to by unexpected clients.

#### Visualizations

* MQTT - All Logs
* MQTT - Client ID
* MQTT - Destination IP
* MQTT - Log Count
* MQTT - Log Count Over Time
* MQTT - Protocol
* MQTT - Publish
* MQTT - Publish Payload
* MQTT - Source IP
* MQTT - Subscription


#### Fields

* `zeek.mqtt_connect.client_id`
* `zeek.mqtt_connect.connect_status`
* `zeek.mqtt_connect.proto_name`
* `zeek.mqtt_connect.proto_version`
* `zeek.mqtt_publish.from_client`
* `zeek.mqtt_publish.payload`
* `zeek.mqtt_publish.payload_len`
* `zeek.mqtt_publish.status`
* `zeek.mqtt_publish.topic`
* `zeek.mqtt_subscribe.ack`
* `zeek.mqtt_subscribe.action`
* `zeek.mqtt_subscribe.topics`


---

### MySQL

* ID: [50ced171-1b10-4c3f-8b67-2db9635661a6](#/dashboard/50ced171-1b10-4c3f-8b67-2db9635661a6)

The MySQL dashboard provides visibility into [MySQL](https://en.wikipedia.org/wiki/MySQL) database protocol traffic, including command types, user credentials (where visible), affected rows, and connection metadata. It helps detect unauthorized database access, SQL operations from unexpected hosts, and unusual query patterns. Security teams can use this to enforce database access policies and identify potential data exfiltration over MySQL connections.

#### Visualizations

* MySQL - Commands
* MySQL - Log Count
* MySQL - Log Count Over Time
* MySQL - Logs
* MySQL - Success


#### Fields

* `zeek.mysql.arg`
* `zeek.mysql.cmd`
* `zeek.mysql.response`
* `zeek.mysql.success`


---

### NTLM

* ID: [543118a9-02d7-43fe-b669-b8652177fc37](#/dashboard/543118a9-02d7-43fe-b669-b8652177fc37)

The NTLM dashboard covers [NT LAN Manager (NTLM)](https://en.wikipedia.org/wiki/NT_LAN_Manager) authentication traffic, including NTLM challenge-response exchanges, domain information, and authentication outcomes. It provides insight into legacy authentication usage and helps detect NTLM relay attacks, credential brute-forcing, and pass-the-hash activity. Security teams can use this dashboard to identify systems still relying on NTLM where Kerberos should be used.

#### Visualizations

* NTLM - Destination IP Address
* NTLM - Destination Port
* NTLM - Domain Name
* NTLM - Hostname
* NTLM - Hostname to Username
* NTLM - Log Count
* NTLM - Log Count Over Time
* NTLM - Logs
* NTLM - Source IP Address
* NTLM - Success
* NTLM - Username


#### Fields

* `related.user`
* `zeek.ntlm.domain`
* `zeek.ntlm.host`
* `zeek.ntlm.server_dns_computer`
* `zeek.ntlm.server_nb_computer`
* `zeek.ntlm.server_tree`
* `zeek.ntlm.success`


---

### NTP

* ID: [af5df620-eeb6-11e9-bdef-65a192b7f586](#/dashboard/af5df620-eeb6-11e9-bdef-65a192b7f586)

The NTP dashboard covers [Network Time Protocol (NTP)](https://en.wikipedia.org/wiki/Network_Time_Protocol) traffic, providing insight into time synchronization activity across the environment. It tracks NTP stratum levels, reference IDs, version numbers, and communication pairs. Analysts can detect NTP amplification abuse, rogue time sources, and unusual NTP query volumes that could indicate reconnaissance or DDoS preparation.

#### Visualizations

* NTP - Destination IP
* NTP - Log Count
* NTP - Log Count Over Time
* NTP - Logs
* NTP - Mode
* NTP - Polling Interval
* NTP - Source IP
* NTP - Stratum
* NTP - Version


#### Fields

* `zeek.ntp.mode_str`
* `zeek.ntp.org_time`
* `zeek.ntp.poll`
* `zeek.ntp.stratum`
* `zeek.ntp.version`
* `zeek.ntp.xmt_time`


---

### OSPF

* ID: [1cc01ff0-5205-11ec-a62c-7bc80e88f3f0](#/dashboard/1cc01ff0-5205-11ec-a62c-7bc80e88f3f0)

The OSPF dashboard covers [Open Shortest Path First (OSPF)](https://en.wikipedia.org/wiki/Open_Shortest_Path_First) routing protocol traffic. It tracks message types (Hello, DBD, LSR, LSU, LSAck), router IDs, area IDs, and neighbor relationships. Security teams can use this to detect unauthorized OSPF neighbors attempting to inject false routing information, which could redirect traffic or enable man-in-the-middle attacks.

#### Visualizations

* OSPF - All IP Addresses
* OSPF - Area and Router
* OSPF - Destination IP
* OSPF - Link State Advertisement
* OSPF - Link Type
* OSPF - Log Count
* OSPF - Log Count Over Time
* OSPF - Logs
* OSPF - Packet Type
* OSPF - Source IP


#### Fields

* `network.protocol_version`
* `zeek.ospf.area_id`
* `zeek.ospf.backup_router`
* `zeek.ospf.desig_router`
* `zeek.ospf.interface_id`
* `zeek.ospf.link_type`
* `zeek.ospf.lsa_type`
* `zeek.ospf.neighbors`
* `zeek.ospf.router_id`


---

### PostgreSQL

* ID: [f2c0da10-d2c5-11ef-8864-d58a560dc292](#/dashboard/f2c0da10-d2c5-11ef-8864-d58a560dc292)

The PostgreSQL dashboard covers [PostgreSQL](https://en.wikipedia.org/wiki/PostgreSQL) database protocol traffic, including connection metadata, command types, and host pairs. It provides visibility into who is accessing PostgreSQL instances and what types of operations they are performing. Analysts can detect unauthorized database access, unexpected client connections, and unusual query volumes that may indicate automated data extraction.

#### Visualizations

* PostgreSQL - Action and Results
* PostgreSQL - Application
* PostgreSQL - Database
* PostgreSQL - Destination IP
* PostgreSQL - Log Count
* PostgreSQL - Log Count Over Time
* PostgreSQL - Logs
* PostgreSQL - Source IP
* PostgreSQL - User


#### Fields

* `related.user`
* `zeek.postgresql.application_name`
* `zeek.postgresql.backend_arg`
* `zeek.postgresql.database`
* `zeek.postgresql.frontend_arg`
* `zeek.postgresql.rows`


---

### QUIC

* ID: [11ddd980-e388-11e9-b568-cf17de8e860c](#/dashboard/11ddd980-e388-11e9-b568-cf17de8e860c)

The QUIC dashboard provides visibility into [QUIC](https://en.wikipedia.org/wiki/QUIC#Google_QUIC_(gQUIC)) protocol traffic, a UDP-based transport used by modern HTTPS and HTTP/3 connections. It covers connection metadata, server names, versions, and host communication pairs. This dashboard is useful for tracking QUIC-based web traffic, identifying applications using QUIC, and detecting attempts to bypass inspection by tunneling traffic over QUIC.

#### Visualizations

* QUIC - CYU Fingerprint
* QUIC - Destination IP Address
* QUIC - Log Count
* QUIC - Log Count Over Time
* QUIC - Logs
* QUIC - Server Name
* QUIC - Source IP Address
* QUIC - User Agent
* QUIC - Version


#### Fields

* `quic.host`
* `quic.version`
* `user_agent.original`
* `zeek.gquic.cyu`
* `zeek.gquic.cyutags`


---

### RADIUS

* ID: [ae79b7d1-4281-4095-b2f6-fa7eafda9970](#/dashboard/ae79b7d1-4281-4095-b2f6-fa7eafda9970)

The RADIUS dashboard covers [Remote Authentication Dial-In User Service (RADIUS)](https://en.wikipedia.org/wiki/RADIUS) protocol traffic, tracking authentication requests, results, username attributes, and NAS identifiers. RADIUS is used for centralized network access authentication, and this dashboard helps detect brute-force attempts, authentication bypass, and rogue RADIUS clients. Analysts can correlate failed authentication spikes with specific NAS devices and usernames.

#### Visualizations

* RADIUS - Authentication Result
* RADIUS - Connection Information
* RADIUS - Destination IP Address
* RADIUS - Log Count
* RADIUS - Log Count Over Time
* RADIUS - Logs
* RADIUS - MAC
* RADIUS - Source IP Address
* RADIUS - Username


#### Fields

* `related.user`
* `zeek.radius.connect_info`
* `zeek.radius.framed_addr`
* `zeek.radius.mac`
* `zeek.radius.result`


---

### RDP

* ID: [7f41913f-cba8-43f5-82a8-241b7ead03e0](#/dashboard/7f41913f-cba8-43f5-82a8-241b7ead03e0)

The RDP dashboard covers [Remote Desktop Protocol (RDP)](https://en.wikipedia.org/wiki/Remote_Desktop_Protocol) sessions, including connection metadata, authentication outcomes, security protocols, and host certificates. It provides visibility into remote desktop usage and helps detect unauthorized remote access, brute-force attempts, and RDP-based lateral movement. This is a high-value dashboard during incident response when adversaries frequently leverage RDP for interactive access.

#### Visualizations

* RDP - Client Version
* RDP - Connections Tree
* RDP - Cookie
* RDP - Destination IP Address
* RDP - Encryption
* RDP - Keyboard Layout
* RDP - Log Count
* RDP - Log Count Over Time
* RDP - Logs
* RDP - Result
* RDP - Source IP Address


#### Fields

* `zeek.rdp.client_build`
* `zeek.rdp.cookie`
* `zeek.rdp.encryption_level`
* `zeek.rdp.encryption_method`
* `zeek.rdp.keyboard_layout`
* `zeek.rdp.result`
* `zeek.rdp.security_protocol`


---

### Redis

* ID: [ef0f9be0-7d3d-11f0-9ca7-8bfd0076f5c9](#/dashboard/ef0f9be0-7d3d-11f0-9ca7-8bfd0076f5c9)

The Redis dashboard covers [Redis](https://en.wikipedia.org/wiki/Redis) in-memory data store protocol traffic, including command types, return values, and communication pairs. Redis is commonly exposed unintentionally without authentication, making it a frequent target for unauthorized access and data manipulation. Analysts can use this dashboard to detect unexpected Redis clients, dangerous commands (FLUSHDB, CONFIG), and unauthorized access to cached data.

#### Visualizations

* Redis - Action and Result
* Redis - Destination
* Redis - Key
* Redis - Key and Value
* Redis - Log Count
* Redis - Logs
* Redis - Logs Over Time
* Redis - Source
* Redis - Success


#### Fields

* `zeek.redis.cmd_key`
* `zeek.redis.cmd_value`
* `zeek.redis.success`


---

### RFB

* ID: [f77bf097-18a8-465c-b634-eb2acc7a4f26](#/dashboard/f77bf097-18a8-465c-b634-eb2acc7a4f26)

The RFB dashboard covers [Remote Framebuffer (RFB)](https://en.wikipedia.org/wiki/RFB_protocol) protocol sessions (used by VNC), including desktop sharing connections, authentication types, and host pairs. It helps identify remote desktop activity outside of expected channels and detect unauthorized VNC access to internal systems. Analysts can use it to baseline legitimate VNC usage and flag unexpected desktop-sharing sessions.

#### Visualizations

* RFB - Authentication Method
* RFB - Authentication Status
* RFB - Client Version
* RFB - Desktop Name
* RFB - Destination IP Address
* RFB - Destination Port
* RFB - Exclusive Session
* RFB - Log Count
* RFB - Log Count Over Time
* RFB - Logs
* RFB - Server Version
* RFB - Source IP Address


#### Fields

* `zeek.rfb.auth`
* `zeek.rfb.authentication_method`
* `zeek.rfb.client_major_version`
* `zeek.rfb.client_minor_version`
* `zeek.rfb.desktop_name`
* `zeek.rfb.server_major_version`
* `zeek.rfb.server_minor_version`
* `zeek.rfb.share_flag`


---

### SIP

* ID: [0b2354ae-0fe9-4fd9-b156-1c3870e5c7aa](#/dashboard/0b2354ae-0fe9-4fd9-b156-1c3870e5c7aa)

The SIP dashboard covers [Session Initiation Protocol (SIP)](https://en.wikipedia.org/wiki/Session_Initiation_Protocol) traffic, including call setup, methods, response codes, user agents, and communication pairs. SIP is used for VoIP and unified communications and can be targeted for toll fraud, call hijacking, and reconnaissance of telephony infrastructure. Analysts can detect unusual SIP activity, rogue clients, high volumes of failed authentication, and unauthorized INVITE or REGISTER messages.

#### Visualizations

* SIP - Content Type
* SIP - Destination Country
* SIP - Destination IP Address
* SIP - Destination Port
* SIP - Log Count
* SIP - Log Count Over Time
* SIP - Logs
* SIP - Method
* SIP - Request Path
* SIP - Source IP Address
* SIP - Status
* SIP - URI
* SIP - User Agent


#### Fields

* `destination.geo.country_name`
* `user_agent.original`
* `zeek.sip.content_type`
* `zeek.sip.request_path`
* `zeek.sip.status_code`
* `zeek.sip.status_msg`
* `zeek.sip.uri`


---

### SMB

* ID: [42e831b9-41a9-4f35-8b7d-e1566d368773](#/dashboard/42e831b9-41a9-4f35-8b7d-e1566d368773)

The SMB dashboard provides visibility into [Server Message Block (SMB)](https://en.wikipedia.org/wiki/Server_Message_Block) protocol traffic, covering file sharing, named pipe operations, and authentication activity. It surfaces the commands used, files accessed, share names, and hosts involved in SMB communication. This is a critical dashboard for detecting lateral movement, credential relay attacks, and ransomware staging behavior that frequently leverages SMB.

#### Visualizations

* SMB - Destination IP Address
* SMB - Destination Port
* SMB - FIle Path
* SMB - File Name
* SMB - File/Path Summary
* SMB - Log Count
* SMB - Log Count Over Time
* SMB - Logs
* SMB - Relevant Notices
* SMB - Source IP Address
* SMB - Version
* SMB Action


#### Fields

* `network.protocol_version`
* `rule.category`
* `rule.name`
* `zeek.notice.msg`
* `zeek.smb_files.name`
* `zeek.smb_files.path`


---

### SMTP

* ID: [bb827f8e-639e-468c-93c8-9f5bc132eb8f](#/dashboard/bb827f8e-639e-468c-93c8-9f5bc132eb8f)

The SMTP dashboard covers [SMTP](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol) email traffic observed on the network. It tracks message senders, recipients, mail servers, attachment details, and transmission metadata. Analysts use it to investigate phishing activity, unauthorized mail relay, and unusual email flow patterns that could indicate account compromise or malware communication.

#### Visualizations

* SMTP  - Destination Country
* SMTP - "From" Address
* SMTP - "To" Address
* SMTP - Destination IP Address
* SMTP - Destination Port
* SMTP - Log Count
* SMTP - Log Count Over Time
* SMTP - Logs
* SMTP - Source IP Address
* SMTP - Subject
* SMTP - TLS
* SMTP - User Agent
* SMTP - Webmail


#### Fields

* `destination.geo.country_name`
* `user_agent.original`
* `zeek.smtp.is_webmail`
* `zeek.smtp.mailfrom`
* `zeek.smtp.rcptto`
* `zeek.smtp.subject`
* `zeek.smtp.tls`
* `zeek.smtp.x_originating_ip`


---

### SNMP

* ID: [4e5f106e-c60a-4226-8f64-d534abb912ab](#/dashboard/4e5f106e-c60a-4226-8f64-d534abb912ab)

The SNMP dashboard covers [Simple Network Management Protocol (SNMP)](https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol) traffic, including get/set operations, community strings (if visible), and managed device identifiers. It provides insight into network device monitoring activity and helps detect unauthorized SNMP polling, community string brute-forcing, and SNMP-based information gathering. Analysts can identify which hosts are querying network infrastructure devices and flag unexpected management traffic.

#### Visualizations

* SNMP - Community String
* SNMP - Destination IP Address
* SNMP - Log Count
* SNMP - Log Count Over Time
* SNMP - Logs
* SNMP - PDU Type
* SNMP - Session Duration
* SNMP - Source IP Address
* SNMP - Version and PDU Type


#### Fields

* `network.protocol_version`
* `zeek.snmp.community`
* `zeek.snmp.duration`
* `zeek.snmp.version`


---

### SSH

* ID: [caef3ade-d289-4d05-a511-149f3e97f238](#/dashboard/caef3ade-d289-4d05-a511-149f3e97f238)

The SSH dashboard tracks [Secure Shell (SSH)](https://en.wikipedia.org/wiki/Secure_Shell) sessions, covering connection counts, authentication outcomes, client and server versions, and geographic origins. It provides visibility into remote access activity and helps detect brute-force attempts, unauthorized access, and unusual geographic sources of SSH connections. Analysts can correlate version data to identify outdated SSH implementations that may be vulnerable.

#### Visualizations

* SSH - Client Algorithms
* SSH - Client/Server
* SSH - Connections Tree
* SSH - Destination IP Address
* SSH - HASSH Client Hash
* SSH - HASSH Server Hash
* SSH - Log Count
* SSH - Log Count Over Time
* SSH - Logs
* SSH - Server Algorithms
* SSH - Source IP Address
* SSH - Version
* SSH -Server


#### Fields

* `zeek.ssh.auth_success`
* `zeek.ssh.cipher_alg`
* `zeek.ssh.client`
* `zeek.ssh.hassh`
* `zeek.ssh.hasshAlgorithms`
* `zeek.ssh.hasshServer`
* `zeek.ssh.hasshServerAlgorithms`
* `zeek.ssh.mac_alg`
* `zeek.ssh.server`
* `zeek.ssh.sshka`
* `zeek.ssh.version`


---

### SSL

* ID: [7f77b58a-df3e-4cc2-b782-fd7f8bad8ffb](#/dashboard/7f77b58a-df3e-4cc2-b782-fd7f8bad8ffb)

The [SSL/TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) dashboard presents certificate and connection data from encrypted traffic observed on the network. It surfaces certificate subjects, issuers, validation errors, cipher suites, and TLS versions in use across the environment. Analysts can use it to identify self-signed or expired certificates, weak cipher usage, and potentially malicious use of encryption to hide command-and-control traffic.

#### Visualizations

* SSL - Certificate Fingerprint
* SSL - Connection Established
* SSL - Destination Address
* SSL - Destination Country
* SSL - Destination Port
* SSL - Elliptic Curve
* SSL - Log Count
* SSL - Log Count Over Time
* SSL - Logs
* SSL - Next Protocol
* SSL - Relevant Notices
* SSL - Server
* SSL - Source IP Address
* SSL - Validation Status
* SSL - Version


#### Fields

* `destination.geo.country_name`
* `event.freq_score_v1`
* `event.freq_score_v2`
* `rule.category`
* `rule.name`
* `zeek.notice.msg`
* `zeek.ssl.curve`
* `zeek.ssl.established`
* `zeek.ssl.next_protocol`
* `zeek.ssl.server_name`
* `zeek.ssl.sni_matches_cert`
* `zeek.ssl.ssl_history`
* `zeek.ssl.ssl_version`
* `zeek.ssl.validation_status`
* `zeek.x509.fingerprint`


---

### STUN

* ID: [fa477130-2b8a-11ec-a9f2-3911c8571bfd](#/dashboard/fa477130-2b8a-11ec-a9f2-3911c8571bfd)

The STUN dashboard covers [Session Traversal Utilities for NAT (STUN)](https://en.wikipedia.org/wiki/STUN) traffic, which is used by applications like WebRTC to establish peer-to-peer connections through firewalls. It tracks binding requests, responses, software identifiers, and communication pairs. Analysts can use this dashboard to identify applications using STUN-based NAT traversal and flag unexpected STUN traffic that may be used for covert communication channels.

#### Visualizations

* STUN - Action and Result
* STUN - Attribute Type
* STUN - Class
* STUN - Destination IP
* STUN - LAN
* STUN - Log Count
* STUN - Log Count Over Time
* STUN - Logs
* STUN - Method and Class
* STUN - Source IP
* STUN - WAN
* STUN NAT - Logs


#### Fields

* `zeek.stun.attr_type`
* `zeek.stun.class`
* `zeek.stun_nat.lan_addr`
* `zeek.stun_nat.wan_addr`
* `zeek.stun_nat.wan_port`


---

### Syslog

* ID: [92985909-dc29-4533-9e80-d3182a0ecf1d](#/dashboard/92985909-dc29-4533-9e80-d3182a0ecf1d)

*Syslog messages observed in network traffic*

The Syslog dashboard presents [syslog](https://en.wikipedia.org/wiki/Syslog) messages observed in network traffic, covering severity levels, facility codes, originating hosts, and message content summaries. It helps analysts understand what systems are forwarding log data, whether logging pipelines are functioning correctly, and whether any unusual error or critical syslog events are being generated. This dashboard is also useful for detecting log flooding, rogue syslog sources, and syslog-based data exfiltration.

#### Visualizations

* Syslog (Zeek) - Logs
* Syslog - Destination IP Address
* Syslog - Destination Port
* Syslog - Facility
* Syslog - Log Count
* Syslog - Log Count Over Time
* Syslog - Protocol
* Syslog - Severity
* Syslog - Source IP Address


#### Fields

* `zeek.syslog.facility`
* `zeek.syslog.message`
* `zeek.syslog.severity`


---

### Tabular Data Stream

* ID: [bed185a0-ef82-11e9-b38a-2db3ee640e88](#/dashboard/bed185a0-ef82-11e9-b38a-2db3ee640e88)

The Tabular Data Stream (TDS) dashboard covers [Microsoft SQL Server's Tabular Data Stream (TDS)](https://en.wikipedia.org/wiki/Tabular_Data_Stream) protocol traffic, including login metadata, query activity, and response codes. It provides visibility into database connections and helps detect unauthorized SQL Server access and unusual database activity. Analysts can identify which clients are connecting to SQL Server instances and detect patterns consistent with SQL injection or data exfiltration.

#### Visualizations

* Tabular Data Stream - All Logs
* Tabular Data Stream - Command
* Tabular Data Stream - Destination IP
* Tabular Data Stream - Log Count
* Tabular Data Stream - Log Count Over Time
* Tabular Data Stream - Source IP


#### Fields

* `zeek.tds.command`


---

### Tabular Data Stream - RPC

* ID: [32587740-ef88-11e9-b38a-2db3ee640e88](#/dashboard/32587740-ef88-11e9-b38a-2db3ee640e88)

The Tabular Data Stream - RPC dashboard focuses on remote procedure call operations within [Microsoft SQL Server's TDS](https://en.wikipedia.org/wiki/Tabular_Data_Stream) protocol traffic, including stored procedure execution and batch operations. It surfaces the RPC procedure names, parameters, and originating hosts, providing detailed insight into programmatic database interactions. Security teams can use this to detect unauthorized stored procedure execution and unusual RPC-based SQL Server communication.

#### Visualizations

* Tabular Data Stream - RPC Destination IP
* Tabular Data Stream - RPC Log Count
* Tabular Data Stream - RPC Log Count Over Time
* Tabular Data Stream - RPC Logs
* Tabular Data Stream - RPC Procedure
* Tabular Data Stream - RPC Source IP


#### Fields

* `zeek.tds_rpc.parameter`
* `zeek.tds_rpc.procedure_name`


---

### Tabular Data Stream - SQL

* ID: [fa141950-ef89-11e9-b38a-2db3ee640e88](#/dashboard/fa141950-ef89-11e9-b38a-2db3ee640e88)

The Tabular Data Stream - SQL dashboard focuses on the SQL statement activity within [Microsoft SQL Server's TDS](https://en.wikipedia.org/wiki/Tabular_Data_Stream) protocol traffic, capturing query text snippets, affected rows, and communication metadata. It provides a window into the types of SQL queries being executed against SQL Server instances. Analysts can use this to detect data harvesting queries, schema enumeration, and unauthorized or unusual SQL activity from unexpected clients.

#### Visualizations

* Tabular Data Stream - SQL Destination IP
* Tabular Data Stream - SQL Header Type
* Tabular Data Stream - SQL Log Count
* Tabular Data Stream - SQL Log Count Over Time
* Tabular Data Stream - SQL Logs
* Tabular Data Stream - SQL Query
* Tabular Data Stream - SQL Source IP


#### Fields

* `zeek.tds_sql_batch.header_type`
* `zeek.tds_sql_batch.query`


---

### Telnet, rlogin and rsh

* ID: [c2549e10-7f2e-11ea-9f8a-1fe1327e2cd2](#/dashboard/c2549e10-7f2e-11ea-9f8a-1fe1327e2cd2)

The Telnet, rlogin, and rsh dashboard covers legacy plaintext remote access protocols — [Telnet](https://en.wikipedia.org/wiki/Telnet), [rlogin, and rsh](https://en.wikipedia.org/wiki/Berkeley_r-commands) — providing visibility into unencrypted interactive sessions. These protocols transmit credentials and session data in cleartext, making them high-risk when observed on modern networks. Analysts can use this dashboard to identify legacy systems still using insecure remote access protocols and investigate any such sessions as potential security incidents.

#### Visualizations

* Telnet, rlogin and rsh - Destination
* Telnet, rlogin and rsh - Log Count
* Telnet, rlogin and rsh - Log Count Over Time
* Telnet, rlogin and rsh - Login Attempts with Cleartext Passwords
* Telnet, rlogin and rsh - Login Success
* Telnet, rlogin and rsh - Logs
* Telnet, rsh and rlogin - Source


#### Fields

* `related.user`
* `user`
* `zeek.login.client_user`
* `zeek.login.success`


---

### TFTP

* ID: [bf5efbb0-60f1-11eb-9d60-dbf0411cfc48](#/dashboard/bf5efbb0-60f1-11eb-9d60-dbf0411cfc48)

The TFTP dashboard covers [Trivial File Transfer Protocol (TFTP)](https://en.wikipedia.org/wiki/Trivial_File_Transfer_Protocol) traffic, including file names, transfer directions, block counts, and host pairs. TFTP is commonly used for network device firmware updates and PXE boot, but also frequently abused for unauthorized file transfers due to its lack of authentication. Analysts can detect unexpected TFTP activity, unauthorized firmware or configuration file transfers, and TFTP servers that should not be accessible.

#### Visualizations

* TFTP - Destination IP
* TFTP - Filename
* TFTP - Log Count
* TFTP - Log Count Over Time
* TFTP - Logs
* TFTP - Operation Results
* TFTP - Source IP
* TFTP - Transfer Mode


#### Fields

* `file.path`
* `zeek.tftp.mode`


---

### Tunnels

* ID: [11be6381-beef-40a7-bdce-88c5398392fc](#/dashboard/11be6381-beef-40a7-bdce-88c5398392fc)

The Tunnels dashboard provides visibility into network [tunneling](https://en.wikipedia.org/wiki/Tunneling_protocol) activity, covering protocols like GRE, IP-in-IP, and application-layer tunnels. It surfaces tunnel types, encapsulated protocols, and the hosts involved in tunneling activity. Analysts can use this to detect covert communication channels, VPN bypass attempts, and unauthorized encapsulation that may be used to hide malicious traffic.

#### Visualizations

* Tunnels - Action
* Tunnels - Country
* Tunnels - Destination Address
* Tunnels - Log Count
* Tunnels - Log Count Over Time
* Tunnels - Logs
* Tunnels - Source IP Address
* Tunnels - Type


#### Fields

* `destination.geo.country_name`
* `zeek.tunnel.action`
* `zeek.tunnel.tunnel_type`


---

### WebSocket

* ID: [b8cf5890-87ed-11ef-ae18-dbcd34795edb](#/dashboard/b8cf5890-87ed-11ef-ae18-dbcd34795edb)

The WebSocket dashboard covers [WebSocket](https://en.wikipedia.org/wiki/WebSocket) upgrade sessions and message traffic, tracking the web hosts, URIs, and connection patterns involved in persistent WebSocket connections. WebSocket connections are used by modern web applications for real-time communication and can also be abused for covert C2 channels. Analysts can use this dashboard to identify unexpected WebSocket usage and flag connections to suspicious or unauthorized endpoints.

#### Visualizations

* WebSocket - Client Extensions
* WebSocket - Destination IP
* WebSocket - Log Count
* WebSocket - Logs
* WebSocket - Logs Over Time
* WebSocket - Protocols
* WebSocket - Server Extensions
* WebSocket - Source IP
* WebSocket - URI
* WebSocket - User Agent Name


#### Fields

* `related.hosts`
* `url.original`
* `user_agent.name`
* `user_agent.original`
* `zeek.websocket.client_extensions`
* `zeek.websocket.client_protocols`
* `zeek.websocket.server_extensions`
* `zeek.websocket.subprotocol`


---

### X.509

* ID: [024062a6-48d6-498f-a91a-3bf2da3a3cd3](#/dashboard/024062a6-48d6-498f-a91a-3bf2da3a3cd3)

The X.509 dashboard focuses on certificate metadata extracted from TLS/SSL sessions, providing a detailed inventory of certificates seen on the network. It covers certificate subjects, issuers, signing algorithms, key lengths, and whether certificates are used for host or client authentication. This dashboard helps identify weak cryptographic configurations, expired or untrusted certificates, and certificate anomalies that may indicate impersonation or MitM attacks.

#### Visualizations

* OCSP - Certificate Revocation
* OCSP - Logs
* SSL - Relevant Notices
* X.509 - Certificate Fingerprint
* X.509 - Certificate Issuer
* X.509 - Certificate Key Algorithm
* X.509 - Certificate Key Length
* X.509 - Certificate Signing Algorithm
* X.509 - Certificate Subject
* X.509 - Is Client Certificate
* X.509 - Is Host Certificate
* X.509 - Log Count
* X.509 - Log Count Over Time
* X.509 - Logs


#### Fields

* `rule.category`
* `rule.name`
* `zeek.notice.msg`
* `zeek.ocsp.certStatus`
* `zeek.ocsp.nextUpdate`
* `zeek.ocsp.revokereason`
* `zeek.ocsp.revoketime`
* `zeek.ocsp.serialNumber`
* `zeek.ocsp.thisUpdate`
* `zeek.x509.certificate_issuer.CN`
* `zeek.x509.certificate_issuer_full`
* `zeek.x509.certificate_key_alg`
* `zeek.x509.certificate_key_length`
* `zeek.x509.certificate_sig_alg`
* `zeek.x509.certificate_subject.CN`
* `zeek.x509.certificate_subject_full`
* `zeek.x509.certificate_version`
* `zeek.x509.client_cert`
* `zeek.x509.fingerprint`
* `zeek.x509.host_cert`


---

## ICS/IoT Protocols

---

### ANSI C12.22

* ID: [db51fc00-673b-11f0-8230-37b935257dd0](#/dashboard/db51fc00-673b-11f0-8230-37b935257dd0)

*ANSI C12.22 visualizations*

The ANSI C12.22 dashboard covers the [ANSI C12.22](https://en.wikipedia.org/wiki/ANSI_C12.22) smart meter communication protocol traffic, used in advanced metering infrastructure (AMI) and utility environments. It surfaces service types, device identifiers, table data access, and communication pairs between meters and head-end systems. Analysts monitoring utility networks can use this dashboard to detect unauthorized meter access, data manipulation, and rogue devices communicating on the AMI network.

#### Visualizations

* C12.22 - AP Titles
* C12.22 - Actions
* C12.22 - Destination IPs
* C12.22 - EPSEM Services
* C12.22 - Log Count
* C12.22 - Logs
* C12.22 - Logs Over Time
* C12.22 - Results
* C12.22 - Service Error Logs
* C12.22 - Source IPs
* C12.22 - Transport Protocol
* C12.22 - User Information Logs
* C12.22 - Users
* C12.22 - Users and Passwords
* C12.22 and Related - Logs


#### Fields

* `related.password`
* `related.user`
* `zeek.c1222.ap_title`
* `zeek.c1222.called_ap_invocation_id`
* `zeek.c1222.called_ap_title`
* `zeek.c1222.calling_ap_invocation_id`
* `zeek.c1222.calling_ap_title`
* `zeek.c1222.calling_auth_value`
* `zeek.c1222.elements`
* `zeek.c1222.epsem_service`
* `zeek.c1222.is_encrypted_epsem`
* `zeek.c1222.req_resp`
* `zeek.c1222_user_information.encrypted_epsem`
* `zeek.c1222_user_information.epsem_control`
* `zeek.c1222_user_information.mac`


---

### BACnet

* ID: [2bec1490-eb94-11e9-a384-0fcf32210194](#/dashboard/2bec1490-eb94-11e9-a384-0fcf32210194)

*Dashboard for the BACnet (Building Automation and Control Networks) Protocol*

The BACnet dashboard covers [Building Automation and Control network (BACnet)](https://en.wikipedia.org/wiki/BACnet) protocol traffic, targeting building management systems. It tracks service types, instance numbers, vendor IDs, object identifiers, and device communication patterns. Analysts and building automation security teams can use this dashboard to detect unauthorized access to HVAC, lighting, and physical access control systems.

#### Visualizations

* ATT&CK for ICS Notices - BACnet
* ATT&CK for ICS Tactic - BACnet
* BACnet  - Read and Write Property
* BACnet - Actions and Results
* BACnet - BVLC Functions
* BACnet - Destination IP
* BACnet - Device Discovery
* BACnet - Device Vendors
* BACnet - Discovery Logs
* BACnet - Log Count
* BACnet - Logs
* BACnet - Logs Over Time
* BACnet - Property Logs
* BACnet - Protocol Data Units (PDUs)
* BACnet - Source IP
* BACnet - Trends
* BACnet Device Control - Logs


#### Fields

* `threat.tactic.name`
* `threat.technique.name`
* `zeek.bacnet.bvlc_function`
* `zeek.bacnet.instance_number`
* `zeek.bacnet.invoke_id`
* `zeek.bacnet.pdu_service`
* `zeek.bacnet.pdu_type`
* `zeek.bacnet_discovery.object_type`
* `zeek.bacnet_discovery.vendor`
* `zeek.bacnet_property.object_type`
* `zeek.bacnet_property.property`
* `zeek.bacnet_property.value`
* `zeek.notice.msg`


---

### BSAP

* ID: [ca5799a0-56b5-11eb-b749-576de068f8ad](#/dashboard/ca5799a0-56b5-11eb-b749-576de068f8ad)

The BSAP dashboard covers [Bristol Standard Asynchronous Protocol (BSAP)](https://en.wikipedia.org/wiki/Bristol_Standard_Asynchronous_Protocol) traffic used in ABB and Bristol Babcock control systems, common in oil and gas and chemical process environments. It logs function codes, device addresses, and communication pairs observed on the network. Security teams can use this dashboard to detect unauthorized commands to BSAP-enabled field devices and monitor for unexpected communication sources.

#### Visualizations

* BSAP - Destination IP
* BSAP - Log Count
* BSAP - Logs Over Time
* BSAP - Source IP
* BSAP - Transport
* BSAP IP - Function
* BSAP IP - Logs
* BSAP Serial - Function
* BSAP Serial - Logs
* BSAP Serial - RDB Function


#### Fields

* `zeek.bsap_ip_rdb.app_func_code`
* `zeek.bsap_ip_rdb.func_code`
* `zeek.bsap_ip_rdb.node_status`
* `zeek.bsap_ip_rdb.variable_count`
* `zeek.bsap_ip_rdb.variables`
* `zeek.bsap_serial_header.dfun`
* `zeek.bsap_serial_header.nsb`
* `zeek.bsap_serial_header.sfun`
* `zeek.bsap_serial_header.type_name`
* `zeek.bsap_serial_rdb.func_code`
* `zeek.bsap_serial_rdb.variable_count`
* `zeek.bsap_serial_rdb.variables`


---

### DNP3

* ID: [870a5862-6c26-4a08-99fd-0c06cda85ba3](#/dashboard/870a5862-6c26-4a08-99fd-0c06cda85ba3)

*Dashboard for the DNP3 Protocol*

The DNP3 dashboard covers [Distributed Network Protocol 3 (DNP3)](https://en.wikipedia.org/wiki/DNP3) traffic, a common ICS protocol used in electric utility and water treatment environments. It surfaces function codes, object headers, master and outstation addresses, and request/response patterns observed on the network. This dashboard helps security and operations teams detect command injection, unauthorized polling, and anomalous DNP3 traffic that may indicate unauthorized access to field devices.

#### Visualizations

* DNP3 - Control Logs
* DNP3 - Control Overview
* DNP3 - Destination IP
* DNP3 - Function Reply
* DNP3 - Function Request
* DNP3 - Internal Indicators Overview
* DNP3 - Log Count
* DNP3 - Logs
* DNP3 - Logs Over Time
* DNP3 - Objects Logs
* DNP3 - Objects Overview
* DNP3 - Source IP
* DNP3 - Trends


#### Fields

* `zeek.dnp3.fc_reply`
* `zeek.dnp3.iin_flags`
* `zeek.dnp3_control.block_type`
* `zeek.dnp3_control.clear_bit`
* `zeek.dnp3_control.function_code`
* `zeek.dnp3_control.index_number`
* `zeek.dnp3_control.operation_type`
* `zeek.dnp3_control.status_code`
* `zeek.dnp3_control.trip_control_code`
* `zeek.dnp3_objects.object_count`
* `zeek.dnp3_objects.object_type`
* `zeek.dnp3_objects.range_high`
* `zeek.dnp3_objects.range_low`


---

### EtherCAT

* ID: [4a073440-b286-11eb-a4d4-09fa12a6ebd4](#/dashboard/4a073440-b286-11eb-a4d4-09fa12a6ebd4)

The EtherCAT dashboard provides visibility into [EtherCAT](https://en.wikipedia.org/wiki/EtherCAT) industrial Ethernet traffic, used in high-speed motion control and automation systems. It captures command types, server addresses, working counters, and communication patterns between client and server devices. This dashboard is useful for detecting anomalous EtherCAT traffic that could indicate device tampering or unauthorized access to automation equipment.

#### Visualizations

* EtherCAT - Commands
* EtherCAT - Destination
* EtherCAT - Log Count
* EtherCAT - Log Count Over Time
* EtherCAT - Register Types and Commands
* EtherCAT - Source
* EtherCAT Registers - Logs
* Logs - EtherCAT


#### Fields

* `destination.mac`
* `destination.oui`
* `source.mac`
* `source.oui`
* `zeek.ecat_registers.register_addr`
* `zeek.ecat_registers.register_type`
* `zeek.ecat_registers.server_addr`


---

### EtherNet/IP

* ID: [29a1b290-eb98-11e9-a384-0fcf32210194](#/dashboard/29a1b290-eb98-11e9-a384-0fcf32210194)

*Dashboard for Ethernet/IP and CIP Protocols*

The EtherNet/IP dashboard covers [EtherNet/IP](https://en.wikipedia.org/wiki/EtherNet/IP) and [Common Industrial Protocol (CIP)](https://en.wikipedia.org/wiki/Common_Industrial_Protocol) traffic, which is widely used in manufacturing and process control environments. It surfaces CIP service codes, class and instance identifiers, device identity data, and communication pairs. Security teams can use this to monitor for unauthorized PLC access, unusual CIP commands, and unexpected EtherNet/IP device discovery activity.

#### Visualizations

* ATT&CK for ICS Notices - EtherNet/IP and CIP
* ATT&CK for ICS Tactic - EtherNet/IP and CIP
* CIP - Device Identity
* CIP - IO Logs
* CIP - Identity Logs
* CIP - Logs
* CIP - Services
* EtherNet/IP -  Detailed Information
* EtherNet/IP - Destination IP
* EtherNet/IP - Log Count
* EtherNet/IP - Logs Over Time
* EtherNet/IP - Source IP
* Ethernet/IP - Commands
* Ethernet/IP - Logs


#### Fields

* `threat.tactic.name`
* `threat.technique.name`
* `zeek.cip.cip_sequence_count`
* `zeek.cip.class_id`
* `zeek.cip.class_name`
* `zeek.cip.direction`
* `zeek.cip.instance_id`
* `zeek.cip.packet_correlation_id`
* `zeek.cip_identity.device_type_name`
* `zeek.cip_identity.product_name`
* `zeek.cip_identity.revision`
* `zeek.cip_identity.serial_number`
* `zeek.cip_identity.vendor_name`
* `zeek.cip_io.connection_id`
* `zeek.cip_io.data_length`
* `zeek.cip_io.sequence_number`
* `zeek.enip.length`
* `zeek.enip.options`
* `zeek.enip.sender_context`
* `zeek.enip.session_handle`
* `zeek.notice.msg`


---

### GE SRTP

* ID: [e233a570-45d9-11ef-96a6-432365601033](#/dashboard/e233a570-45d9-11ef-96a6-432365601033)

*Dashboard for the GE SRTP Protocol*

The GE SRTP dashboard covers the [GE Service Request Transport Protocol (SRTP)](https://en.wikipedia.org/wiki/Service_Request_Transport_Protocol), used to communicate with GE PLCs and automation devices. It captures service request types, memory area access, sequence numbers, and communication pairs. Security teams can use this to detect unauthorized reads or writes to GE PLC memory areas, which could indicate ICS-targeted attacks or insider threats.

#### Visualizations

* GE SRTP - Actions and Results
* GE SRTP - Constant Sweep Mode
* GE SRTP - Destination IP
* GE SRTP - I/O Fault Entry Present
* GE SRTP - I/O Fault Table Changed
* GE SRTP - Log Count
* GE SRTP - Logs
* GE SRTP - Logs Over Time
* GE SRTP - OEM Protection
* GE SRTP - Oversweep Flag
* GE SRTP - PLC Fault Entry Present
* GE SRTP - PLC Fault Table Changed
* GE SRTP - PLC State
* GE SRTP - Panel Enable Switch
* GE SRTP - Panel Run Switch
* GE SRTP - Programmer Attachment
* GE SRTP - Source IP


#### Fields

* `zeek.ge_srtp.constant_sweep_mode`
* `zeek.ge_srtp.data_length`
* `zeek.ge_srtp.front_panel_enable_switch`
* `zeek.ge_srtp.front_panel_run_switch`
* `zeek.ge_srtp.io_fault_entry_last_read`
* `zeek.ge_srtp.io_fault_entry_present`
* `zeek.ge_srtp.memory_offset`
* `zeek.ge_srtp.oem_protected`
* `zeek.ge_srtp.oversweep_flag`
* `zeek.ge_srtp.packet_number`
* `zeek.ge_srtp.plc_fault_entry_last_read`
* `zeek.ge_srtp.plc_fault_entry_present`
* `zeek.ge_srtp.plc_state`
* `zeek.ge_srtp.programmer_attachment`
* `zeek.ge_srtp.segment_selector`
* `zeek.ge_srtp.sequence_number_1`
* `zeek.ge_srtp.sequence_number_2`
* `zeek.ge_srtp.srtp_type`
* `zeek.ge_srtp.total_packet_number`


---

### GENISYS

* ID: [03207c00-d07e-11ec-b4a7-d1b4003706b7](#/dashboard/03207c00-d07e-11ec-b4a7-d1b4003706b7)

*Dashboard for the GENISYS Protocol*

The GENISYS dashboard covers network traffic for the [GENISYS](https://manualzz.com/doc/6363274/genisys-2000---ansaldo-sts---product-support#93) industrial protocol. It tracks source and destination communication pairs, station addresses, operation directions, and event results. This dashboard gives operators and security teams visibility into GENISYS device communication and helps detect anomalous commands or unexpected participants in protocol exchanges.

#### Visualizations

* GENISYS - Action
* GENISYS - Destination
* GENISYS - Log Count
* GENISYS - Log Count Over Time
* GENISYS - Logs
* GENISYS - Message Direction
* GENISYS - Result
* GENISYS - Source
* GENISYS - Station Address


#### Fields

* `zeek.genisys.direction`
* `zeek.genisys.payload`
* `zeek.genisys.server`


---

### HART-IP

* ID: [3a9e3440-75e2-11ef-8138-03748f839a49](#/dashboard/3a9e3440-75e2-11ef-8138-03748f839a49)

The HART-IP dashboard covers [Highway Addressable Remote Transducer (HART)](https://en.wikipedia.org/wiki/Highway_Addressable_Remote_Transducer_Protocol) over IP traffic, used to communicate with smart field instruments in process control environments. It logs command codes, device addresses, response codes, and communication participants. Security teams monitoring process control networks can use this to detect unauthorized read or write commands to smart sensors and field devices.

#### Visualizations

* Audit Log Insecure Syslog Connection
* Configuration Changed (Direct PDU)
* Configuration Changed (Token Passing PDU)
* Critical Power Failure
* Device Malfunction (Direct PDU)
* Device Malfunction (Token Passing PDU)
* Device Variable Alert
* Failure
* Function Check
* HART-IP - Actions and Results
* HART-IP - Destination IP
* HART-IP - Logs
* HART-IP - Logs Count
* HART-IP - Logs Over Time
* HART-IP - PDU Command
* HART-IP - Source IP
* HART-IP - Universal Commands Device Profile and Type
* HART-IP - Universal Commands Message and Response
* Header Version
* Insecure Session
* Maintenance Required
* Out of Specification
* Protocol Major Revision
* Session Summary: Writes Occurred


#### Fields

* `zeek.hart_ip.direct_pdu_device_status_configuration_changed`
* `zeek.hart_ip.direct_pdu_device_status_device_malfunction`
* `zeek.hart_ip.direct_pdu_extended_status_critical_power_failure`
* `zeek.hart_ip.direct_pdu_extended_status_device_variable_alert`
* `zeek.hart_ip.direct_pdu_extended_status_failure`
* `zeek.hart_ip.direct_pdu_extended_status_function_check`
* `zeek.hart_ip.direct_pdu_extended_status_maintenance_required`
* `zeek.hart_ip.direct_pdu_extended_status_out_of_specification`
* `zeek.hart_ip.header_sequence_number`
* `zeek.hart_ip.header_version`
* `zeek.hart_ip.read_audit_log_server_status_insecure_syslog_connection`
* `zeek.hart_ip.token_passing_pdu_command_number`
* `zeek.hart_ip.token_passing_pdu_contents_response_device_status_configuration_changed`
* `zeek.hart_ip.token_passing_pdu_contents_response_device_status_device_malfunction`
* `zeek.hart_ip_session_record.session_log_record_session_status_summary_insecure_session`
* `zeek.hart_ip_session_record.session_log_record_session_status_summary_writes_occurred`
* `zeek.hart_ip_universal_commands.read_message_response_message`
* `zeek.hart_ip_universal_commands.read_unique_identifier_response_device_profile`
* `zeek.hart_ip_universal_commands.read_unique_identifier_response_expanded_device_type`
* `zeek.hart_ip_universal_commands.read_unique_identifier_response_hart_protocol_major_revision`
* `zeek.hart_ip_universal_commands.write_message_message_string`


---

### ICS Best Guess

* ID: [12e3a130-d83b-11eb-a0b0-f328ce09b0b7](#/dashboard/12e3a130-d83b-11eb-a0b0-f328ce09b0b7)

The ICS Best Guess dashboard surfaces connections that exhibit characteristics consistent with industrial control system (ICS) or operational technology (OT) protocols, even when not definitively identified. It flags traffic that heuristically resembles ICS protocols based on port, behavior, and tagging logic. This dashboard is a useful tool for discovering shadow ICS/OT devices or unrecognized protocols in environments where all OT traffic should be accounted for.

#### Visualizations

* Best Guess - Category
* Best Guess - Log Count
* Best Guess - Log Count Over Time
* Best Guess - Logs
* Best Guess - Summary
* Best Guess Protocol - Destination
* Best Guess Protocol - Source


#### Fields

* `protocol`
* `zeek.bestguess.category`
* `zeek.bestguess.name`


---

### ICS/IoT Security Overview

* ID: [4a4bde20-4760-11ea-949c-bbb5a9feecbf](#/dashboard/4a4bde20-4760-11ea-949c-bbb5a9feecbf)

The ICS/IoT Security Overview dashboard aggregates security-relevant data specific to industrial control and IoT network traffic. It presents ICS log volumes, protocol distribution, external connectivity, ATT&CK for ICS tactic mapping, and unusual actions or results. Security teams use it to monitor the risk posture of OT/ICS environments and quickly surface tactics or techniques that map to known ICS attack patterns.

#### Visualizations

* ACID on ATT&CK for ICS
* ATT&CK for ICS Tactic
* ICS Tactics and Techniques
* ICS/IoT Actions and Results
* ICS/IoT Destination IP
* ICS/IoT External Traffic
* ICS/IoT Log Counts
* ICS/IoT Logs
* ICS/IoT Source IP
* ICS/IoT Traffic Over Time
* Network Layer


#### Fields

* `destination.geo.country_name`
* `network.bytes`
* `rule.category`
* `source.geo.country_name`
* `threat.tactic.name`
* `threat.technique.name`
* `zeek.notice.msg`


---

### Modbus

* ID: [152f29dc-51a2-4f53-93e9-6e92765567b8](#/dashboard/152f29dc-51a2-4f53-93e9-6e92765567b8)

*Dashboard for the Modbus Protocol*

The Modbus dashboard provides visibility into [Modbus](https://en.wikipedia.org/wiki/Modbus) industrial protocol traffic, covering function codes, register addresses, unit identifiers, and host communication pairs. Modbus is widely used in SCADA and ICS environments for controlling field devices, making this dashboard critical for OT security monitoring. Analysts can detect unauthorized commands, unusual function codes, and communication with unexpected Modbus devices.

#### Visualizations

* Modbus - Destination IP
* Modbus - Detailed
* Modbus - Device Identification Objects
* Modbus - Functions and Exceptions
* Modbus - Log Count
* Modbus - Logs
* Modbus - Logs Over Time
* Modbus - Mask Write
* Modbus - Observed Client/Server Ratio
* Modbus - Observed Clients and Servers
* Modbus - Read Device Identification
* Modbus - Read Write Multiple
* Modbus - Reads
* Modbus - Request and Response
* Modbus - Source IP
* Modbus - Transport
* Modbus - Trends
* Modbus - Writes


#### Fields

* `network.bytes`
* `zeek.known_modbus.device_type`
* `zeek.modbus.network_direction`
* `zeek.modbus.trans_id`
* `zeek.modbus.unit_id`
* `zeek.modbus_detailed.address`
* `zeek.modbus_detailed.link_id`
* `zeek.modbus_detailed.matched`
* `zeek.modbus_detailed.quantity`
* `zeek.modbus_detailed.request_values`
* `zeek.modbus_detailed.response_values`
* `zeek.modbus_mask_write_register.and_mask`
* `zeek.modbus_mask_write_register.or_mask`
* `zeek.modbus_read_device_identification.conformity_level`
* `zeek.modbus_read_device_identification.device_id_code`
* `zeek.modbus_read_device_identification.object_id`
* `zeek.modbus_read_device_identification.object_value`
* `zeek.modbus_read_write_multiple_registers.read_registers`
* `zeek.modbus_read_write_multiple_registers.read_start_address`
* `zeek.modbus_read_write_multiple_registers.write_registers`
* `zeek.modbus_read_write_multiple_registers.write_start_address`


---

### Omron FINS

* ID: [c899f8b0-d36b-11ef-b619-17836b3bbf47](#/dashboard/c899f8b0-d36b-11ef-b619-17836b3bbf47)

The Omron FINS dashboard provides visibility into the [Factory Interface Network Service (FINS)](https://en.wikipedia.org/wiki/Factory_Interface_Network_Service) protocol used by Omron PLCs and automation equipment. It tracks command codes, memory area designations, unit addresses, and source/destination host pairs. This dashboard is useful for detecting unauthorized command execution against Omron controllers, including memory reads, writes, and PLC status queries.

#### Visualizations

* Omron FINS - Action and Result
* Omron FINS - Address, Node, and Unit
* Omron FINS - All Logs
* Omron FINS - Controller Model and Version
* Omron FINS - Data Type
* Omron FINS - Destination IP
* Omron FINS - Files/Volumes
* Omron FINS - Log Counts
* Omron FINS - Logs Over Time
* Omron FINS - Source IP
* Omron FINS - Transport Protocol


#### Fields

* `file.path`
* `zeek.omron_fins.destination_network_address`
* `zeek.omron_fins.destination_node_number`
* `zeek.omron_fins.destination_unit_address`
* `zeek.omron_fins.icf_data_type`
* `zeek.omron_fins.link_id`
* `zeek.omron_fins.service_id`
* `zeek.omron_fins.source_network_address`
* `zeek.omron_fins.source_node_number`
* `zeek.omron_fins.source_unit_address`
* `zeek.omron_fins_detail.controller_model`
* `zeek.omron_fins_detail.controller_version`


---

### OPCUA Binary

* ID: [dd87edd0-796a-11ec-9ce6-b395c1ff58f4](#/dashboard/dd87edd0-796a-11ec-9ce6-b395c1ff58f4)

The OPC UA Binary dashboard covers [OPC Unified Architecture (OPC UA)](https://en.wikipedia.org/wiki/OPC_Unified_Architecture) binary protocol traffic, the modern standard for industrial data exchange between PLCs, SCADA systems, and enterprise applications. It captures service types, node IDs, security policy, and communication pairs observed on the network. Analysts can use this to detect unauthorized OPC UA connections, unusual browsing or write operations, and unexpected cross-zone OPC UA traffic.

#### Visualizations

* OPCUA Binary - Actions
* OPCUA Binary - Destination
* OPCUA Binary - Log Count
* OPCUA Binary - Logs
* OPCUA Binary - Password Count
* OPCUA Binary - Protocol Version
* OPCUA Binary - Results
* OPCUA Binary - Software
* OPCUA Binary - Source
* OPCUA Binary - Traffic Over Time
* OPCUA Binary - URLs and URIs
* OPCUA Binary - User
* OPCUA Binary and Related - Logs


#### Fields

* `network.protocol_version`
* `related.password`
* `related.user`
* `url.original`
* `zeek.opcua_binary.opcua_link_id`
* `zeek.software.name`


---

### PROFINET

* ID: [a7514350-eba6-11e9-a384-0fcf32210194](#/dashboard/a7514350-eba6-11e9-a384-0fcf32210194)

The PROFINET dashboard covers [PROFINET](https://en.wikipedia.org/wiki/PROFINET) industrial communication protocol traffic, commonly used in manufacturing automation with Siemens and other ICS vendors. It tracks DCP (Discovery and Configuration Protocol), IO (real-time I/O), and DCE/RPC sub-protocol activity between PLCs, HMIs, and I/O devices. Security teams use it to detect unauthorized device discovery, configuration changes, and unusual PROFINET communication patterns.

#### Visualizations

* PROFINET - Destination IP
* PROFINET - Log Count
* PROFINET - Logs Over Time
* PROFINET - Operation
* PROFINET - Operation Details
* PROFINET - Source IP
* PROFINET I/O CM - Logs
* PROFINET I/O CM - Operation
* PROFINET and Related - Logs


#### Fields

* `network.protocol_version`
* `zeek.profinet.block_version`
* `zeek.profinet.index`
* `zeek.profinet.operation_type`
* `zeek.profinet.slot_number`
* `zeek.profinet.subslot_number`
* `zeek.profinet_io_cm.operation`
* `zeek.profinet_io_cm.packet_type`
* `zeek.profinet_io_cm.sequence_num`


---

### ROC Plus

* ID: [cbf2e4d0-29e8-11f0-862c-2dfee4f08125](#/dashboard/cbf2e4d0-29e8-11f0-862c-2dfee4f08125)

The ROC Plus dashboard covers the Emerson [ROC Plus](https://www.emerson.com/documents/automation/roc-plus-protocol-specification-manual-en-6851618.pdf) protocol traffic used to communicate with remote operations controllers commonly found in oil and gas environments. It logs parameter group and logic numbers, operation types, and communication participants. Security teams can use this dashboard to detect unauthorized reads or writes to ROC devices and monitor for unexpected communication patterns in pipeline control systems.

#### Visualizations

* ROC Plus - Action
* ROC Plus - All Logs
* ROC Plus - Destination IP
* ROC Plus - File Transfer Directory
* ROC Plus - File Transfer Filename
* ROC Plus - Log Types
* ROC Plus - Packet Size
* ROC Plus - Result
* ROC Plus - Source IP
* ROC Plus - Traffic Over Time
* ROC Plus - Transport Protocol


#### Fields

* `file.directory`
* `file.name`
* `network.bytes`
* `zeek.roc_plus.link_id`
* `zeek.roc_plus.packet_type`


---

### S7comm / S7comm Plus

* ID: [e76d05c0-eb9f-11e9-a384-0fcf32210194](#/dashboard/e76d05c0-eb9f-11e9-a384-0fcf32210194)

The S7comm dashboard provides visibility into [Siemens S7 protocol (S7comm)](https://wiki.wireshark.org/S7comm) communication used to program and control Siemens PLCs, a frequent target in ICS attacks. It surfaces function codes, block types, CPU data, and communication pairs between engineering stations and PLCs. This is a critical dashboard for detecting unauthorized PLC programming, reading of sensitive memory areas, and reconnaissance against Siemens control systems.

#### Visualizations

* ATT&CK for ICS Notices - S7comm
* ATT&CK for ICS Tactic - S7comm
* S7comm - Log Count
* S7comm - Logs Over Time
* S7comm - Upload/Download File Names
* S7comm Destination IP
* S7comm Devices
* S7comm Operations
* S7comm Plus Version
* S7comm Read-SZL
* S7comm Source IP
* S7comm and Related - Logs


#### Fields

* `file.path`
* `network.protocol_version`
* `threat.tactic.name`
* `threat.technique.name`
* `zeek.notice.msg`
* `zeek.s7comm.pdu_reference`
* `zeek.s7comm_known_devices.automation_system_name`
* `zeek.s7comm_known_devices.module_name`
* `zeek.s7comm_known_devices.module_serial`
* `zeek.s7comm_known_devices.plant_name`
* `zeek.s7comm_read_szl.method`
* `zeek.s7comm_read_szl.szl_index`
* `zeek.s7comm_upload_download.block_type`
* `zeek.s7comm_upload_download.destination_filesystem`


---

### Synchrophasor

* ID: [2cc56240-e460-11ed-a9d5-9f591c284cb4](#/dashboard/2cc56240-e460-11ed-a9d5-9f591c284cb4)

*Dashboard for the DNP3 Protocol*

The Synchrophasor dashboard covers [IEEE C37.118](https://en.wikipedia.org/wiki/C37.118) synchrophasor protocol traffic used in electric grid monitoring and wide-area measurement systems (WAMS). It tracks frame types (data, header, configuration, command), PMU identifiers, data rates, and communication participants. Grid operators and security teams can use this to detect unauthorized access to phasor measurement units and anomalous configuration or command frames.

#### Visualizations

* Synchrophasor - Action
* Synchrophasor - Analog Channels
* Synchrophasor - Data Modified
* Synchrophasor - Destination
* Synchrophasor - Digital Channels
* Synchrophasor - Frame Types
* Synchrophasor - Frequency Deviation From Nominal Over Time
* Synchrophasor - Log Count
* Synchrophasor - Log Count Over Time
* Synchrophasor - Logs
* Synchrophasor - Phasors
* Synchrophasor - Rate of Change of Frequency Over Time
* Synchrophasor - Source
* Synchrophasor - Stations
* Synchrophasor - Transport
* Synchrophasor and Related - Logs


#### Fields

* `network.protocol_version`
* `totDataBytes`
* `zeek.synchrophasor.data_frame_count`
* `zeek.synchrophasor.data_rate`
* `zeek.synchrophasor.data_stream_id`
* `zeek.synchrophasor.frame_size_tot`
* `zeek.synchrophasor.frame_type`
* `zeek.synchrophasor.history`
* `zeek.synchrophasor_cfg_detail.annam`
* `zeek.synchrophasor_cfg_detail.dgnam`
* `zeek.synchrophasor_cfg_detail.phnam`
* `zeek.synchrophasor_cfg_detail.station_name`
* `zeek.synchrophasor_data_detail.data_modified`
* `zeek.synchrophasor_data_detail.freq_dev_mhz`
* `zeek.synchrophasor_data_detail.rocof`


---
