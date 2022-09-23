# Malcolm Contributor Guide

The purpose of this document is to provide some direction for those willing to modify Malcolm, whether for local customization or for contribution to the Malcolm project.

<a name="ContribTableOfContents"></a>
* [Local modifications](contributing-local-modifications.md#LocalMods)
    + [Docker bind mounts](contributing-local-modifications.md#Bind)
    + [Building Malcolm's Docker images](contributing-local-modifications.md#ContribBuild)
* [Adding a new service (Docker image)](contributing-new-image.md#NewImage)
    + [Networking and firewall](contributing-new-image.md#NewImageFirewall)
* [Adding new log fields](contributing-new-log-fields.md#NewFields)
- [Zeek](contributing-zeek.md#Zeek)
    + [`local.zeek`](contributing-zeek.md#LocalZeek)
    + [Adding a new Zeek package](contributing-zeek.md#ZeekPackage)
    + [Zeek Intelligence Framework](contributing-zeek.md#ContributingZeekIntel)
* [PCAP processors](contributing-pcap.md#PCAP)
* [Logstash](contributing-logstash.md#Logstash)
    + [Parsing a new log data source](contributing-logstash.md#LogstashNewSource)
    + [Parsing new Zeek logs](contributing-logstash.md#LogstashZeek)
    + [Enrichments](contributing-logstash.md#LogstashEnrichments)
    + [Logstash plugins](contributing-logstash.md#LogstashPlugins)
* [OpenSearch Dashboards](contributing-dashboards.md#dashboards)
    + [Adding new visualizations and dashboards](contributing-dashboards.md#DashboardsNewViz)
    + [OpenSearch Dashboards plugins](contributing-dashboards.md#DashboardsPlugins)
* [Carved file scanners](contributing-file-scanners.md#Scanners)
* [Style](contributing-style.md#Style)
