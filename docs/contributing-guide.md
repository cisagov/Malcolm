# Malcolm Contributor Guide

The purpose of this document is to provide some direction for those willing to modify Malcolm, whether for local customization or for contribution to the Malcolm project.

It is recommended before reviewing this guide to read the documentation on [custom rules and scripts](custom-rules.md#CustomRulesAndScripts), which outlines customizations that can be made to the behavior of Suricata, Zeek, and YARA.

<a name="ContribTableOfContents"></a>
* [Local modifications](contributing-local-modifications.md#LocalMods)
    + [Volume bind mounts](contributing-local-modifications.md#Bind)
    + [Building Malcolm's images](contributing-local-modifications.md#ContribBuild)
* [Adding a new service (image)](contributing-new-image.md#NewImage)
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
* [Using GitHub runners to build Malcolm images](contributing-github-runners.md#GitHubRunners)
* [Preparing a Malcolm Release](contributing-release-prep.md)
* [Malcolm code provenance and software supply chain](contributing-guide-code-provenance.md)
* [`malcolm-test`: Malcolm System Tests](contributing-malcolm-test.md#MalcolmTest)