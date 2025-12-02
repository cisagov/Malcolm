# General Overview

[Malcolm]({{ site.github.repository_url }}) is a powerful network traffic analysis tool suite designed with the following goals in mind:

* **Easy to use** – Malcolm accepts network traffic data in the form of full packet capture (PCAP) files, Zeek logs, and Suricata alerts. These artifacts can be uploaded via a simple browser-based interface or passively captured live and forwarded to Malcolm using lightweight forwarders. In either case, the data is automatically normalized, enriched, and correlated for analysis.
* **Powerful traffic analysis** – Visibility into network communications is provided through two intuitive interfaces: OpenSearch Dashboards, a flexible data visualization plugin with dozens of prebuilt dashboards providing an at-a-glance overview of network protocols; and Arkime, a powerful tool for finding and identifying the network sessions comprising suspected security incidents.
* **Streamlined deployment** – Malcolm operates as a cluster of software containers – isolated sandboxes that each serve a dedicated function of the system. This container-based deployment model, combined with a few simple scripts for setup and run-time management, makes Malcolm suitable to be deployed quickly across a variety of platforms and use cases; whether it be for long-term deployment on a Linux server in a security operations center (SOC) or for incident response on a Macbook for an individual engagement.
* **Secure communications** – All communications with Malcolm, both from the user interface and from remote log forwarders, are secured with industry standard encryption protocols.
* **Permissive license** – Malcolm is comprised of several widely used open-source tools, making it an attractive alternative to security solutions requiring paid licenses.
* **Expanding control systems visibility** – While Malcolm is great for general-purpose network traffic analysis, its creators see a particular need in the community for tools providing insight into protocols used in industrial control systems (ICS) environments. Ongoing Malcolm development will aim to provide additional parsers for common ICS protocols.

Although all the [open-source tools](components.md) that make up Malcolm are already available and in general use, Malcolm provides a framework of interconnectivity that makes it greater than the sum of its parts.

In short, Malcolm provides an easily deployable traffic analysis tool suite for network security monitoring.

# Features

* Network capture
    - Malcolm can passively capture network traffic and generate network log data for analysis in a number of scenarios. For less-complicated network configurations, Malcolm runs in a [standalone "all-in-one"](live-analysis.md#LocalPCAP) deployment in which it fulfills the roles of both network sensor and log aggregator. For deployments in which network capture needs to be instrumented at multiple tap points, Malcolm's lightweight network sensor operating system [Hedgehog Linux](hedgehog.md) can be deployed to [passively observe traffic and forward metadata](live-analysis.md#Hedgehog) about the network sessions it observes to the Malcolm aggregator for enrichment, correlation, and indexing.
    - Depending on local requirements, network capture is can be performed by a combination of several tools:
        + Zeek - an extensible network analysis framework and IDS
        + Arkime - a tool for providing traffic capture and managing local storage of raw or compressed packet capture artifacts (PCAP files)
        + Suricata - a signature-based IDS and threat detection engine
        + netsniff-ng or tcpdump - for simpler capture-only deployments where initial traffic parsing and metadata forwarding are not required
    - Previously-captured PCAP files and Zeek logs can also be [uploaded](upload.md#Upload) via a web browser-based form.
    - Limitation: Malcolm captures traffic at the Ethernet link layer: its focus is primarily IP network traffic, although there are a few protocol parsers that operate directly at the network internface layer. Malcolm does not have built-in support for capture and dissection of serial-only protocols.
    - Limitation: Malcolm does not have the capability to decrypt encrypted traffic. If that is a requirement, other solutions must be deployed to decrypt TLS & SSL communications prior to handing it off to Malcolm for analysis.
* Data Analytics
    - Malcolm's data analytics capabilities are provided at several layers of its stack:
        + At the point of capture, Zeek provides the capability to correlate session traffic perform some protocol-specific analytics. Good examples of this include the [BZAR](https://github.com/mitre-attack/bzar) and [ACID](https://github.com/cisagov/ACID) packages, developed by MITRE corporation, the former for analysis of SMB/DCE-RPC traffic and its classification to the ATT&CK framework, and the latter for analysis of ICS traffic from a number of OT protocols and its classification to the ATT&CK for ICS framework. ACID was specifically developed by MITRE on top of Zeek [protocol analyzers](https://github.com/cisagov/ICSNPP) created by the Malcolm team at INL.
        + File transfers are detected *in situ* in network traffic and [extracted for scanning and analysis](file-scanning.md#ZeekFileExtraction). This automated static file analysis is handled by several signature- and heuristics-based tools including ClamAV (an antivirus engine), capa (a static capabilities analyzer for portable executable files), and YARA (a pattern-matching tool to identify and classify malware). Development is underway to incorporate AssemblyLine, a tool for file triage and dynamic malware analysis.
        + For analyst-driven analytics, all network traffic metadata is indexed into an [OpenSearch or Elasticsearch](opensearch-instances.md#OpenSearchInstance) data store where it can be queried by analysts using dozens of pre-built dashboards and visualizations. Custom analytics can be developed using a variety of tools and query languages. Since the data is indexed into these industry-standard data analytics platforms, other tools like [OpenSearch Security Analytics](https://opensearch.org/docs/latest/security-analytics/) or [Elastic Security](https://www.elastic.co/security) can also be overlaid on top of Malcolm's data. Users can write custom queries written with [Lucene](https://lucene.apache.org/core/2_9_4/queryparsersyntax.md), [DQL](https://opensearch.org/docs/latest/dashboards/dql/)/[KQL](https://www.elastic.co/guide/en/kibana/current/kuery-query.md) (Dashboards and Kibana query languages, respectively), [PPL](https://opensearch.org/docs/latest/search-plugins/sql/ppl/index/) (piped processing language), or [SQL](https://opensearch.org/docs/latest/search-plugins/sql/sql/index/) (structured query language).
        + Arkime also provides ["Hunt"](arkime.md#ArkimeHunt) capabilities, meaning that users can write and execute full-packet search queries that are performed against the raw PCAP payloads stored at the point of capture.
* Data Visualization
    - Data visualization is provided in Malcolm by the following browswer-based user interfaces:
        + [OpenSearch Dashboards](dashboards.md#Dashboards) (if using the OpenSearch backend) or Kibana (if using Elasticsearch) provide hundreds of prebuilt visualizations organized in dozens of dashboards. These tools also provide drag-and-drop creation of custom visualizations. These dashboards and visualizations can be accessed via web interface, exported to PDF or PNG files, or automatically sent with triggered [alerts](https://opensearch.org/docs/latest/observing-your-data/alerting/index/) or as scheduled [reports](https://opensearch.org/docs/latest/reporting/report-dashboard-index/).
        + [Arkime](arkime.md#Arkime) hosts several unique visualizations:
            * The [Sessions](arkime.md#ArkimeSessions) view allows individual events from all of Malcolm's data sources to be viewed in a single pane of glass and full packet capture payloads examined inline in the context of their network sessions.
            * The [SPIView](arkime.md#ArkimeSPIView) and [SPIGraph](arkime.md#ArkimeSPIGraph) (SPI - session profile information) views that help visualize network traffic by breaking it down chronologically, geographically, and by whatever data points the user selects.
            * The [Connections](arkime.md#ArkimeConnections) view generates a force-directed network graph that can be used to visualize the relationships between network enpoints and the protocols over which they communicate. Baselining is also possible, meaning changes to observed network communications over time can be highlighted.
* [Anomaly Detection](anomaly-detection.md#AnomalyDetection) and Machine Learning/AI opportunities
    - OpenSearch's [anomaly detection engine](https://opensearch.org/docs/latest/observing-your-data/ad/index/) automatically detects anomalies in network traffic in near real-time using [Random Cut Forests (RCF)](https://api.semanticscholar.org/CorpusID:927435), an unsupervised (i.e., "black box" or self-training) machine learning algorithm that models a sketch of the data stream to compute an anomaly grade and confidence score value for each incoming data point. These values are used to differentiate an anomaly from normal variations. Malcolm ships with several useful detectors based on this technique, but users can create detectors from any of the nearly 4,000 data points gathered from across Malcolm's supported network protocols. Anomalies and detectors can be managed and viewed in [OpenSearch Dashboards](https://github.com/opensearch-project/anomaly-detection-dashboards-plugin).
    - More experienced data scientists can harness the [OpenSearch ML Commons](https://opensearch.org/docs/latest/ml-commons-plugin/) plugin to do machine-learning model-powered search, using pretrained models provided by OpenSearch, uploading their own models to the OpenSearch engine, or connecting to a model hosted on an external platform. This plugin can be managed via a Dashboards interface or through a set of rest APIs.
    - Those using the Elasticsearch platform can use the machine learning and anomaly detection [tools provided](https://www.elastic.co/elasticsearch/machine-learning) by that platform depending on their Elasticsearch license subscription.
    - Limitation: Anomaly detection and machine learning algorithms rely on enough data (for network data, this generally means at least several weeks' worth or more) to be able to build a baseline of what is normal before they can accurately flag anomalies, and each network is different. Anomaly detection and ML are typically not useful for limited deployments without the available traffic to build that baseline.
    - Limitation: While Malcolm provides some powerful tools in the anomaly detection and ML realm, as of yet they have not been built out to provide the value that they will probably one day realize.
* Threat ingestion
    - Malcolm can ingest threat indicators in the form of static MISP- or STIX-formatted files. It can also subscribe to and periodically update threat indicators from [MISP](zeek-intel.md#ZeekIntelMISP), [TAXII](zeek-intel.md#ZeekIntelSTIX), [Google](zeek-intel.md#ZeekIntelGoogle), and [Mandiant](zeek-intel.md#ZeekIntelMandiant) feeds. These indicators are converted into a format that is read by Zeek, and matches in network traffic are [surfaced through the Zeek intelligence framework](zeek-intel.md#ZeekIntel) for logging.
    - Limitation: Some formats for threat indicators allow for complex definitions and logic. For STIX/TAXII, only indicators of cyber-observable objects matched with the equals (=) comparison operator against a single value can be expressed as Zeek intelligence items. Similarly, only a subset of MISP attribute types can be expressed with the Zeek intelligence indicator types. While this is generally sufficient to cover most indicators interest, more complex indicators are silently ignored.
* Network Modeling
    - Malcolm provides an instance of [NetBox](https://netboxlabs.com/oss/netbox/), an open-source "solution for modeling and documenting modern networks" which is used to model instrumented networks and enrich passively-observed network traffic from that model, a technique Malcolm calls ["Asset Interaction Analysis"](asset-interaction-analysis.md#AssetInteractionAnalysis). Users can pivot between the network visualization tools (the Asset Interaction Analysis and Zeek Known Summary dashboards in OpenSearch Dashboards, and the Arkime Sessions interface) and the NetBox UI to investigate and examine network assets.
    - The NetBox network inventory can be built manually (through manual object entry or by importing CSV, XML, JSON, etc. files) or through [passively-gathered](asset-interaction-analysis.md#NetBoxPopPassive) network traffic metadata.
    - Limitation: Malcolm does not actively probe a network for asset discovery. As its only methods for automatic inventory population are passive, layer 2 network devices are not usually visible nor discoverable through observed network traffic and must be entered manually. There is, however, some research being conducted to overcome this limitation. Active discovery is also being discovered as a possibility for future development.
* Payload Analysis
    - The [Arkime sessions interface](arkime.md#ArkimeSessions) provides access to full PCAP payload. Full payloads are viewable inline in the context of their sessions, or can be [exported](arkime.md#ArkimePCAPExport) for analysis in other tools like WireShark, Network Miner, GRASSMARLIN, etc.
* Throughput limits
    - Malcolm does not specify any particular hardware profile and can be run on a variety of hardware. By providing Malcolm with sufficient computing and storage resources, it should be capable to scale to handle a wide range of throughput requirements. One of Malcolm's partners in the US military is deploying Malcolm in environments with tens of gigabits per second of network throughput.
    - Limitation: Not much time has been spent by Malcolm developers probing the limits of network throughput, so we don't have a lot of solid numbers on this.
* Storage
    - The initial artifacts associated with network traffic capture (PCAP files, raw Zeek and Suricata logs, extracted files, etc.) are stored at the point of capture, whether that be on a standalone Malcolm instance or on sensors running Hedgehog Linux. Indices for the OpenSearch or Elasticsearch data store are managed locally by the Malcolm aggregator, or [remote data store clusters](opensearch-instances.md#OpenSearchInstance) can be used. Solid state storage or RAID configurations are usually required to keep up with streaming full PCAP to disk. For long-running deployments, Malcolm can be [configured to](malcolm-config.md#DiskUsage) prune old indices and artifacts to make room for new data.
    - Limitation: Malcolm does not currently provide a mechanism for configuring automatic backups or rollover of network traffic artifacts to offline or network-attached storage.
* Extensiblity
    - Malcolm provides its own set of [REST APIs](api.md#API) to allow other platforms to interface directly with its data or to access the APIs of its underlying components (e.g., OpenSearch or Elasticsearch, Logstash, NetBox).
    - [Custom rules, scripts, and plugins](custom-rules.md#CustomRulesAndScripts) can easily be dropped-in for several of Malcolm's components:
        + Zeek scripts and plugins
        + Suricata rules
        + YARA rules
        + [Threat intelligence feeds](zeek-intel.md#ZeekIntel)
        + NetBox plugins
        + Sigma rules*
            * Sigma rules are supported through OpenSearch Security Analytics, although development on the upcoming Malcolm roadmap is needed to make this integration fully capable
    - A [contributor's guide](contributing-guide.md) in the documentation provides guidelines for outside developers who wish to enhance or extend Malcolm.
    - Limitation: A full-fledged plugin system for adding features to Malcolm does not yet exist, though is in early design stages.
* Automation
    - For the most part, Malcolm can run with a "set it and forget it" mindset should keep itself running without much hands-on maintenance.
    - Automatic updates of threat intelligence feeds and rules for file scanning engines can be scheduled to run automatically in the background.
    - Automatic [alerting](alerting.md#Alerting) and [reporting](reporting.md#Reporting) capabilities are available.
    - Limitation: Malcolm does not yet have a well-defined plan for [automated upgrades](malcolm-upgrade.md#UpgradePlan): it's a pretty manual process.
* Cloud deployment capabilities
    - Malcolm can be cloud-deployed with [Kubernetes](kubernetes.md#Kubernetes) either on-prem, on [Amazon AWS with Elastic Kubernetes Service](aws.md#AWSEKSAuto), or ostensibly on any other Kubernetes-based platform.
    - As Hedgehog Linux is a dedicated OS for traffic capture, it is not used directly capture in cloud deployments. Instead, for cloud deployments, traffic can be collected in a few ways:
        + Capture in physical network environments can be done normally with Hedgehog Linux and forwarded to a Malcolm instance in the cloud.
        + Malcolm can run in "standalone" mode to do capture of a virtual or physical [interface available](live-analysis.md#LocalPCAP) to nodes the Kubernetes cluster, or run in the capture-only [Hedgehog run profile](live-analysis.md#Profiles).
        + On AWS, [VPC traffic mirroring](https://docs.aws.amazon.com/vpc/latest/mirroring/what-is-traffic-mirroring.md) can be [configured](https://www.awsnetworkshops.com/030_module1/mirrortraffic/) and expose an interface for Malcolm to listen on.
    - Limitation: As the variety of cloud platforms is varied, some of the configuration for traffic capture on cloud networks is left up to the user somewhat; Malcolm can listen on anything provided to it as a virtual interface, but assumes that the traffic-mirroring interface has been configured correctly by the user.
    - Limitation: The documened instructions for cloud deployment don't yet walk the user through many of the scale-out capabilities Kubernetes provides. However, a US military partner is working on a [Helm chart](https://github.com/idaholab/Malcolm-Helm) that expands its cloud capabilities and has contributed that back upstream to the main Malcolm project.
    - Limitation: Malcolm [does not yet](https://github.com/idaholab/Malcolm/issues/232) have instrumentation for receiving and capturing cloud infrastructure logs, such as VPC flow logs, CloudFront access logs, ELB logs, S3 bucket logs, Route 53 query logs, Amazon RDS logs, Azure infrastructure logs, etc.
* Resource requirements
    - Hardware
        + Malcolm
            * Minimum system requirements
                - 24 gigabytes RAM
                - 8 CPU cores (amd64 and arm64 supported)
                - As much storage (preferably solid-state or RAID) as necessary to meet data retention requirements
            * Recommended system requirements
                - 32+ gigabytes RAM
                - 16+ CPU cores (amd64 and arm64 supported)
                - As much storage (preferably solid-state or RAID) as necessary to meet data retention requirements
        + Hedgehog Linux
            * Minimum system requirements
                - 8 gigabytes RAM
                - 4 CPU cores (amd64 supported, arm64 supported for Raspberry Pi image)
                - As much storage (preferably solid-state or RAID) as necessary to meet full PCAP retention requirements
            * Recommended system requirements
                - 16+ gigabytes RAM
                - 8+ CPU cores (amd64 supported, arm64 supported for Raspberry Pi image)
                - As much storage (preferably solid-state or RAID) as necessary to meet data retention requirements
    - License
        + Malcolm is [distributed](https://github.com/idaholab/Malcolm/blob/main/LICENSE.txt) under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) on an as-is basis, without warranties or conditions of any kind, either express or implied.
        + Malcolm's [components](components.md) are for the most part permissive open-source licenses as well. In cases where underlying system components are released under more restrictive copyleft license terms (e.g., GPL), Malcolm interfaces with those tools or libraries in a loosely-coupled way that is, for example,  satisfied by the GPLv2's "mere aggregation" clause and the GPLv3 "aggregates" clause, in addition to the fact that in Malcolm's software containers those tools run as "separate and independent" processes. [This article from opensource.com](https://opensource.com/article/18/1/containers-gpl-and-copyleft) explains the ramifications of GPL and copyleft as it pertains to Linux containers.
    - Support
        + The organizations supporting Malcolm's development do not offer paid professional services or any contract-based support. Any support provided is done the same way most other open-source projects do so, which is through GitHub, for example:
            * [Community discussions board](https://github.com/cisagov/Malcolm/discussions)
            * [Issue and feature tracking](https://github.com/cisagov/malcolm/issues?q=is%3Aissue+is%3Aopen+-label%3Atraining)
            * [Project roadmap tracking](https://github.com/orgs/cisagov/projects/98)
        + Beyond engagement via the forums listed here, no expectation of any particular level of support should be assumed.
* User experience/UI/intuitive
    - Malcolm's user-friendly analyst-facing interfaces are accessible via an easy-to-nagivate [landing page](images/screenshots/malcolm_landing_page.png).
    - Malcolm's [documentation](README.md) is robust and usable.
    - A series of [YouTube videos](https://www.youtube.com/@malcolmnetworktrafficanalysis/playlists) are being developed for a [variety of topics](https://github.com/idaholab/Malcolm/wiki/Malcolm-Learning-Tree).
    - A technical training course is being developed which will be publicly released to help organizations train Malcolm users.
    - Limitation: Because Malcolm is a framework hosting discrete tools, several of which have their own user interfaces, some users may feel that the Malcolm user experience isn't as "unified" as it would be if these interfaces had all been created in tandem by one entity.
