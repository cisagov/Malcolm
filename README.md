# Malcolm

![](./docs/images/logo/Malcolm_banner.png)

[Malcolm](https://github.com/idaholab/Malcolm) is a powerful network traffic analysis tool suite designed with the following goals in mind:

* **Easy to use** – Malcolm accepts network traffic data in the form of full packet capture (PCAP) files and Zeek (formerly Bro) logs. These artifacts can be uploaded via a simple browser-based interface or captured live and forwarded to Malcolm using lightweight forwarders. In either case, the data is automatically normalized, enriched, and correlated for analysis.
* **Powerful traffic analysis** – Visibility into network communications is provided through two intuitive interfaces: Kibana, a flexible data visualization plugin with dozens of prebuilt dashboards providing an at-a-glance overview of network protocols; and Arkime (formerly Moloch), a powerful tool for finding and identifying the network sessions comprising suspected security incidents.
* **Streamlined deployment** – Malcolm operates as a cluster of Docker containers, isolated sandboxes which each serve a dedicated function of the system. This Docker-based deployment model, combined with a few simple scripts for setup and run-time management, makes Malcolm suitable to be deployed quickly across a variety of platforms and use cases, whether it be for long-term deployment on a Linux server in a security operations center (SOC) or for incident response on a Macbook for an individual engagement.
* **Secure communications** – All communications with Malcolm, both from the user interface and from remote log forwarders, are secured with industry standard encryption protocols.
* **Permissive license** – Malcolm is comprised of several widely used open source tools, making it an attractive alternative to security solutions requiring paid licenses.
* **Expanding control systems visibility** – While Malcolm is great for general-purpose network traffic analysis, its creators see a particular need in the community for tools providing insight into protocols used in industrial control systems (ICS) environments. Ongoing Malcolm development will aim to provide additional parsers for common ICS protocols.

Although all of the open source tools which make up Malcolm are already available and in general use, Malcolm provides a framework of interconnectivity which makes it greater than the sum of its parts. And while there are many other network traffic analysis solutions out there, ranging from complete Linux distributions like Security Onion to licensed products like Splunk Enterprise Security, the creators of Malcolm feel its easy deployment and robust combination of tools fill a void in the network security space that will make network traffic analysis accessible to many in both the public and private sectors as well as individual enthusiasts.

In short, Malcolm provides an easily deployable network analysis tool suite for full packet capture artifacts (PCAP files) and Zeek logs. While Internet access is required to build it, it is not required at runtime.

## <a name="TableOfContents"></a>Table of Contents

* [Quick start](#QuickStart)
    * [Getting Malcolm](#GetMalcolm)
    * [User interface](#UserInterfaceURLs)
* [Overview](#Overview)
* [Components](#Components)
* [Supported Protocols](#Protocols)
* [Development](#Development)
    * [Building from source](#Build)
* [Pre-Packaged installation files](#Packager)
* [Preparing your system](#Preparing)
    * [Recommended system requirements](#SystemRequirements)
    * [System configuration and tuning](#ConfigAndTuning)
        * [`docker-compose.yml` parameters](#DockerComposeYml)
        * [Linux host system configuration](#HostSystemConfigLinux)
        * [macOS host system configuration](#HostSystemConfigMac)
        * [Windows host system configuration](#HostSystemConfigWindows)
* [Running Malcolm](#Running)
    * [Configure authentication](#AuthSetup)
        * [Local account management](#AuthBasicAccountManagement)
        * [Lightweight Directory Access Protocol (LDAP) authentication](#AuthLDAP)
            - [LDAP connection security](#AuthLDAPSecurity)
    * [Starting Malcolm](#Starting)
    * [Stopping and restarting Malcolm](#StopAndRestart)
    * [Clearing Malcolm's data](#Wipe)
* [Capture file and log archive upload](#Upload)
    - [Tagging](#Tagging)
    - [Processing uploaded PCAPs with Zeek](#UploadPCAPZeek)
* [Live analysis](#LiveAnalysis)
    * [Capturing traffic on local network interfaces](#LocalPCAP)
    * [Using a network sensor appliance](#Hedgehog)
    * [Manually forwarding Zeek logs from an external source](#ZeekForward)
* [Arkime](#Arkime)
    * [Zeek log integration](#ArkimeZeek)
        - [Correlating Zeek logs and Arkime sessions](#ZeekArkimeFlowCorrelation)
    * [Help](#ArkimeHelp)
    * [Sessions](#ArkimeSessions)
        * [PCAP Export](#ArkimePCAPExport)
    * [SPIView](#ArkimeSPIView)
    * [SPIGraph](#ArkimeSPIGraph)
    * [Connections](#ArkimeConnections)
    * [Hunt](#ArkimeHunt)
    * [Statistics](#ArkimeStats)
    * [Settings](#ArkimeSettings)
* [Kibana](#Kibana)
    * [Discover](#Discover)
        - [Screenshots](#DiscoverGallery)
    * [Visualizations and dashboards](#KibanaVisualizations)
        - [Prebuilt visualizations and dashboards](#PrebuiltVisualizations)
            - [Screenshots](#PrebuiltVisualizationsGallery)
        - [Building your own visualizations and dashboards](#BuildDashboard)
            + [Screenshots](#NewVisualizationsGallery)
* [Search Queries in Arkime and Kibana](#SearchCheatSheet)
* [Other Malcolm features](#MalcolmFeatures)
    - [Automatic file extraction and scanning](#ZeekFileExtraction)
    - [Automatic host and subnet name assignment](#HostAndSubnetNaming)
        + [IP/MAC address to hostname mapping via `host-map.txt`](#HostNaming)
        + [CIDR subnet to network segment name mapping via `cidr-map.txt`](#SegmentNaming)
        + [Defining hostname and CIDR subnet names interface](#NameMapUI)
        + [Applying mapping changes](#ApplyMapping)
    - [Elasticsearch index management](#IndexManagement)
    - [Alerting](#Alerting)
* [Using Beats to forward host logs to Malcolm](#OtherBeats)
* [Malcolm installer ISO](#ISO)
    * [Installation](#ISOInstallation)
    * [Generating the ISO](#ISOBuild)
    * [Setup](#ISOSetup)
    * [Time synchronization](#ConfigTime)
    * [Hardening](#Hardening)
        * [STIG compliance exceptions](#STIGExceptions)
        * [CIS benchmark compliance exceptions](#CISExceptions)
* [Known issues](#Issues)
* [Installation example using Ubuntu 20.04 LTS](#InstallationExample)
* [Upgrading Malcolm](#UpgradePlan)
* [Forks](#Forks)
* [Copyright](#Footer)

## <a name="QuickStart"></a>Quick start

### <a name="GetMalcolm"></a>Getting Malcolm

For a `TL;DR` example of downloading, configuring, and running Malcolm on a Linux platform, see [Installation example using Ubuntu 20.04 LTS](#InstallationExample).

The scripts to control Malcolm require Python 3.

#### Source code

The files required to build and run Malcolm are available on the [Idaho National Lab's GitHub page](https://github.com/idaholab/Malcolm/tree/master). Malcolm's source code is released under the terms of a permissive open source software license (see see `License.txt` for the terms of its release).

#### Building Malcolm from scratch

The `build.sh` script can build Malcolm's Docker images from scratch. See [Building from source](#Build) for more information.

#### Initial configuration

You must run [`auth_setup`](#AuthSetup) prior to pulling Malcolm's Docker images. You should also ensure your system configuration and `docker-compose.yml` settings are tuned by running `./scripts/install.py` or `./scripts/install.py --configure` (see [System configuration and tuning](#ConfigAndTuning)).
    
#### Pull Malcolm's Docker images

Malcolm's Docker images are periodically built and hosted on [Docker Hub](https://hub.docker.com/u/malcolmnetsec). If you already have [Docker](https://www.docker.com/) and [Docker Compose](https://docs.docker.com/compose/), these prebuilt images can be pulled by navigating into the Malcolm directory (containing the `docker-compose.yml` file) and running `docker-compose pull` like this:
```
$ docker-compose pull
Pulling arkime        ... done
Pulling elasticsearch ... done
Pulling file-monitor  ... done
Pulling filebeat      ... done
Pulling freq          ... done
Pulling htadmin       ... done
Pulling kibana        ... done
Pulling logstash      ... done
Pulling name-map-ui   ... done
Pulling nginx-proxy   ... done
Pulling pcap-capture  ... done
Pulling pcap-monitor  ... done
Pulling upload        ... done
Pulling zeek          ... done
```

You can then observe that the images have been retrieved by running `docker images`:
```
$ docker images
REPOSITORY                                          TAG                 IMAGE ID            CREATED             SIZE
malcolmnetsec/arkime                                3.0.0               xxxxxxxxxxxx        39 hours ago        683MB
malcolmnetsec/elasticsearch-od                      3.0.0               xxxxxxxxxxxx        40 hours ago        690MB
malcolmnetsec/file-monitor                          3.0.0               xxxxxxxxxxxx        39 hours ago        470MB
malcolmnetsec/file-upload                           3.0.0               xxxxxxxxxxxx        39 hours ago        199MB
malcolmnetsec/filebeat-oss                          3.0.0               xxxxxxxxxxxx        39 hours ago        555MB
malcolmnetsec/freq                                  3.0.0               xxxxxxxxxxxx        39 hours ago        390MB
malcolmnetsec/htadmin                               3.0.0               xxxxxxxxxxxx        39 hours ago        180MB
malcolmnetsec/kibana-helper                         3.0.0               xxxxxxxxxxxx        40 hours ago        141MB
malcolmnetsec/kibana-od                             3.0.0               xxxxxxxxxxxx        40 hours ago        1.16GB
malcolmnetsec/logstash-oss                          3.0.0               xxxxxxxxxxxx        39 hours ago        1.41GB
malcolmnetsec/name-map-ui                           3.0.0               xxxxxxxxxxxx        39 hours ago        137MB
malcolmnetsec/nginx-proxy                           3.0.0               xxxxxxxxxxxx        39 hours ago        120MB
malcolmnetsec/pcap-capture                          3.0.0               xxxxxxxxxxxx        39 hours ago        111MB
malcolmnetsec/pcap-monitor                          3.0.0               xxxxxxxxxxxx        39 hours ago        157MB
malcolmnetsec/zeek                                  3.0.0               xxxxxxxxxxxx        39 hours ago        887MB
```

#### Import from pre-packaged tarballs

Once built, the `malcolm_appliance_packager.sh` script can be used to create pre-packaged Malcolm tarballs for import on another machine. See [Pre-Packaged Installation Files](#Packager) for more information.

### Starting and stopping Malcolm

Use the scripts in the `scripts/` directory to start and stop Malcolm, view debug logs of a currently running
instance, wipe the database and restore Malcolm to a fresh state, etc.

### <a name="UserInterfaceURLs"></a>User interface

A few minutes after starting Malcolm (probably 5 to 10 minutes for Logstash to be completely up, depending on the system), the following services will be accessible:

* Arkime: [https://localhost:443](https://localhost:443)
* Kibana: [https://localhost/kibana/](https://localhost/kibana/) or [https://localhost:5601](https://localhost:5601)
* Capture File and Log Archive Upload (Web): [https://localhost/upload/](https://localhost/upload/) or [https://localhost:8443](https://localhost:8443)
* Capture File and Log Archive Upload (SFTP): `sftp://<username>@127.0.0.1:8022/files`
* [Host and Subnet Name Mapping](#HostAndSubnetNaming) Editor: [https://localhost/name-map-ui/](https://localhost/name-map-ui/)
* Account Management: [https://localhost:488](https://localhost:488)

## <a name="Overview"></a>Overview

![Malcolm Network Diagram](./docs/images/malcolm_network_diagram.png)

Malcolm processes network traffic data in the form of packet capture (PCAP) files or Zeek logs. A [sensor](#Hedgehog) (packet capture appliance) monitors network traffic mirrored to it over a SPAN port on a network switch or router, or using a network TAP device. [Zeek](https://www.zeek.org/index.html) logs and [Arkime](https://molo.ch/) sessions are generated containing important session metadata from the traffic observed, which are then securely forwarded to a Malcolm instance. Full PCAP files are optionally stored locally on the sensor device for examination later.

Malcolm parses the network session data and enriches it with additional lookups and mappings including GeoIP mapping, hardware manufacturer lookups from [organizationally unique identifiers (OUI)](http://standards-oui.ieee.org/oui/oui.txt) in MAC addresses, assigning names to [network segments](#SegmentNaming) and [hosts](#HostNaming) based on user-defined IP address and MAC mappings, performing [TLS fingerprinting](#https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967), and many others.

The enriched data is stored in an [Elasticsearch](https://opendistro.github.io/for-elasticsearch/) document store in a format suitable for analysis through two intuitive interfaces: Kibana, a flexible data visualization plugin with dozens of prebuilt dashboards providing an at-a-glance overview of network protocols; and Arkime, a powerful tool for finding and identifying the network sessions comprising suspected security incidents. These tools can be accessed through a web browser from analyst workstations or for display in a security operations center (SOC). Logs can also optionally be forwarded on to another instance of Malcolm.

For smaller networks, use at home by network security enthusiasts, or in the field for incident response engagements, Malcolm can also easily be deployed locally on an ordinary consumer workstation or laptop. Malcolm can process local artifacts such as locally-generated Zeek logs, locally-captured PCAP files, and PCAP files collected offline without the use of a dedicated sensor appliance.

## <a name="Components"></a>Components

Malcolm leverages the following excellent open source tools, among others.

* [Arkime](https://arkime.com/) (formerly Moloch) - for PCAP file processing, browsing, searching, analysis, and carving/exporting; Arkime itself consists of two parts:
    * [moloch-capture](https://github.com/arkime/arkime/tree/master/capture) - a tool for traffic capture, as well as offline PCAP parsing and metadata insertion into Elasticsearch
    * [viewer](https://github.com/arkime/arkime/tree/master/viewer) - a browser-based interface for data visualization
* [Elasticsearch](https://www.elastic.co/products/elasticsearch) ([Open Distro](https://opendistro.github.io/for-elasticsearch/) variant) - a search and analytics engine for indexing and querying network traffic session metadata 
* [Logstash](https://www.elastic.co/products/logstash) and [Filebeat](https://www.elastic.co/products/beats/filebeat) - for ingesting and parsing [Zeek](https://www.zeek.org/index.html) [Log Files](https://docs.zeek.org/en/stable/script-reference/log-files.html) and ingesting them into Elasticsearch in a format that Arkime understands and is able to understand in the same way it natively understands PCAP data
* [Kibana](https://www.elastic.co/products/kibana) ([Open Distro](https://opendistro.github.io/for-elasticsearch/) variant) - for creating additional ad-hoc visualizations and dashboards beyond that which is provided by Arkime viewer
* [Zeek](https://www.zeek.org/index.html) - a network analysis framework and IDS
* [Yara](https://github.com/VirusTotal/yara) - a tool used to identify and classify malware samples
* [Capa](https://github.com/fireeye/capa) - a tool for detecting capabilities in executable files
* [ClamAV](https://www.clamav.net/) - an antivirus engine for scanning files extracted by Zeek
* [CyberChef](https://github.com/gchq/CyberChef) - a "swiss-army knife" data conversion tool 
* [jQuery File Upload](https://github.com/blueimp/jQuery-File-Upload) - for uploading PCAP files and Zeek logs for processing
* [List.js](https://github.com/javve/list.js) - for the [host and subnet name mapping](#HostAndSubnetNaming) interface
* [Docker](https://www.docker.com/) and [Docker Compose](https://docs.docker.com/compose/) - for simple, reproducible deployment of the Malcolm appliance across environments and to coordinate communication between its various components
* [Nginx](https://nginx.org/) - for HTTPS and reverse proxying Malcolm components
* [nginx-auth-ldap](https://github.com/kvspb/nginx-auth-ldap) - an LDAP authentication module for nginx
* [Mark Baggett](https://github.com/MarkBaggett)'s [freq](https://github.com/MarkBaggett/freq) - a tool for calculating entropy of strings
* [Florian Roth](https://github.com/Neo23x0)'s [Signature-Base](https://github.com/Neo23x0/signature-base) Yara ruleset
* These Zeek plugins:
    * some of Amazon.com, Inc.'s [ICS protocol](https://github.com/amzn?q=zeek) analyzers
    * Andrew Klaus's [Sniffpass](https://github.com/cybera/zeek-sniffpass) plugin for detecting cleartext passwords in HTTP POST requests
    * Andrew Klaus's [zeek-httpattacks](https://github.com/precurse/zeek-httpattacks) plugin for detecting noncompliant HTTP requests
    * ICS protocol analyzers for Zeek published by [DHS CISA](https://github.com/cisagov/ICSNPP) and [Idaho National Lab](https://github.com/idaholab/ICSNPP)
    * Corelight's [bro-xor-exe](https://github.com/corelight/bro-xor-exe-plugin) plugin
    * Corelight's ["bad neighbor" (CVE-2020-16898)](https://github.com/corelight/CVE-2020-16898) plugin    
    * Corelight's [callstranger-detector](https://github.com/corelight/callstranger-detector) plugin
    * Corelight's [community ID](https://github.com/corelight/zeek-community-id) flow hashing plugin
    * Corelight's [ripple20](https://github.com/corelight/ripple20) plugin
    * Corelight's [SIGred](https://github.com/corelight/SIGred) plugin
    * Corelight's [Zerologon](https://github.com/corelight/zerologon) plugin
    * J-Gras' [Zeek::AF_Packet](https://github.com/J-Gras/zeek-af_packet-plugin) plugin
    * Johanna Amann's [CVE-2020-0601](https://github.com/0xxon/cve-2020-0601) ECC certificate validation plugin and [CVE-2020-13777](https://github.com/0xxon/cve-2020-13777) GnuTLS unencrypted session ticket detection plugin
    * Lexi Brent's [EternalSafety](https://github.com/0xl3x1/zeek-EternalSafety) plugin
    * MITRE Cyber Analytics Repository's [Bro/Zeek ATT&CK-Based Analytics (BZAR)](https://github.com/mitre-attack/car/tree/master/implementations) script
    * Salesforce's [gQUIC](https://github.com/salesforce/GQUIC_Protocol_Analyzer) analyzer
    * Salesforce's [HASSH](https://github.com/salesforce/hassh) SSH fingerprinting plugin
    * Salesforce's [JA3](https://github.com/salesforce/ja3) TLS fingerprinting plugin
    * SoftwareConsultingEmporium's [Bro::LDAP](https://github.com/SoftwareConsultingEmporium/ldap-analyzer) analyzer
    * Verizon Media's [spicy-noise](https://github.com/theparanoids/spicy-noise) WireGuard analyzer plugin
    * Zeek's [Spicy](https://github.com/zeek/spicy) plugin framework
* [GeoLite2](https://dev.maxmind.com/geoip/geoip2/geolite2/) - Malcolm includes GeoLite2 data created by [MaxMind](https://www.maxmind.com)

## <a name="Protocols"></a>Supported Protocols

Malcolm uses [Zeek](https://docs.zeek.org/en/stable/script-reference/proto-analyzers.html) and [Arkime](https://github.com/arkime/arkime/tree/master/capture/parsers) to analyze network traffic. These tools provide varying degrees of visibility into traffic transmitted over the following network protocols:

| Traffic | Wiki | Organization/Specification | Arkime | Zeek |
|---|:---:|:---:|:---:|:---:|
|Internet layer|[🔗](https://en.wikipedia.org/wiki/Internet_layer)|[🔗](https://tools.ietf.org/html/rfc791)|[✓](https://github.com/arkime/arkime/blob/master/capture/packet.c)|[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info)|
|Border Gateway Protocol (BGP)|[🔗](https://en.wikipedia.org/wiki/Border_Gateway_Protocol)|[🔗](https://tools.ietf.org/html/rfc2283)|[✓](https://github.com/arkime/arkime/blob/master/capture/parsers/bgp.c)||
|Building Automation and Control (BACnet)|[🔗](https://en.wikipedia.org/wiki/BACnet)|[🔗](http://www.bacnet.org/)||[✓](https://github.com/cisagov/ICSNPP/tree/master/zeek_bacnet_parser)|
|Bristol Standard Asynchronous Protocol (BSAP)|[🔗](https://en.wikipedia.org/wiki/Bristol_Standard_Asynchronous_Protocol)|[🔗](http://www.documentation.emersonprocess.com/groups/public/documents/specification_sheets/d301321x012.pdf)[🔗](http://www.documentation.emersonprocess.com/groups/public/documents/instruction_manuals/d301401x012.pdf)||[✓](https://github.com/cisagov/ICSNPP/tree/master/zeek_bsap_ip_parser)[✓](https://github.com/cisagov/ICSNPP/tree/master/zeek_bsap_serial_parser)|
|Distributed Computing Environment / Remote Procedure Calls (DCE/RPC)|[🔗](https://en.wikipedia.org/wiki/DCE/RPC)|[🔗](https://pubs.opengroup.org/onlinepubs/009629399/toc.pdf)||[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/dce-rpc/main.zeek.html#type-DCE_RPC::Info)|
|Dynamic Host Configuration Protocol (DHCP)|[🔗](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol)|[🔗](https://tools.ietf.org/html/rfc2131)|[✓](https://github.com/arkime/arkime/blob/master/capture/parsers/dhcp.c)|[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/dhcp/main.zeek.html#type-DHCP::Info)|
|Distributed Network Protocol 3 (DNP3)|[🔗](https://en.wikipedia.org/wiki/DNP3)|[🔗](https://www.dnp.org)||[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/dnp3/main.zeek.html#type-DNP3::Info)[✓](https://github.com/cisagov/ICSNPP/tree/master/zeek_dnp3_parser)|
|Domain Name System (DNS)|[🔗](https://en.wikipedia.org/wiki/Domain_Name_System)|[🔗](https://tools.ietf.org/html/rfc1035)|[✓](https://github.com/arkime/arkime/blob/master/capture/parsers/dns.c)|[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/dns/main.zeek.html#type-DNS::Info)|
|EtherNet/IP / Common Industrial Protocol (CIP)|[🔗](https://en.wikipedia.org/wiki/EtherNet/IP) [🔗](https://en.wikipedia.org/wiki/Common_Industrial_Protocol)|[🔗](https://www.odva.org/Technology-Standards/EtherNet-IP/Overview)||[✓](https://github.com/cisagov/ICSNPP/tree/master/zeek_enip_parser)|
|FTP (File Transfer Protocol)|[🔗](https://en.wikipedia.org/wiki/File_Transfer_Protocol)|[🔗](https://tools.ietf.org/html/rfc959)||[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/ftp/info.zeek.html#type-FTP::Info)|
|Google Quick UDP Internet Connections (gQUIC)|[🔗](https://en.wikipedia.org/wiki/QUIC#Google_QUIC_(gQUIC))|[🔗](https://www.chromium.org/quic)|[✓](https://github.com/arkime/arkime/blob/master/capture/parsers/quic.c)|[✓](https://github.com/salesforce/GQUIC_Protocol_Analyzer/blob/master/scripts/Salesforce/GQUIC/main.bro)|
|Hypertext Transfer Protocol (HTTP)|[🔗](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol)|[🔗](https://tools.ietf.org/html/rfc7230)|[✓](https://github.com/arkime/arkime/blob/master/capture/parsers/http.c)|[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/http/main.zeek.html#type-HTTP::Info)|
|Internet Relay Chat (IRC)|[🔗](https://en.wikipedia.org/wiki/Internet_Relay_Chat)|[🔗](https://tools.ietf.org/html/rfc1459)|[✓](https://github.com/arkime/arkime/blob/master/capture/parsers/irc.c)|[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/irc/main.zeek.html#type-IRC::Info)|
|Kerberos|[🔗](https://en.wikipedia.org/wiki/Kerberos_(protocol))|[🔗](https://tools.ietf.org/html/rfc4120)|[✓](https://github.com/arkime/arkime/blob/master/capture/parsers/krb5.c)|[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/krb/main.zeek.html#type-KRB::Info)|
|Lightweight Directory Access Protocol (LDAP)|[🔗](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol)|[🔗](https://tools.ietf.org/html/rfc4511)|[✓](https://github.com/arkime/arkime/blob/master/capture/parsers/ldap.c)|[✓](https://github.com/SoftwareConsultingEmporium/ldap-analyzer/blob/master/scripts/main.bro)|
|Modbus|[🔗](https://en.wikipedia.org/wiki/Modbus)|[🔗](http://www.modbus.org/)||[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/modbus/main.zeek.html#type-Modbus::Info)[✓](https://github.com/cisagov/ICSNPP/tree/master/zeek_modbus_parser)|
|MQ Telemetry Transport (MQTT)|[🔗](https://en.wikipedia.org/wiki/MQTT)|[🔗](https://mqtt.org/)||[✓](https://docs.zeek.org/en/stable/scripts/policy/protocols/mqtt/main.zeek.html)|
|MySQL|[🔗](https://en.wikipedia.org/wiki/MySQL)|[🔗](https://dev.mysql.com/doc/internals/en/client-server-protocol.html)|[✓](https://github.com/arkime/arkime/blob/master/capture/parsers/mysql.c)|[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/mysql/main.zeek.html#type-MySQL::Info)|
|NT Lan Manager (NTLM)|[🔗](https://en.wikipedia.org/wiki/NT_LAN_Manager)|[🔗](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4?redirectedfrom=MSDN)||[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/ntlm/main.zeek.html#type-NTLM::Info)|
|Network Time Protocol (NTP)|[🔗](https://en.wikipedia.org/wiki/Network_Time_Protocol)|[🔗](http://www.ntp.org)||[✓](https://docs.zeek.org/en/latest/scripts/base/protocols/ntp/main.zeek.html#type-NTP::Info)|
|Oracle|[🔗](https://en.wikipedia.org/wiki/Oracle_Net_Services)|[🔗](https://docs.oracle.com/cd/E11882_01/network.112/e41945/layers.htm#NETAG004)|[✓](https://github.com/arkime/arkime/blob/master/capture/parsers/oracle.c)||
|PostgreSQL|[🔗](https://en.wikipedia.org/wiki/PostgreSQL)|[🔗](https://www.postgresql.org/)|[✓](https://github.com/arkime/arkime/blob/master/capture/parsers/postgresql.c)||
|Process Field Net (PROFINET)|[🔗](https://en.wikipedia.org/wiki/PROFINET)|[🔗](https://us.profinet.com/technology/profinet/)||[✓](https://github.com/amzn/zeek-plugin-profinet/blob/master/scripts/main.zeek)|
|Remote Authentication Dial-In User Service (RADIUS)|[🔗](https://en.wikipedia.org/wiki/RADIUS)|[🔗](https://tools.ietf.org/html/rfc2865)|[✓](https://github.com/arkime/arkime/blob/master/capture/parsers/radius.c)|[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/radius/main.zeek.html#type-RADIUS::Info)|
|Remote Desktop Protocol (RDP)|[🔗](https://en.wikipedia.org/wiki/Remote_Desktop_Protocol)|[🔗](https://docs.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol?redirectedfrom=MSDN)||[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/rdp/main.zeek.html#type-RDP::Info)|
|Remote Framebuffer (RFB)|[🔗](https://en.wikipedia.org/wiki/RFB_protocol)|[🔗](https://tools.ietf.org/html/rfc6143)||[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/rfb/main.zeek.html#type-RFB::Info)|
|S7comm / Connection Oriented Transport Protocol (COTP)|[🔗](https://wiki.wireshark.org/S7comm) [🔗](https://wiki.wireshark.org/COTP)|[🔗](https://support.industry.siemens.com/cs/document/26483647/what-properties-advantages-and-special-features-does-the-s7-protocol-offer-?dti=0&lc=en-WW) [🔗](https://www.ietf.org/rfc/rfc0905.txt)||[✓](https://github.com/amzn/zeek-plugin-s7comm/blob/master/scripts/main.zeek)|
|Session Initiation Protocol (SIP)|[🔗](https://en.wikipedia.org/wiki/Session_Initiation_Protocol)|[🔗](https://tools.ietf.org/html/rfc3261)||[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/sip/main.zeek.html#type-SIP::Info)|
|Server Message Block (SMB) / Common Internet File System (CIFS)|[🔗](https://en.wikipedia.org/wiki/Server_Message_Block)|[🔗](https://docs.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview)|[✓](https://github.com/arkime/arkime/blob/master/capture/parsers/smb.c)|[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/smb/main.zeek.html)|
|Simple Mail Transfer Protocol|[🔗](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol)|[🔗](https://tools.ietf.org/html/rfc5321)|[✓](https://github.com/arkime/arkime/blob/master/capture/parsers/smtp.c)|[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/smtp/main.zeek.html#type-SMTP::Info)|
|Simple Network Management Protocol|[🔗](https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol)|[🔗](https://tools.ietf.org/html/rfc2578)|[✓](https://github.com/arkime/arkime/blob/master/capture/parsers/smtp.c)|[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/snmp/main.zeek.html#type-SNMP::Info)|
|SOCKS|[🔗](https://en.wikipedia.org/wiki/SOCKS)|[🔗](https://tools.ietf.org/html/rfc1928)|[✓](https://github.com/arkime/arkime/blob/master/capture/parsers/socks.c)|[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/socks/main.zeek.html#type-SOCKS::Info)|
|Secure Shell (SSH)|[🔗](https://en.wikipedia.org/wiki/Secure_Shell)|[🔗](https://tools.ietf.org/html/rfc4253)|[✓](https://github.com/arkime/arkime/blob/master/capture/parsers/ssh.c)|[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/ssh/main.zeek.html#type-SSH::Info)|
|Secure Sockets Layer (SSL) / Transport Layer Security (TLS)|[🔗](https://en.wikipedia.org/wiki/Transport_Layer_Security)|[🔗](https://tools.ietf.org/html/rfc5246)|[✓](https://github.com/arkime/arkime/blob/master/capture/parsers/socks.c)|[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/ssl/main.zeek.html#type-SSL::Info)|
|Syslog|[🔗](https://en.wikipedia.org/wiki/Syslog)|[🔗](https://tools.ietf.org/html/rfc5424)|[✓](https://github.com/arkime/arkime/blob/master/capture/parsers/tls.c)|[✓](https://docs.zeek.org/en/stable/scripts/base/protocols/syslog/main.zeek.html#type-Syslog::Info)|
|Tabular Data Stream|[🔗](https://en.wikipedia.org/wiki/Tabular_Data_Stream)|[🔗](https://www.freetds.org/tds.html) [🔗](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/b46a581a-39de-4745-b076-ec4dbb7d13ec)|[✓](https://github.com/arkime/arkime/blob/master/capture/parsers/tds.c)|[✓](https://github.com/amzn/zeek-plugin-tds/blob/master/scripts/main.zeek)|
|Telnet / remote shell (rsh) / remote login (rlogin)|[🔗](https://en.wikipedia.org/wiki/Telnet)[🔗](https://en.wikipedia.org/wiki/Berkeley_r-commands)|[🔗](https://tools.ietf.org/html/rfc854)[🔗](https://tools.ietf.org/html/rfc1282)|[✓](https://github.com/arkime/arkime/blob/master/capture/parsers/misc.c#L336)|[✓](https://docs.zeek.org/en/current/scripts/base/bif/plugins/Zeek_Login.events.bif.zeek.html)[❋](https://github.com/idaholab/Malcolm/blob/master/zeek/config/login.zeek)|
|TFTP (Trivial File Transfer Protocol)|[🔗](https://en.wikipedia.org/wiki/Trivial_File_Transfer_Protocol)|[🔗](https://tools.ietf.org/html/rfc1350)||[✓](https://github.com/zeek/spicy-tftp)|
|WireGuard|[🔗](https://en.wikipedia.org/wiki/WireGuard)|[🔗](https://www.wireguard.com/protocol/)[🔗](https://www.wireguard.com/papers/wireguard.pdf)||[✓](https://github.com/theparanoids/spicy-noise/blob/master/zeek/spicy-noise.zeek)|
|various tunnel protocols (e.g., GTP, GRE, Teredo, AYIYA, IP-in-IP, etc.)|[🔗](https://en.wikipedia.org/wiki/Tunneling_protocol)||[✓](https://github.com/arkime/arkime/blob/master/capture/packet.c)|[✓](https://docs.zeek.org/en/stable/scripts/base/frameworks/tunnels/main.zeek.html#type-Tunnel::Info)|

Additionally, Zeek is able to detect and, where possible, log the type, vendor and version of [various](https://docs.zeek.org/en/stable/scripts/base/frameworks/software/main.zeek.html#type-Software::Type) other [software protocols](https://en.wikipedia.org/wiki/Application_layer).

As part of its network traffic analysis, Zeek can extract and analyze files transferred across the protocols it understands. In addition to generating logs for transferred files, deeper analysis is done into the following file types:

* [Portable executable](https://docs.zeek.org/en/stable/scripts/base/files/pe/main.zeek.html#type-PE::Info) files
* [X.509](https://docs.zeek.org/en/stable/scripts/base/files/x509/main.zeek.html#type-X509::Info) certificates

See [automatic file extraction and scanning](#ZeekFileExtraction) for additional features related to file scanning.

See [Zeek log integration](#ArkimeZeek) for more information on how Malcolm integrates [Arkime sessions and Zeek logs](#ZeekArkimeFlowCorrelation) for analysis. 

## <a name="Development"></a>Development

Checking out the [Malcolm source code](https://github.com/idaholab/Malcolm/tree/master) results in the following subdirectories in your `malcolm/` working copy:

* `Dockerfiles` - a directory containing build instructions for Malcolm's docker images
* `docs` - a directory containing instructions and documentation
* `elasticsearch` - an initially empty directory where the Elasticsearch database instance will reside
* `elasticsearch-backup` - an initially empty directory for storing Elasticsearch [index snapshots](#IndexManagement) 
* `filebeat` - code and configuration for the `filebeat` container which ingests Zeek logs and forwards them to the `logstash` container
* `file-monitor` - code and configuration for the `file-monitor` container which can scan files extracted by Zeek
* `file-upload` - code and configuration for the `upload` container which serves a web browser-based upload form for uploading PCAP files and Zeek logs, and which serves an SFTP share as an alternate method for upload
* `freq-server` - code and configuration for the `freq` container used for calculating entropy of strings
* `htadmin` - configuration for the `htadmin` user account management container
* `kibana` - code and configuration for the `kibana` container for creating additional ad-hoc visualizations and dashboards beyond that which is provided by Arkime Viewer
* `logstash` - code and configuration for the `logstash` container which parses Zeek logs and forwards them to the `elasticsearch` container
* `malcolm-iso` - code and configuration for building an [installer ISO](#ISO) for a minimal Debian-based Linux installation for running Malcolm
* `moloch` - code and configuration for the `arkime` container which processes PCAP files using `moloch-capture` and which serves the Viewer application
* `moloch-logs` - an initially empty directory to which the `arkime` container will write some debug log files
* `moloch-raw` - an initially empty directory to which the `arkime` container will write captured PCAP files; as Arkime as employed by Malcolm is currently used for processing previously-captured PCAP files, this directory is currently unused
* `name-map-ui` - code and configuration for the `name-map-ui` container which provides the [host and subnet name mapping](#HostAndSubnetNaming) interface
* `nginx` - configuration for the `nginx` reverse proxy container
* `pcap` - an initially empty directory for PCAP files to be uploaded, processed, and stored
* `pcap-capture` - code and configuration for the `pcap-capture` container which can capture network traffic
* `pcap-monitor` - code and configuration for the `pcap-monitor` container which watches for new or uploaded PCAP files notifies the other services to process them
* `scripts` - control scripts for starting, stopping, restarting, etc. Malcolm
* `sensor-iso` - code and configuration for building a [Hedgehog Linux](#Hedgehog) ISO
* `shared` - miscellaneous code used by various Malcolm components 
* `zeek` - code and configuration for the `zeek` container which handles PCAP processing using Zeek
* `zeek-logs` - an initially empty directory for Zeek logs to be uploaded, processed, and stored

and the following files of special note:

* `auth.env` - the script `./scripts/auth_setup` prompts the user for the administrator credentials used by the Malcolm appliance, and `auth.env` is the environment file where those values are stored
* `cidr-map.txt` - specify custom IP address to network segment mapping
* `host-map.txt` - specify custom IP and/or MAC address to host mapping
* `net-map.json` - an alternative to `cidr-map.txt` and `host-map.txt`, mapping hosts and network segments to their names in a JSON-formatted file
* `docker-compose.yml` - the configuration file used by `docker-compose` to build, start, and stop an instance of the Malcolm appliance
* `docker-compose-standalone.yml` - similar to `docker-compose.yml`, only used for the ["packaged"](#Packager) installation of Malcolm

### <a name="Build"></a>Building from source

Building the Malcolm docker images from scratch requires internet access to pull source files for its components. Once internet access is available, execute the following command to build all of the Docker images used by the Malcolm appliance:

```
$ ./scripts/build.sh
```

Then, go take a walk or something since it will be a while. When you're done, you can run `docker images` and see you have fresh images for:

* `malcolmnetsec/arkime` (based on `debian:buster-slim`)
* `malcolmnetsec/elasticsearch-od` (based on `amazon/opendistro-for-elasticsearch`)
* `malcolmnetsec/filebeat-oss` (based on `docker.elastic.co/beats/filebeat-oss`)
* `malcolmnetsec/file-monitor` (based on `debian:buster-slim`)
* `malcolmnetsec/file-upload` (based on `debian:buster-slim`)
* `malcolmnetsec/freq` (based on `debian:buster-slim`)
* `malcolmnetsec/htadmin` (based on `debian:buster-slim`)
* `malcolmnetsec/kibana-od` (based on `amazon/opendistro-for-elasticsearch-kibana`)
* `malcolmnetsec/kibana-helper` (based on `alpine:3.12`)
* `malcolmnetsec/logstash-oss` (based on `docker.elastic.co/logstash/logstash-oss`)
* `malcolmnetsec/name-map-ui` (based on `alpine:3.12`)
* `malcolmnetsec/nginx-proxy` (based on `alpine:3.12`)
* `malcolmnetsec/pcap-capture` (based on `debian:buster-slim`)
* `malcolmnetsec/pcap-monitor` (based on `debian:buster-slim`)
* `malcolmnetsec/pcap-zeek` (based on `debian:buster-slim`)

## <a name="Packager"></a>Pre-Packaged installation files

### Creating pre-packaged installation files

`scripts/malcolm_appliance_packager.sh` can be run to package up the configuration files (and, if necessary, the Docker images) which can be copied to a network share or USB drive for distribution to non-networked machines. For example:

```
$ ./scripts/malcolm_appliance_packager.sh 
You must set a username and password for Malcolm, and self-signed X.509 certificates will be generated

Store administrator username/password for local Malcolm access? (Y/n): 

Administrator username: analyst
analyst password: 
analyst password (again): 

(Re)generate self-signed certificates for HTTPS access (Y/n): 

(Re)generate self-signed certificates for a remote log forwarder (Y/n): 

Store username/password for forwarding Logstash events to a secondary, external Elasticsearch instance (y/N): 

Store username/password for email alert sender account (y/N): 

Packaged Malcolm to "/home/user/tmp/malcolm_20190513_101117_f0d052c.tar.gz"

Do you need to package docker images also [y/N]? y
This might take a few minutes...

Packaged Malcolm docker images to "/home/user/tmp/malcolm_20190513_101117_f0d052c_images.tar.gz"


To install Malcolm:
  1. Run install.py
  2. Follow the prompts

To start, stop, restart, etc. Malcolm:
  Use the control scripts in the "scripts/" directory:
   - start         (start Malcolm)
   - stop          (stop Malcolm)
   - restart       (restart Malcolm)
   - logs          (monitor Malcolm logs)
   - wipe          (stop Malcolm and clear its database)
   - auth_setup    (change authentication-related settings)

A minute or so after starting Malcolm, the following services will be accessible:
  - Arkime: https://localhost/
  - Kibana: https://localhost/kibana/
  - PCAP upload (web): https://localhost/upload/
  - PCAP upload (sftp): sftp://USERNAME@127.0.0.1:8022/files/
  - Host and subnet name mapping editor: https://localhost/name-map-ui/
  - Account management: https://localhost:488/
```

The above example will result in the following artifacts for distribution as explained in the script's output:

```
$ ls -lh
total 2.0G
-rwxr-xr-x 1 user user  61k May 13 11:32 install.py
-rw-r--r-- 1 user user 2.0G May 13 11:37 malcolm_20190513_101117_f0d052c_images.tar.gz
-rw-r--r-- 1 user user  683 May 13 11:37 malcolm_20190513_101117_f0d052c.README.txt
-rw-r--r-- 1 user user 183k May 13 11:32 malcolm_20190513_101117_f0d052c.tar.gz
```

### Installing from pre-packaged installation files

If you have obtained pre-packaged installation files to install Malcolm on a non-networked machine via an internal network share or on a USB key, you likely have the following files:

* `malcolm_YYYYMMDD_HHNNSS_xxxxxxx.README.txt` - This readme file contains a minimal set up instructions for extracting the contents of the other tarballs and running the Malcolm appliance.
* `malcolm_YYYYMMDD_HHNNSS_xxxxxxx.tar.gz` - This tarball contains the configuration files and directory configuration used by an instance of Malcolm. It can be extracted via `tar -xf malcolm_YYYYMMDD_HHNNSS_xxxxxxx.tar.gz` upon which a directory will be created (named similarly to the tarball) containing the directories and configuration files. Alternatively, `install.py` can accept this filename as an argument and handle its extraction and initial configuration for you.
* `malcolm_YYYYMMDD_HHNNSS_xxxxxxx_images.tar.gz` - This tarball contains the Docker images used by Malcolm. It can be imported manually via `docker load -i malcolm_YYYYMMDD_HHNNSS_xxxxxxx_images.tar.gz`
* `install.py` - This install script can load the Docker images and extract Malcolm configuration files from the aforementioned tarballs and do some initial configuration for you.

Run `install.py malcolm_XXXXXXXX_XXXXXX_XXXXXXX.tar.gz` and follow the prompts. If you do not already have Docker and Docker Compose installed, the `install.py` script will help you install them.

## <a name="Preparing"></a>Preparing your system

### <a name="SystemRequirements"></a>Recommended system requirements

Malcolm runs on top of [Docker](https://www.docker.com/) which runs on recent releases of Linux, Apple macOS and Microsoft Windows 10.

To quote the [Elasticsearch documentation](https://www.elastic.co/guide/en/elasticsearch/guide/current/hardware.html), "If there is one resource that you will run out of first, it will likely be memory." The same is true for Malcolm: you will want at least 16 gigabytes of RAM to run Malcolm comfortably. For processing large volumes of traffic, I'd recommend at a bare minimum a dedicated server with 16 cores and 16 gigabytes of RAM. Malcolm can run on less, but more is better. You're going to want as much hard drive space as possible, of course, as the amount of PCAP data you're able to analyze and store will be limited by your hard drive.

Arkime's wiki has a couple of documents ([here](https://github.com/arkime/arkime#hardware-requirements) and [here](https://github.com/arkime/arkime/wiki/FAQ#what-kind-of-capture-machines-should-we-buy) and [here](https://github.com/arkime/arkime/wiki/FAQ#how-many-elasticsearch-nodes-or-machines-do-i-need) and a [calculator here](https://molo.ch/#estimators)) which may be helpful, although not everything in those documents will apply to a Docker-based setup like Malcolm.

### <a name="ConfigAndTuning"></a>System configuration and tuning

If you already have Docker and Docker Compose installed, the `install.py` script can still help you tune system configuration and `docker-compose.yml` parameters for Malcolm. To run it in "configuration only" mode, bypassing the steps to install Docker and Docker Compose, run it like this:
```
./scripts/install.py --configure
```

Although `install.py` will attempt to automate many of the following configuration and tuning parameters, they are nonetheless listed in the following sections for reference:

#### <a name="DockerComposeYml"></a>`docker-compose.yml` parameters

Edit `docker-compose.yml` and search for the `ES_JAVA_OPTS` key. Edit the `-Xms4g -Xmx4g` values, replacing `4g` with a number that is half of your total system memory, or just under 32 gigabytes, whichever is less. So, for example, if I had 64 gigabytes of memory I would edit those values to be `-Xms31g -Xmx31g`. This indicates how much memory can be allocated to the Elasticsearch heaps. For a pleasant experience, I would suggest not using a value under 10 gigabytes. Similar values can be modified for Logstash with `LS_JAVA_OPTS`, where using 3 or 4 gigabytes is recommended.

Various other environment variables inside of `docker-compose.yml` can be tweaked to control aspects of how Malcolm behaves, particularly with regards to processing PCAP files and Zeek logs. The environment variables of particular interest are located near the top of that file under **Commonly tweaked configuration options**, which include:

* `PUID` and `PGID` - Docker runs all of its containers as the privileged `root` user by default. For better security, Malcolm immediately drops to non-privileged user accounts for executing internal processes wherever possible. The `PUID` (**p**rocess **u**ser **ID**) and `PGID` (**p**rocess **g**roup **ID**) environment variables allow Malcolm to map internal non-privileged user accounts to a corresponding [user account](https://en.wikipedia.org/wiki/User_identifier) on the host.

* `NGINX_BASIC_AUTH` - if set to `true`, use [TLS-encrypted HTTP basic](#AuthBasicAccountManagement) authentication (default); if set to `false`, use [Lightweight Directory Access Protocol (LDAP)](#AuthLDAP) authentication

* `NGINX_LOG_ACCESS_AND_ERRORS` - if set to `true`, all access to Malcolm via its [web interfaces](#UserInterfaceURLs) will be logged to Elasticsearch (default `false`)

* `MANAGE_PCAP_FILES` – if set to `true`, all PCAP files imported into Malcolm will be marked as available for deletion by Arkime if available storage space becomes too low (default `false`)

* `ZEEK_AUTO_ANALYZE_PCAP_FILES` – if set to `true`, all PCAP files imported into Malcolm will automatically be analyzed by Zeek, and the resulting logs will also be imported (default `false`)

* `ZEEK_DISABLE_...` - if set to any non-blank value, each of these variables can be used to disable a certain Zeek function when it analyzes PCAP files (for example, setting `ZEEK_DISABLE_LOG_PASSWORDS` to `true` to disable logging of cleartext passwords)

* `MAXMIND_GEOIP_DB_LICENSE_KEY` - Malcolm uses MaxMind's free GeoLite2 databases for GeoIP lookups. As of December 30, 2019, these databases are [no longer available](https://blog.maxmind.com/2019/12/18/significant-changes-to-accessing-and-using-geolite2-databases/) for download via a public URL. Instead, they must be downloaded using a MaxMind license key (available without charge [from MaxMind](https://www.maxmind.com/en/geolite2/signup)). The license key can be specified here for GeoIP database downloads during build- and run-time.

* `ARKIME_ANALYZE_PCAP_THREADS` – the number of threads available to Arkime for analyzing PCAP files (default `1`)

* `ZEEK_AUTO_ANALYZE_PCAP_THREADS` – the number of threads available to Malcolm for analyzing Zeek logs (default `1`)

* `LOGSTASH_OUI_LOOKUP` – if set to `true`, Logstash will map MAC addresses to vendors for all source and destination MAC addresses when analyzing Zeek logs (default `true`)

* `LOGSTASH_REVERSE_DNS` – if set to `true`, Logstash will perform a reverse DNS lookup for all external source and destination IP address values when analyzing Zeek logs (default `false`)

* `ES_EXTERNAL_HOSTS` – if specified (in the format `'10.0.0.123:9200'`), logs received by Logstash will be forwarded on to another external Elasticsearch instance in addition to the one maintained locally by Malcolm

* `ES_EXTERNAL_SSL` –  if set to `true`, Logstash will use HTTPS for the connection to external Elasticsearch instances specified in `ES_EXTERNAL_HOSTS`

* `ES_EXTERNAL_SSL_CERTIFICATE_VERIFICATION` – if set to `true`, Logstash will require full SSL certificate validation; this may fail if using self-signed certificates (default `false`)

* `AUTO_TAG` – if set to `true`, Malcolm will automatically create Arkime sessions and Zeek logs with tags based on the filename, as described in [Tagging](#Tagging) (default `true`)

* `BEATS_SSL` – if set to `true`, Logstash will use require encrypted communications for any external Beats-based forwarders from which it will accept logs; if Malcolm is being used as a standalone tool then this can safely be set to `false`, but if external log feeds are to be accepted then setting it to true is recommended (default `false`)

* `ZEEK_EXTRACTOR_MODE` – determines the file extraction behavior for file transfers detected by Zeek; see [Automatic file extraction and scanning](#ZeekFileExtraction) for more details

* `EXTRACTED_FILE_IGNORE_EXISTING` – if set to `true`, files extant in `./zeek-logs/extract_files/`  directory will be ignored on startup rather than scanned

* `EXTRACTED_FILE_PRESERVATION` – determines behavior for preservation of [Zeek-extracted files](#ZeekFileExtraction)

* `VTOT_API2_KEY` – used to specify a [VirusTotal Public API v.20](https://www.virustotal.com/en/documentation/public-api/) key, which, if specified, will be used to submit hashes of [Zeek-extracted files](#ZeekFileExtraction) to VirusTotal

* `EXTRACTED_FILE_ENABLE_YARA` – if set to `true`, [Zeek-extracted files](#ZeekFileExtraction) will be scanned with [Yara](https://github.com/VirusTotal/yara)

* `EXTRACTED_FILE_YARA_CUSTOM_ONLY` – if set to `true`, Malcolm will bypass the default [Yara ruleset](https://github.com/Neo23x0/signature-base) and use only user-defined rules in `./yara/rules`

* `EXTRACTED_FILE_ENABLE_CAPA` – if set to `true`, [Zeek-extracted files](#ZeekFileExtraction) that are determined to be PE (portable executable) files will be scanned with [Capa](https://github.com/fireeye/capa)

* `EXTRACTED_FILE_CAPA_VERBOSE` – if set to `true`, all Capa rule hits will be logged; otherwise (`false`) only [MITRE ATT&CK technique](https://attack.mitre.org/techniques) classifications will be logged

* `EXTRACTED_FILE_ENABLE_CLAMAV` – if set to `true`, [Zeek-extracted files](#ZeekFileExtraction) will be scanned with [ClamAV](https://www.clamav.net/)

* `EXTRACTED_FILE_UPDATE_RULES` – if set to `true`, file scanner engines (e.g., ClamAV, Capa, Yara) will periodically update their rule definitions

* `EXTRACTED_FILE_HTTP_SERVER_ENABLE` – if set to `true`, the directory containing [Zeek-extracted files](#ZeekFileExtraction) will be served over HTTP at `./extracted-files/` (e.g., [https://localhost/extracted-files/](https://localhost/extracted-files/) if you are connecting locally)

* `EXTRACTED_FILE_HTTP_SERVER_ENCRYPT` – if set to `true`, those Zeek-extracted files will be AES-256-CBC-encrypted in an `openssl enc`-compatible format (e.g., `openssl enc -aes-256-cbc -d -in example.exe.encrypted -out example.exe`)

* `EXTRACTED_FILE_HTTP_SERVER_KEY` – specifies the AES-256-CBC decryption password for encrypted Zeek-extracted files; used in conjunction with `EXTRACTED_FILE_HTTP_SERVER_ENCRYPT`

* `PCAP_ENABLE_NETSNIFF` – if set to `true`, Malcolm will capture network traffic on the local network interface(s) indicated in `PCAP_IFACE` using [netsniff-ng](http://netsniff-ng.org/)

* `PCAP_ENABLE_TCPDUMP` – if set to `true`, Malcolm will capture network traffic on the local network interface(s) indicated in `PCAP_IFACE` using [tcpdump](https://www.tcpdump.org/); there is no reason to enable *both* `PCAP_ENABLE_NETSNIFF` and `PCAP_ENABLE_TCPDUMP`

* `PCAP_IFACE` – used to specify the network interface(s) for local packet capture if `PCAP_ENABLE_NETSNIFF` or `PCAP_ENABLE_TCPDUMP` are enabled; for multiple interfaces, separate the interface names with a comma (e.g., `'enp0s25'` or `'enp10s0,enp11s0'`)

* `PCAP_ROTATE_MEGABYTES` – used to specify how large a locally-captured PCAP file can become (in megabytes) before it closed for processing and a new PCAP file created 

* `PCAP_ROTATE_MINUTES` – used to specify an time interval (in minutes) after which a locally-captured PCAP file will be closed for processing and a new PCAP file created

* `PCAP_FILTER` – specifies a tcpdump-style filter expression for local packet capture; leave blank to capture all traffic

#### <a name="HostSystemConfigLinux"></a>Linux host system configuration

##### Installing Docker

Docker installation instructions vary slightly by distribution. Please follow the links below to docker.com to find the instructions specific to your distribution:

* [Ubuntu](https://docs.docker.com/install/linux/docker-ce/ubuntu/)
* [Debian](https://docs.docker.com/install/linux/docker-ce/debian/)
* [Fedora](https://docs.docker.com/install/linux/docker-ce/fedora/)
* [CentOS](https://docs.docker.com/install/linux/docker-ce/centos/)
* [Binaries](https://docs.docker.com/install/linux/docker-ce/binaries/)

After installing Docker, because Malcolm should be run as a non-root user, add your user to the `docker` group with something like:
```
$ sudo usermod -aG docker yourusername
```

Following this, either reboot or log out then log back in.

Docker starts automatically on DEB-based distributions. On RPM-based distributions, you need to start it manually or enable it using the appropriate `systemctl` or `service` command(s).

You can test docker by running `docker info`, or (assuming you have internet access), `docker run --rm hello-world`.

##### Installing docker-compose

Please follow [this link](https://docs.docker.com/compose/install/) on docker.com for instructions on installing docker-compose.

##### Operating system configuration

The host system (ie., the one running Docker) will need to be configured for the [best possible Elasticsearch performance](https://www.elastic.co/guide/en/elasticsearch/reference/master/system-config.html). Here are a few suggestions for Linux hosts (these may vary from distribution to distribution):

* Append the following lines to `/etc/sysctl.conf`:

```
# the maximum number of open file handles
fs.file-max=2097152

# increase maximums for inotify watches
fs.inotify.max_user_watches=131072
fs.inotify.max_queued_events=131072
fs.inotify.max_user_instances=512

# the maximum number of memory map areas a process may have
vm.max_map_count=262144

# decrease "swappiness" (swapping out runtime memory vs. dropping pages)
vm.swappiness=1

# the maximum number of incoming connections
net.core.somaxconn=65535

# the % of system memory fillable with "dirty" pages before flushing
vm.dirty_background_ratio=40

# maximum % of dirty system memory before committing everything
vm.dirty_ratio=80
```

* Depending on your distribution, create **either** the file `/etc/security/limits.d/limits.conf` containing:

```
# the maximum number of open file handles
* soft nofile 65535
* hard nofile 65535
# do not limit the size of memory that can be locked
* soft memlock unlimited
* hard memlock unlimited
```

**OR** the file `/etc/systemd/system.conf.d/limits.conf` containing: 

```
[Manager]
# the maximum number of open file handles
DefaultLimitNOFILE=65535:65535
# do not limit the size of memory that can be locked
DefaultLimitMEMLOCK=infinity
```

* Change the readahead value for the disk where the Elasticsearch data will be stored. There are a few ways to do this. For example, you could add this line to `/etc/rc.local` (replacing `/dev/sda` with your disk block descriptor):

```
# change disk read-adhead value (# of blocks)
blockdev --setra 512 /dev/sda
```

* Change the I/O scheduler to `deadline` or `noop`. Again, this can be done in a variety of ways. The simplest is to add `elevator=deadline` to the arguments in `GRUB_CMDLINE_LINUX` in `/etc/default/grub`, then running `sudo update-grub2`

* If you are planning on using very large data sets, consider formatting the drive containing `elasticsearch` volume as XFS.

After making all of these changes, do a reboot for good measure!

#### <a name="HostSystemConfigMac"></a>macOS host system configuration

##### Automatic installation using `install.py`

The `install.py` script will attempt to guide you through the installation of Docker and Docker Compose if they are not present. If that works for you, you can skip ahead to **Configure docker daemon option** in this section.

##### Install Homebrew

The easiest way to install and maintain docker on Mac is using the [Homebrew cask](https://brew.sh). Execute the following in a terminal.

```
$ /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
$ brew install cask
$ brew tap homebrew/cask-versions
```

##### Install docker-edge

```
$ brew cask install docker-edge
```
This will install the latest version of docker and docker-compose. It can be upgraded later using `brew` as well:
```
$ brew cask upgrade --no-quarantine docker-edge
```
You can now run docker from the Applications folder.

##### Configure docker daemon option

Some changes should be made for performance ([this link](http://markshust.com/2018/01/30/performance-tuning-docker-mac) gives a good succinct overview).

* **Resource allocation** - For a good experience, you likely need at least a quad-core MacBook Pro with 16GB RAM and an SSD. I have run Malcolm on an older 2013 MacBook Pro with 8GB of RAM, but the more the better. Go in your system tray and select **Docker** → **Preferences** → **Advanced**. Set the resources available to docker to at least 4 CPUs and 8GB of RAM (>= 16GB is preferable).

* **Volume mount performance** - You can speed up performance of volume mounts by removing unused paths from **Docker** → **Preferences** → **File Sharing**. For example, if you’re only going to be mounting volumes under your home directory, you could share `/Users` but remove other paths.

After making these changes, right click on the Docker 🐋 icon in the system tray and select **Restart**.

#### <a name="HostSystemConfigWindows"></a>Windows host system configuration

#### <a name="HostSystemConfigWindowsDocker"></a>Installing and configuring Docker Desktop for Windows

Installing and configuring Docker to run under Windows must be done manually, rather than through the `install.py` script as is done for Linux and macOS.

1. In order to be able to configure Docker volume mounts correctly, you should be running [Windows 10, version 1803](https://docs.microsoft.com/en-us/windows/whats-new/whats-new-windows-10-version-1803) or higher.
1. The control scripts in the `scripts/` directory are written for Python 3. They also rely on a few other utilities such as OpenSSL and htpasswd. The easiest way to run these tools in Windows is using the [Windows Subsystem for Linux](https://docs.microsoft.com/en-us/windows/wsl/install-win10) (WSL) (however, they may also be installed and configured manually: [Python 3](https://www.python.org/downloads/windows); [OpenSSL](https://wiki.openssl.org/index.php/Binaries); [htpasswd](https://httpd.apache.org/docs/current/platform/windows.html#down), download the `httpd….zip` file and extract `htpasswd.exe` from the `Apache…\bin\` directory). To install WSL, run the following command in PowerShell as Administrator:
    + `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux`
1. Install the [Linux distribution of your choice](https://docs.microsoft.com/en-us/windows/wsl/install-win10#install-your-linux-distribution-of-choice) in WSL. These instructions have been tested using Debian, but will probably work with other distributions as well.
1. Run the following commands in PowerShell as Administrator to enable required Windows features:
    + `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All`
    + `Enable-WindowsOptionalFeature -Online -FeatureName Containers –All`
1. If you have not yet done so after enabling the Windows features, reboot.
1. Install [Docker Desktop for Windows](https://hub.docker.com/editions/community/docker-ce-desktop-windows) either by downloading the installer from the official Docker site or installing it through [chocolatey](https://chocolatey.org/packages/docker-desktop).
1. Run **Docker Desktop**, click the **Settings** option in the Docker system tray menu and make the following adjustments:
    + **General**
        * Ensure *Start Docker Desktop when you log in* is checked.
    + **Shared Drives**
        * Mark the drive onto which Malcolm is installed as *Shared* (e.g., check *Shared* for drive *C*).
    + **Advanced**
        + Increase *CPUs* to as many as you're comfortable with (at least *4* is best).
        + Increase *Memory* to as much as you're comfortable with (at least *16* is recommended, no fewer than *10*).
        + Increase *Disk image max size* to however much space you want Malcolm to have available to it (ideally at least several hundred gigabytes), and change the *Disk image location* if needed to accommodate it.
1. Make sure Docker applies/restarts (or just reboot), then go back in and check the **Advanced** settings to make sure things stick.
1. To ensure Docker volume mounts work correctly when using WSL, WSL needs to be configured to mount at `/` instead of at `/mnt`. Inside your WSL Bash shell, run the following command to write `/etc/wsl.conf` to specify the WSL mount point:
    + `echo -e '[automount]\nroot = /\noptions = "metadata"' | sudo tee /etc/wsl.conf`
1. Reboot.
1. Run `docker info` in PowerShell to make sure Docker is running.
1. Open a shell in your WSL distribution and run `docker.exe info` to make sure Docker is accessible from within WSL.
    + Previous versions of WSL required the native Linux `docker` command-line client to interact with the Windows Desktop Docker server. Recent improvements to WSL allow the Windows executables `docker-compose.exe` and `docker.exe` to be run seamlessly in WSL. Malcolm's control scripts detect this scenario.

#### <a name="HostSystemConfigWindowsMalcolm"></a>Finish Malcolm's configuration

Once Docker is installed, configured and running as described in the previous section, run [`./scripts/install.py --configure`](#ConfigAndTuning) (in WSL it will probably be something like `sudo ./scripts/install.py --configure`) to finish configuration of the local Malcolm installation.

The control scripts outlined in the [Running Malcolm](#Running) section may not be symlinked correctly under Windows. Rather than running `./scripts/start`, `./scripts/stop`, etc., you can run `./scripts/control.py --start`, `./scripts/control.py --stop`, etc. to the same effect.

## <a name="Running"></a>Running Malcolm

### <a name="AuthSetup"></a>Configure authentication

Malcolm requires authentication to access the [user interface](#UserInterfaceURLs). [Nginx](https://nginx.org/) can authenticate users with either local TLS-encrypted HTTP basic authentication or using a remote Lightweight Directory Access Protocol (LDAP) authentication server.

With the local basic authentication method, user accounts are managed by Malcolm and can be created, modified, and deleted using a [user management web interface](#AccountManagement). This method is suitable in instances where accounts and credentials do not need to be synced across many Malcolm installations.

LDAP authentication are managed on a remote directory service, such as a [Microsoft Active Directory Domain Services](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview) or [OpenLDAP](https://www.openldap.org/).

Malcolm's authentication method is defined in the `x-auth-variables` section near the top of the [`docker-compose.yml`](#DockerComposeYml) file with the `NGINX_BASIC_AUTH` environment variable: `true` for local TLS-encrypted HTTP basic authentication, `false` for LDAP authentication.

In either case, you **must** run `./scripts/auth_setup` before starting Malcolm for the first time in order to:

* define the local Malcolm administrator account username and password (although these credentials will only be used for basic authentication, not LDAP authentication)
* specify whether or not to (re)generate the self-signed certificates used for HTTPS access
    * key and certificate files are located in the `nginx/certs/` directory
* specify whether or not to (re)generate the self-signed certificates used by a remote log forwarder (see the `BEATS_SSL` environment variable above)
    * certificate authority, certificate, and key files for Malcolm’s Logstash instance are located in the `logstash/certs/` directory
    * certificate authority, certificate, and key files to be copied to and used by the remote log forwarder are located in the `filebeat/certs/` directory
* specify whether or not to store the username/password for forwarding Logstash events to a secondary, external Elasticsearch instance (see the `ES_EXTERNAL_HOSTS`, `ES_EXTERNAL_SSL`, and `ES_EXTERNAL_SSL_CERTIFICATE_VERIFICATION` environment variables above)
    * these parameters are stored securely in the Logstash keystore file `logstash/certs/logstash.keystore`
* specify whether or not to [store the username/password](https://opendistro.github.io/for-elasticsearch-docs/docs/alerting/monitors/#authenticate-sender-account) for [email alert senders](https://opendistro.github.io/for-elasticsearch-docs/docs/alerting/monitors/#create-destinations)
    * these parameters are stored securely in the Elasticsearch keystore file `elasticsearch/elasticsearch.keystore`

##### <a name="AuthBasicAccountManagement"></a>Local account management

[`auth_setup`](#AuthSetup) is used to define the username and password for the administrator account. Once Malcolm is running, the administrator account can be used to manage other user accounts via a **Malcolm User Management** page served over HTTPS on port 488 (e.g., [https://localhost:488](https://localhost:488) if you are connecting locally).

Malcolm user accounts can be used to access the [interfaces](#UserInterfaceURLs) of all of its [components](#Components), including Arkime. Arkime uses its own internal database of user accounts, so when a Malcolm user account logs in to Arkime for the first time Malcolm creates a corresponding Arkime user account automatically. This being the case, it is *not* recommended to use the Arkime **Users** settings page or change the password via the **Password** form under the Arkime **Settings** page, as those settings would not be consistently used across Malcolm.

Users may change their passwords via the **Malcolm User Management** page by clicking **User Self Service**. A forgotten password can also be reset via an emailed link, though this requires SMTP server settings to be specified in `htadmin/config.ini` in the Malcolm installation directory.

#### <a name="AuthLDAP"></a>Lightweight Directory Access Protocol (LDAP) authentication

The [nginx-auth-ldap](https://github.com/kvspb/nginx-auth-ldap) module serves as the interface between Malcolm's [Nginx](https://nginx.org/) web server and a remote LDAP server. When you run [`auth_setup`](#AuthSetup) for the first time, a sample LDAP configuration file is created at `nginx/nginx_ldap.conf`. 

```
# This is a sample configuration for the ldap_server section of nginx.conf.
# Yours will vary depending on how your Active Directory/LDAP server is configured.
# See https://github.com/kvspb/nginx-auth-ldap#available-config-parameters for options.

ldap_server ad_server {
  url "ldap://ds.example.com:3268/DC=ds,DC=example,DC=com?sAMAccountName?sub?(objectClass=person)";

  binddn "bind_dn";
  binddn_passwd "bind_dn_password";

  group_attribute member;
  group_attribute_is_dn on;
  require group "CN=Malcolm,CN=Users,DC=ds,DC=example,DC=com";
  require valid_user;
  satisfy all;
}

auth_ldap_cache_enabled on;
auth_ldap_cache_expiration_time 10000;
auth_ldap_cache_size 1000;
```

This file is mounted into the `nginx` container when Malcolm is started to provide connection information for the LDAP server.

The contents of `nginx_ldap.conf` will vary depending on how the LDAP server is configured. Some of the [avaiable parameters](https://github.com/kvspb/nginx-auth-ldap#available-config-parameters) in that file include:

* **`url`** - the `ldap://` or `ldaps://` connection URL for the remote LDAP server, which has the [following syntax](https://www.ietf.org/rfc/rfc2255.txt): `ldap[s]://<hostname>:<port>/<base_dn>?<attributes>?<scope>?<filter>`
* **`binddn`** and **`binddn_password`** - the account credentials used to query the LDAP directory
* **`group_attribute`** - the group attribute name which contains the member object (e.g., `member` or `memberUid`)
* **`group_attribute_is_dn`** - whether or not to search for the user's full distinguished name as the value in the group's member attribute
* **`require`** and **`satisfy`** - `require user`, `require group` and `require valid_user` can be used in conjunction with `satisfy any` or `satisfy all` to limit the users that are allowed to access the Malcolm instance

Before starting Malcolm, edit `nginx/nginx_ldap.conf` according to the specifics of your LDAP server and directory tree structure. Using a LDAP search tool such as [`ldapsearch`](https://www.openldap.org/software/man.cgi?query=ldapsearch) in Linux or [`dsquery`](https://social.technet.microsoft.com/wiki/contents/articles/2195.active-directory-dsquery-commands.aspx) in Windows may be of help as you formulate the configuration. Your changes should be made within the curly braces of the `ldap_server ad_server { … }` section. You can troubleshoot configuration file syntax errors and LDAP connection or credentials issues by running `./scripts/logs` (or `docker-compose logs nginx`) and examining the output of the `nginx` container.

The **Malcolm User Management** page described above is not available when using LDAP authentication.

##### <a name="AuthLDAPSecurity"></a>LDAP connection security

Authentication over LDAP can be done using one of three ways, [two of which](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8e73932f-70cf-46d6-88b1-8d9f86235e81) offer data confidentiality protection: 

* **StartTLS** - the [standard extension](https://tools.ietf.org/html/rfc2830) to the LDAP protocol to establish an encrypted SSL/TLS connection within an already established LDAP connection
* **LDAPS** - a commonly used (though unofficial and considered deprecated) method in which SSL negotiation takes place before any commands are sent from the client to the server
* **Unencrypted** (clear text) (***not recommended***)

In addition to the `NGINX_BASIC_AUTH` environment variable being set to `false` in the `x-auth-variables` section near the top of the [`docker-compose.yml`](#DockerComposeYml) file, the `NGINX_LDAP_TLS_STUNNEL` and `NGINX_LDAP_TLS_STUNNEL` environment variables are used in conjunction with the values in `nginx/nginx_ldap.conf` to define the LDAP connection security level. Use the following combinations of values to achieve the connection security methods above, respectively:

* **StartTLS**
    - `NGINX_LDAP_TLS_STUNNEL` set to `true` in [`docker-compose.yml`](#DockerComposeYml)
    - `NGINX_LDAP_TLS_STUNNEL_PROTOCOL` set to `winldap` (for Microsoft Active Directory Domain Services) or `openldap` (for OpenLDAP) in [`docker-compose.yml`](#DockerComposeYml)
    - `url` should begin with `ldap://` and its port should be either the default LDAP port (389) or the default Global Catalog port (3268) in `nginx/nginx_ldap.conf` 
* **LDAPS**
    - `NGINX_LDAP_TLS_STUNNEL` set to `false` in [`docker-compose.yml`](#DockerComposeYml)
    - `url` should begin with `ldaps://` and its port should be either the default LDAPS port (636) or the default LDAPS Global Catalog port (3269) in `nginx/nginx_ldap.conf` 
* **Unencrypted** (clear text) (***not recommended***)
    - `NGINX_LDAP_TLS_STUNNEL` set to `false` in [`docker-compose.yml`](#DockerComposeYml)
    - `url` should begin with `ldap://` and its port should be either the default LDAP port (389) or the default Global Catalog port (3268) in `nginx/nginx_ldap.conf` 

For encrypted connections (whether using **StartTLS** or **LDAPS**), Malcolm will require and verify certificates when one or more trusted CA certificate files are placed in the `nginx/ca-trust/` directory. Otherwise, any certificate presented by the domain server will be accepted.

### <a name="Starting"></a>Starting Malcolm

[Docker compose](https://docs.docker.com/compose/) is used to coordinate running the Docker containers. To start Malcolm, navigate to the directory containing `docker-compose.yml` and run:
```
$ ./scripts/start
```
This will create the containers' virtual network and instantiate them, then leave them running in the background. The Malcolm containers may take a several minutes to start up completely. To follow the debug output for an already-running Malcolm instance, run:
```
$ ./scripts/logs
```
You can also use `docker stats` to monitor the resource utilization of running containers.

### <a name="StopAndRestart"></a>Stopping and restarting Malcolm

You can run `./scripts/stop` to stop the docker containers and remove their virtual network. Alternatively, `./scripts/restart` will restart an instance of Malcolm. Because the data on disk is stored on the host in docker volumes, doing these operations will not result in loss of data. 

Malcolm can be configured to be automatically restarted when the Docker system daemon restart (for example, on system reboot). This behavior depends on the [value](https://docs.docker.com/config/containers/start-containers-automatically/) of the [`restart:`](https://docs.docker.com/compose/compose-file/#restart) setting for each service in the `docker-compose.yml` file. This value can be set by running [`./scripts/install.py --configure`](#ConfigAndTuning) and answering "yes" to "`Restart Malcolm upon system or Docker daemon restart?`."

### <a name="Wipe"></a>Clearing Malcolm’s data

Run `./scripts/wipe` to stop the Malcolm instance and wipe its Elasticsearch database (**including** [index snapshots and management policies](#IndexManagement) and [alerting configuration](#Alerting)).

## <a name="Upload"></a>Capture file and log archive upload

Malcolm serves a web browser-based upload form for uploading PCAP files and Zeek logs at [https://localhost/upload/](https://localhost/upload/) if you are connecting locally.

![Capture File and Log Archive Upload](./docs/images/screenshots/malcolm_upload.png)

Additionally, there is a writable `files` directory on an SFTP server served on port 8022 (e.g., `sftp://USERNAME@localhost:8022/files/` if you are connecting locally).

The types of files supported are:

* PCAP files (of mime type `application/vnd.tcpdump.pcap` or `application/x-pcapng`)
    - PCAPNG files are *partially* supported: Zeek is able to process PCAPNG files, but not all of Arkime's packet examination features work correctly
* Zeek logs in archive files (`application/gzip`, `application/x-gzip`, `application/x-7z-compressed`, `application/x-bzip2`, `application/x-cpio`, `application/x-lzip`, `application/x-lzma`, `application/x-rar-compressed`, `application/x-tar`, `application/x-xz`, or `application/zip`)
    - where the Zeek logs are found in the internal directory structure in the archive file does not matter

Files uploaded via these methods are monitored and moved automatically to other directories for processing to begin, generally within one minute of completion of the upload.

### <a name="Tagging"></a>Tagging

In addition to be processed for uploading, Malcolm events will be tagged according to the components of the filenames of the PCAP files or Zeek log archives files from which the events were parsed. For example, records created from a PCAP file named `ACME_Scada_VLAN10.pcap` would be tagged with `ACME`, `Scada`, and `VLAN10`. Tags are extracted from filenames by splitting on the characters "," (comma), "-" (dash), and "_" (underscore). These tags are viewable and searchable (via the `tags` field) in Arkime and Kibana. This behavior can be changed by modifying the `AUTO_TAG` [environment variable in `docker-compose.yml`](#DockerComposeYml).

Tags may also be specified manually with the [browser-based upload form](#Upload).

### <a name="UploadPCAPZeek"></a>Processing uploaded PCAPs with Zeek

The browser-based upload interface also provides the ability to specify tags for events extracted from the files uploaded. Additionally, an **Analyze with Zeek** checkbox may be used when uploading PCAP files to cause them to be analyzed by Zeek, similarly to the `ZEEK_AUTO_ANALYZE_PCAP_FILES` environment variable [described above](#DockerComposeYml), only on a per-upload basis. Zeek can also automatically carve out files from file transfers; see [Automatic file extraction and scanning](#ZeekFileExtraction) for more details.

## <a name="LiveAnalysis"></a>Live analysis

### <a name="LocalPCAP"></a>Capturing traffic on local network interfaces

Malcolm's `pcap-capture` container can capture traffic on one or more local network interfaces and periodically rotate these files for processing with Arkime and Zeek. The `pcap-capture` Docker container is started with additional privileges (`IPC_LOCK`, `NET_ADMIN`, `NET_RAW`, and `SYS_ADMIN`) in order for it to be able to open network interfaces in promiscuous mode for capture.

The environment variables prefixed with `PCAP_` in the [`docker-compose.yml`](#DockerComposeYml) file determine local packet capture behavior. Local capture can also be configured by running [`./scripts/install.py --configure`](#ConfigAndTuning) and answering "yes" to "`Should Malcolm capture network traffic to PCAP files?`."

Note that currently Microsoft Windows and Apple macOS platforms run Docker inside of a virtualized environment. This would require additional configuration of virtual interfaces and port forwarding in Docker, the process for which is outside of the scope of this document.

### <a name="Hedgehog"></a>Using a network sensor appliance

A remote network sensor appliance can be used to monitor network traffic, capture PCAP files, and forward Zeek logs, Arkime sessions, or other information to Malcolm. [Hedgehog Linux](https://github.com/idaholab/Malcolm/tree/master/sensor-iso/) is a Debian-based operating system built to

* monitor network interfaces
* capture packets to PCAP files
* detect file transfers in network traffic and extract and scan those files for threats
* generate and forward Zeek logs, Arkime sessions, and other information to [Malcolm](https://github.com/idaholab/malcolm)

Please see the [Hedgehog Linux README](https://github.com/idaholab/Malcolm/blob/master/sensor-iso/README.md) for more information.

### <a name="ZeekForward"></a>Manually forwarding Zeek logs from an external source

Malcolm’s Logstash instance can also be configured to accept Zeek logs from a [remote forwarder](https://www.elastic.co/products/beats/filebeat) by running [`./scripts/install.py --configure`](#ConfigAndTuning) and answering "yes" to "`Expose Logstash port to external hosts?`." Enabling encrypted transport of these logs files is discussed in [Configure authentication](#AuthSetup) and the description of the `BEATS_SSL` environment variable in the [`docker-compose.yml`](#DockerComposeYml) file.

Configuring Filebeat to forward Zeek logs to Malcolm might look something like this example [`filebeat.yml`](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-reference-yml.html):
```
filebeat.inputs:
- type: log
  paths:
    - /var/zeek/*.log
  fields_under_root: true
  fields:
    type: "session"
  compression_level: 0
  exclude_lines: ['^\s*#']
  scan_frequency: 10s
  clean_inactive: 180m
  ignore_older: 120m
  close_inactive: 90m
  close_renamed: true
  close_removed: true
  close_eof: false
  clean_renamed: true
  clean_removed: true

output.logstash:
  hosts: ["192.0.2.123:5044"]
  ssl.enabled: true
  ssl.certificate_authorities: ["/foo/bar/ca.crt"]
  ssl.certificate: "/foo/bar/client.crt"
  ssl.key: "/foo/bar/client.key"
  ssl.supported_protocols: "TLSv1.2"
  ssl.verification_mode: "none"
```

## <a name="Arkime"></a>Arkime

The Arkime interface will be accessible over HTTPS on port 443 at the docker hosts IP address (e.g., [https://localhost](https://localhost) if you are connecting locally).

### <a name="ArkimeZeek"></a>Zeek log integration

A stock installation of Arkime extracts all of its network connection ("session") metadata ("SPI" or "Session Profile Information") from full packet capture artifacts (PCAP files). Zeek (formerly Bro) generates similar session metadata, linking network events to sessions via a connection UID. Malcolm aims to facilitate analysis of Zeek logs by mapping values from Zeek logs to the Arkime session database schema for equivalent fields, and by creating new "native" Arkime database fields for all the other Zeek log values for which there is not currently an equivalent in Arkime:

![Zeek log session record](./docs/images/screenshots/moloch_session_zeek.png)

In this way, when full packet capture is an option, analysis of PCAP files can be enhanced by the additional information Zeek provides. When full packet capture is not an option, similar analysis can still be performed using the same interfaces and processes using the Zeek logs alone.

One value of particular mention is **Zeek Log Type** (`zeek.logType` in Elasticsearch). This value corresponds to the kind of Zeek `.log` file from which the record was created. In other words, a search could be restricted to records from `conn.log` by searching `zeek.logType == conn`, or restricted to records from `weird.log` by searching `zeek.logType == weird`. In this same way, to view *only* records from Zeek logs (excluding any from PCAP files), use the special Arkime `EXISTS` filter, as in `zeek.logType == EXISTS!`. On the other hand, to exclude Zeek logs and only view records from PCAP files, use `zeek.logType != EXISTS!`. 

Click the icon of the owl **🦉** in the upper-left hand corner of to access the Arkime usage documentation (accessible at [https://localhost/help](https://localhost/help) if you are connecting locally), click the **Fields** label in the navigation pane, then search for `zeek` to see a list of the other Zeek log types and fields available to Malcolm.

![Zeek fields](./docs/images/screenshots/moloch_help_fields.png)

The values of records created from Zeek logs can be expanded and viewed like any native Arkime session by clicking the plus **➕** icon to the left of the record in the Sessions view. However, note that when dealing with these Zeek records the full packet contents are not available, so buttons dealing with viewing and exporting PCAP information will not behave as they would for records from PCAP files. Other than that, Zeek records and their values are usable in Malcolm just like native PCAP session records.

#### <a name="ZeekArkimeFlowCorrelation"></a>Correlating Zeek logs and Arkime sessions

The Arkime interface displays both Zeek logs and Arkime sessions alongside each other. Using fields common to both data sources, one can [craft queries](#SearchCheatSheet) to filter results matching desired criteria.

A few fields of particular mention that help limit returned results to those Zeek logs and Arkime session records generated from the same network connection are [Community ID](https://github.com/corelight/community-id-spec) (`communityId` and `zeek.community_id` in Arkime and Zeek, respectively) and Zeek's [connection UID](https://docs.zeek.org/en/stable/examples/logs/#using-uids) (`zeek.uid`), which Malcolm maps to Arkime's `rootId` field.

Community ID is specification for standard flow hashing [published by Corelight](https://github.com/corelight/community-id-spec) with the intent of making it easier to pivot from one dataset (e.g., Arkime sessions) to another (e.g., Zeek `conn.log` entries). In Malcolm both Arkime and [Zeek](https://github.com/corelight/zeek-community-id) populate this value, which makes it possible to filter for a specific network connection and see both data sources' results for that connection.

The `rootId` field is used by Arkime to link session records together when a particular session has too many packets to be represented by a single session. When normalizing Zeek logs to Arkime's schema, Malcolm piggybacks on `rootId` to store Zeek's [connection UID](https://docs.zeek.org/en/stable/examples/logs/#using-uids) to crossreference entries across Zeek log types. The connection UID is also stored in `zeek.uid`.

Filtering on community ID OR'ed with zeek UID (e.g., `communityId == "1:r7tGG//fXP1P0+BXH3zXETCtEFI=" || rootId == "CQcoro2z6adgtGlk42"`) is an effective way to see both the Arkime sessions and Zeek logs generated by a particular network connection.

![Correlating Arkime sessions and Zeek logs](./docs/images/screenshots/moloch_correlate_communityid_uid.png)

### <a name="ArkimeHelp"></a>Help

Click the icon of the owl 🦉 in the upper-left hand corner of to access the Arkime usage documentation (accessible at [https://localhost/help](https://localhost/help) if you are connecting locally), which includes such topics as [search syntax](https://localhost/help#search), the [Sessions view](https://localhost/help#sessions), [SPIView](https://localhost/help#spiview), [SPIGraph](https://localhost/help#spigraph), and the [Connections](https://localhost/help#connections) graph.

### <a name="ArkimeSessions"></a>Sessions

The **Sessions** view provides low-level details of the sessions being investigated, whether they be Arkime sessions created from PCAP files or [Zeek logs mapped](#ArkimeZeek) to the Arkime session database schema.

![Arkime's Sessions view](./docs/images/screenshots/moloch_sessions.png)

The **Sessions** view contains many controls for filtering the sessions displayed from all sessions down to sessions of interest:

* [search bar](https://localhost/help#search): Indicated by the magnifying glass **🔍** icon, the search bar allows defining filters on session/log metadata
* [time bounding](https://localhost/help#timebounding) controls: The **🕘**, **Start**, **End**, **Bounding**, and **Interval** fields, and the **date histogram** can be used to visually zoom and pan the time range being examined.
* search button: The **Search** button re-runs the sessions query with the filters currently specified.
* views button: Indicated by the eyeball **👁** icon, views allow overlaying additional previously-specified filters onto the current sessions filters. For convenience, Malcolm provides several Arkime preconfigured views including several on the `zeek.logType` field. 

![Malcolm views](./docs/images/screenshots/moloch_log_filter.png)

* map: A global map can be expanded by clicking the globe **🌎** icon. This allows filtering sessions by IP-based geolocation when possible.

Some of these filter controls are also available on other Arkime pages (such as SPIView, SPIGraph, Connections, and Hunt).

The number of sessions displayed per page, as well as the page currently displayed, can be specified using the paging controls underneath the time bounding controls.

The sessions table is displayed below the filter controls. This table contains the sessions/logs matching the specified filters.

To the left of the column headers are two buttons. The **Toggle visible columns** button, indicated by a grid **⊞** icon, allows toggling which columns are displayed in the sessions table. The **Save or load custom column configuration** button, indicated by a columns **◫** icon, allows saving the current displayed columns or loading previously-saved configurations. This is useful for customizing which columns are displayed when investigating different types of traffic. Column headers can also be clicked to sort the results in the table, and column widths may be adjusted by dragging the separators between column headers.

Details for individual sessions/logs can be expanded by clicking the plus **➕** icon on the left of each row. Each row may contain multiple sections and controls, depending on whether the row represents a Arkime session or a [Zeek log](#ArkimeZeek). Clicking the field names and values in the details sections allows additional filters to be specified or summary lists of unique values to be exported.

When viewing Arkime session details (ie., a session generated from a PCAP file), an additional packets section will be visible underneath the metadata sections. When the details of a session of this type are expanded, Arkime will read the packet(s) comprising the session for display here. Various controls can be used to adjust how the packet is displayed (enabling **natural** decoding and enabling **Show Images & Files** may produce visually pleasing results), and other options (including PCAP download, carving images and files, applying decoding filters, and examining payloads in [CyberChef](https://github.com/gchq/CyberChef)) are available.

See also Arkime's usage documentation for more information on the [Sessions view](https://localhost/help#sessions).

#### <a name="ArkimePCAPExport"></a>PCAP Export

Clicking the down arrow **▼** icon to the far right of the search bar presents a list of actions including **PCAP Export** (see Arkime's [sessions help](https://localhost/help#sessions) for information on the other actions).  When full PCAP sessions are displayed, the **PCAP Export** feature allows you to create a new PCAP file from the matching Arkime sessions, including controls for which sessions are included (open items, visible items, or all matching items) and whether or not to include linked segments. Click **Export PCAP** button to generate the PCAP, after which you'll be presented with a browser download dialog to save or open the file. Note that depending on the scope of the filters specified this might take a long time (or, possibly even time out).

![Export PCAP](./docs/images/screenshots/moloch_export_pcap.png)

See the [issues](#Issues) section of this document for an error that can occur using this feature when Zeek log sessions are displayed.View

### <a name="ArkimeSPIView"></a>SPIView

Arkime's **SPI** (**S**ession **P**rofile **I**nformation) **View** provides a quick and easy-to-use interface for  exploring session/log metrics. The SPIView page lists categories for general session metrics (e.g., protocol, source and destination IP addresses, sort and destination ports, etc.) as well as for all of various types of network understood by Arkime and Zeek. These categories can be expanded and the top *n* values displayed, along with each value's cardinality, for the fields of interest they contain.

![Arkime's SPIView](./docs/images/screenshots/moloch_spiview.png)

Click the the plus **➕** icon to the right of a category to expand it. The values for specific fields are displayed by clicking the field description in the field list underneath the category name. The list of field names can be filtered by typing part of the field name in the *Search for fields to display in this category* text input. The **Load All** and **Unload All** buttons can be used to toggle display of all of the fields belonging to that category. Once displayed, a field's name or one of its values may be clicked to provide further actions for filtering or displaying that field or its values. Of particular interest may be the **Open [fieldname] SPI Graph** option when clicking on a field's name. This will open a new tab with the SPI Graph ([see below](#ArkimeSPIGraph)) populated with the field's top values.

Note that because the SPIView page can potentially run many queries, SPIView limits the search domain to seven days (in other words, seven indices, as each index represents one day's worth of data). When using SPIView, you will have best results if you limit your search time frame to less than or equal to seven days. This limit can be adjusted by editing the `spiDataMaxIndices` setting in [config.ini](./etc/moloch/config.ini) and rebuilding the `malcolmnetsec/arkime` docker container.

See also Arkime's usage documentation for more information on [SPIView](https://localhost/help#spiview).

### <a name="ArkimeSPIGraph"></a>SPIGraph

Arkime's **SPI** (**S**ession **P**rofile **I**nformation) **Graph** visualizes the occurrence of some field's top *n* values over time, and (optionally) geographically. This is particularly useful for identifying trends in a particular type of communication over time: traffic using a particular protocol when seen sparsely at regular intervals on that protocol's date histogram in the SPIGraph may indicate a connection check, polling, or beaconing (for example, see the `llmnr` protocol in the screenshot below).

![Arkime's SPIGraph](./docs/images/screenshots/moloch_spigraph.png)

Controls can be found underneath the time bounding controls for selecting the field of interest, the number of elements to be displayed, the sort order, and a periodic refresh of the data.

See also Arkime's usage documentation for more information on [SPIGraph](https://localhost/help#spigraph).

### <a name="ArkimeConnections"></a>Connections

The **Connections** page presents network communications via a force-directed graph, making it easy to visualize logical relationships between network hosts.

![Arkime's Connections graph](./docs/images/screenshots/moloch_connections.png)

Controls are available for specifying the query size (where smaller values will execute more quickly but may only contain an incomplete representation of the top *n* sessions, and larger values may take longer to execute but will be more complete), which fields to use as the source and destination for node values, a minimum connections threshold, and the method for determining the "weight" of the link between two nodes. As is the case with most other visualizations in Arkime, the graph is interactive: clicking on a node or the link between two nodes can be used to modify query filters, and the nodes themselves may be repositioned by dragging and dropping them. A node's color indicates whether it communicated as a source/originator, a destination/responder, or both.

While the default source and destination fields are *Src IP* and *Dst IP:Dst Port*, the Connections view is able to use any combination of any of the fields populated by Arkime and Zeek. For example:

* *Src OUI* and *Dst OUI* (hardware manufacturers)
* *Src IP* and *Protocols*
* *Originating Network Segment* and *Responding Network Segment* (see [CIDR subnet to network segment name mapping](#SegmentNaming))
* *Originating GeoIP City* and *Responding GeoIP City*

or any other combination of these or other fields.

See also Arkime's usage documentation for more information on the [Connections graph](https://localhost/help#connections).

### <a name="ArkimeHunt"></a>Hunt

Arkime's **Hunt** feature allows an analyst to search within the packets themselves (including payload data) rather than simply searching the session metadata. The search string may be specified using ASCII (with or without case sensitivity), hex codes, or regular expressions. Once a hunt job is complete, matching sessions can be viewed in the [Sessions](#ArkimeSessions)  view.

Clicking the **Create a packet search job** on the Hunt page will allow you to specify the following parameters for a new hunt job:

* a packet search job **name**
* a **maximum number of packets** to examine per session
* the **search string** and its format (*ascii*, *ascii (case sensitive)*, *hex*, *regex*, or *hex regex*)
* whether to search **source packets**, **destination packets**, or both
* whether to search **raw** or **reassembled** packets

Click the **➕ Create** button to begin the search. Arkime will scan the source PCAP files from which the sessions were created according to the search criteria. Note that whatever filters were specified when the hunt job is executed will apply to the hunt job as well; the number of sessions matching the current filters will be displayed above the hunt job parameters with text like "ⓘ Creating a new packet search job will search the packets of # sessions."

![Hunt creation](./docs/images/screenshots/moloch_hunt_creation.png)

Once a hunt job is submitted, it will be assigned a unique hunt ID (a long unique string of characters like `yuBHAGsBdljYmwGkbEMm`) and its progress will be updated periodically in the **Hunt Job Queue** with the execution percent complete, the number of matches found so far, and the other parameters with which the job was submitted. More details for the hunt job can be viewed by expanding its row with the plus **➕** icon on the left.

![Hunt completed](./docs/images/screenshots/moloch_hunt_finished.png)

Once the hunt job is complete (and a minute or so has passed, as the `huntId` must be added to the matching session records in the database), click the folder **📂** icon on the right side of the hunt job row to open a new [Sessions](#ArkimeSessions) tab with the search bar prepopulated to filter to sessions with packets matching the search criteria.

![Hunt result sessions](./docs/images/screenshots/moloch_hunt_sessions.png)

From this list of filtered sessions you can expand session details and explore packet payloads which matched the hunt search criteria.

The hunt feature is available only for sessions created from full packet capture data, not Zeek logs. This being the case, it is a good idea to click the eyeball **👁** icon and select the **PCAP Files** view to exclude Zeek logs from candidate sessions prior to using the hunt feature.

See also Arkime's usage documentation for more information on the [hunt feature](https://localhost/help#hunt).

### <a name="ArkimeStats"></a>Statistics

Arkime provides several other reports which show information about the state of Arkime and the underlying Elasticsearch database.

The **Files** list displays a list of PCAP files processed by Arkime, the date and time of the earliest packet in each file, and the file size:

![Arkime's Files list](./docs/images/screenshots/moloch_files.png)

The **ES Indices** list (available under the **Stats** page) lists the Elasticsearch indices within which log data is contained:

![Arkime's ES indices list](./docs/images/screenshots/moloch_es_stats.png)

The **History** view provides a historical list of queries issues to Arkime and the details of those queries:

![Arkime's History view](./docs/images/screenshots/moloch_history.png)

See also Arkime's usage documentation for more information on the [Files list](https://localhost/help#files), [statistics](https://localhost/help#files), and [history](https://localhost/help#history).

### <a name="ArkimeSettings"></a>Settings

#### General settings

The **Settings** page can be used to tweak Arkime preferences, defined additional custom views and column configurations, tweak the color theme, and more.

See Arkime's usage documentation for more information on [settings](https://localhost/help#settings).

![Arkime general settings](./docs/images/screenshots/moloch_general_settings.png)

![Arkime custom view management](./docs/images/screenshots/moloch_view_settings.png)

## <a name="Kibana"></a>Kibana

While Arkime provides very nice visualizations, especially for network traffic, [Kibana](https://www.elastic.co/guide/en/kibana/current/getting-started.html) (an open source general-purpose data visualization tool for Elasticsearch) can be used to create custom visualizations (tables, charts, graphs, dashboards, etc.) using the same data.

The Kibana container can be accessed at [https://localhost/kibana/](https://localhost/kibana/) if you are connecting locally. Several preconfigured dashboards for Zeek logs are included in Malcolm's Kibana configuration.

The official [Kibana User Guide](https://www.elastic.co/guide/en/kibana/current/index.html) has excellent tutorials for a variety of topics.

Kibana has several components for data searching and visualization:

### <a name="Discover"></a>Discover

The **Discover** view enables you to view events on a record-by-record basis (similar to a *session* record in Arkime or an individual line from a Zeek log). See the official [Kibana User Guide](https://www.elastic.co/guide/en/kibana/current/index.html) for information on using the Discover view:

* [Getting Started: Discovering Your Data](https://www.elastic.co/guide/en/kibana/current/tutorial-discovering.html)
* [Discover](https://www.elastic.co/guide/en/kibana/current/discover.html)
* [Searching Your Data](https://www.elastic.co/guide/en/kibana/current/search.html)

#### <a name="DiscoverGallery"></a>Screenshots

![Kibana's Discover view](./docs/images/screenshots/kibana_discover.png)

![Viewing the details of a session in Discover](./docs/images/screenshots/kibana_discover_table.png)

![Filtering by tags to display only sessions with public IP addresses](./docs/images/screenshots/kibana_add_filter.png)

![Changing the fields displayed in Discover](./docs/images/screenshots/kibana_fields_list.png)

![Opening a previously-saved search](./docs/images/screenshots/kibana_open_search.png)

### <a name="KibanaVisualizations"></a>Visualizations and dashboards

#### <a name="PrebuiltVisualizations"></a>Prebuilt visualizations and dashboards

Malcolm comes with dozens of prebuilt visualizations and dashboards for the network traffic represented by each of the Zeek log types. Click **Dashboard** to see a list of these dashboards. As is the case with all Kibana's visualizations, all of the charts, graphs, maps, and tables are interactive and can be clicked on to narrow or expand the scope of the data you are investigating. Similarly, click **Visualize** to explore the prebuilt visualizations used to build the dashboards.

Many of Malcolm's prebuilt visualizations for Zeek logs are heavily inspired by the excellent [Kibana Dashboards](https://github.com/Security-Onion-Solutions/securityonion-elastic/tree/master/kibana/dashboards) that are part of [Security Onion](https://securityonion.net/).

##### <a name="PrebuiltVisualizationsGallery"></a>Screenshots

![The Connections dashboard displays information about the "top talkers" across all types of sessions](./docs/images/screenshots/kibana_connections.png)

![The HTTP dashboard displays important details about HTTP traffic](./docs/images/screenshots/kibana_http.png)

![There are several Connections visualizations using locations from GeoIP lookups](./docs/images/screenshots/kibana_latlon_map.png)

![Kibana includes both coordinate and region map types](./docs/images/screenshots/kibana_region_map.png)

![The Notices dashboard highlights things which Zeek determine are potentially bad](./docs/images/screenshots/kibana_notices.png)

![The Signatures dashboard displays signature hits, such as antivirus hits on files extracted from network traffic](./docs/images/screenshots/kibana_signatures.png)

![The Software dashboard displays the type, name, and version of software seen communicating on the network](./docs/images/screenshots/kibana_software.png)

![The PE (portable executables) dashboard displays information about executable files transferred over the network](./docs/images/screenshots/kibana_portable_executables.png)

![The SMTP dashboard highlights details about SMTP traffic](./docs/images/screenshots/kibana_smtp.png)

![The SSL dashboard displays information about SSL versions, certificates, and TLS JA3 fingerprints](./docs/images/screenshots/kibana_ssl.png)

![The files dashboard displays metrics about the files transferred over the network](./docs/images/screenshots/kibana_files_source.png)

![This dashboard provides insight into DNP3 (Distributed Network Protocol), a protocol used commonly in electric and water utilities](./docs/images/screenshots/kibana_dnp3.png)

![Modbus is a standard protocol found in many industrial control systems (ICS)](./docs/images/screenshots/kibana_modbus.png)

![BACnet is a communications protocol for Building Automation and Control (BAC) networks](./docs/images/screenshots/kibana_bacnet.png)

![EtherNet/IP is an industrial network protocol that adapts the Common Industrial Protocol to standard Ethernet](./docs/images/screenshots/kibana_ethernetip.png)

![MQTT is a lightweight publish-subscribe network protocol that transports messages between devices](./docs/images/screenshots/kibana_mqtt.png)

![PROFINET is an industry technical standard for data communication over Industrial Ethernet](./docs/images/screenshots/kibana_profinet.png)

![S7comm is a Siemens proprietary protocol that runs between programmable logic controllers (PLCs) of the Siemens family](./docs/images/screenshots/kibana_s7comm.png)

#### <a name="BuildDashboard"></a>Building your own visualizations and dashboards

See the official [Kibana User Guide](https://www.elastic.co/guide/en/kibana/current/index.html) for information on creating your own visualizations and dashboards:

* [Getting Started: Visualizing Your Data](https://www.elastic.co/guide/en/kibana/current/tutorial-visualizing.html)
* [Visualize](https://www.elastic.co/guide/en/kibana/current/visualize.html)
* [Dashboard](https://www.elastic.co/guide/en/kibana/current/dashboard.html)
* [Timelion](https://www.elastic.co/guide/en/kibana/current/timelion.html) (more advanced time series data visualizer)

##### <a name="NewVisualizationsGallery"></a>Screenshots

![Kibana boasts many types of visualizations for displaying your data](./docs/images/screenshots/kibana_new_visualization.png)

![Timelion is a powerful tool for visualizing time series data](./docs/images/screenshots/kibana_timelion.png)

![Visual Builder is another time series data visualizer](./docs/images/screenshots/kibana_time_series.png)

## <a name="SearchCheatSheet"></a>Search Queries in Arkime and Kibana

Kibana support two query syntaxes: the legacy [Lucene](https://www.elastic.co/guide/en/kibana/current/lucene-query.html) stynax and the new [Kibana Query Language (KQL)](https://www.elastic.co/guide/en/kibana/current/kuery-query.html), both of which are somewhat different than Arkime's query syntax (see the help at [https://localhost/help#search](https://localhost/help#search) if you are connecting locally). The Arkime interface is for searching and visualizing both Arkime sessions and Zeek logs. The prebuilt dashboards in the Kibana interface are for searching and visualizing Zeek logs, but will not include Arkime sessions. Here are some common patterns used in building search query strings for Arkime and Kibana, respectively. See the links provided for further documentation.

| | [Arkime Search String](https://localhost/help#search) | [Kibana Search String (Lucene)](https://www.elastic.co/guide/en/kibana/current/lucene-query.html) | [Kibana Search String (KQL)](https://www.elastic.co/guide/en/kibana/current/kuery-query.html)|
|---|:---:|:---:|:---:|
| Field exists |`zeek.logType == EXISTS!`|`_exists_:zeek.logType`|`zeek.logType:*`|
| Field does not exist |`zeek.logType != EXISTS!`|`NOT _exists_:zeek.logType`|`NOT zeek.logType:*`|
| Field matches a value |`port.dst == 22`|`dstPort:22`|`dstPort:22`|
| Field does not match a value |`port.dst != 22`|`NOT dstPort:22`|`NOT dstPort:22`|
| Field matches at least one of a list of values |`tags == [external_source, external_destination]`|`tags:(external_source OR external_destination)`|`tags:(external_source or external_destination)`|
| Field range (inclusive) |`http.statuscode >= 200 && http.statuscode <= 300`|`http.statuscode:[200 TO 300]`|`http.statuscode >= 200 and http.statuscode <= 300`|
| Field range (exclusive) |`http.statuscode > 200 && http.statuscode < 300`|`http.statuscode:{200 TO 300}`|`http.statuscode > 200 and http.statuscode < 300`|
| Field range (mixed exclusivity) |`http.statuscode >= 200 && http.statuscode < 300`|`http.statuscode:[200 TO 300}`|`http.statuscode >= 200 and http.statuscode < 300`|
| Match all search terms (AND) |`(tags == [external_source, external_destination]) && (http.statuscode == 401)`|`tags:(external_source OR external_destination) AND http.statuscode:401`|`tags:(external_source or external_destination) and http.statuscode:401`|
| Match any search terms (OR) |`(zeek_ftp.password == EXISTS!) || (zeek_http.password == EXISTS!) || (zeek.user == "anonymous")`|`_exists_:zeek_ftp.password OR _exists_:zeek_http.password OR zeek.user:"anonymous"`|`zeek_ftp.password:* or zeek_http.password:* or zeek.user:"anonymous"`|
| Global string search (anywhere in the document) |all Arkime search expressions are field-based|`microsoft`|`microsoft`|
| Wildcards|`host.dns == "*micro?oft*"` (`?` for single character, `*` for any characters)|`dns.host:*micro?oft*` (`?` for single character, `*` for any characters)|`dns.host:*micro*ft*` (`*` for any characters)|
| Regex |`host.http == /.*www\.f.*k\.com.*/`|`zeek_http.host:/.*www\.f.*k\.com.*/`|Kibana Query Language does not currently support regex|
| IPv4 values |`ip == 0.0.0.0/0`|`srcIp:"0.0.0.0/0" OR dstIp:"0.0.0.0/0"`|`srcIp:"0.0.0.0/0" OR dstIp:"0.0.0.0/0"`|
| IPv6 values |`(ip.src == EXISTS! || ip.dst == EXISTS!) && (ip != 0.0.0.0/0)`|`(_exists_:srcIp AND NOT srcIp:"0.0.0.0/0") OR (_exists_:dstIp AND NOT dstIp:"0.0.0.0/0")`|`(srcIp:* and not srcIp:"0.0.0.0/0") or (dstIp:* and not dstIp:"0.0.0.0/0")`|
| GeoIP information available |`country == EXISTS!`|`_exists_:zeek.destination_geo OR _exists_:zeek.source_geo`|`zeek.destination_geo:* or zeek.source_geo:*`|
| Zeek log type |`zeek.logType == notice`|`zeek.logType:notice`|`zeek.logType:notice`|
| IP CIDR Subnets |`ip.src == 172.16.0.0/12`|`srcIp:"172.16.0.0/12"`|`srcIp:"172.16.0.0/12"`|
| Search time frame |Use Arkime time bounding controls under the search bar|Use Kibana time range controls in the upper right-hand corner|Use Kibana time range controls in the upper right-hand corner|

When building complex queries, it is **strongly recommended** that you enclose search terms and expressions in parentheses to control order of operations.

As Zeek logs are ingested, Malcolm parses and normalizes the logs' fields to match Arkime's underlying Elasticsearch schema. A complete list of these fields can be found in the Arkime help (accessible at [https://localhost/help#fields](https://localhost/help#fields) if you are connecting locally).

Whenever possible, Zeek fields are mapped to existing corresponding Arkime fields: for example, the `orig_h` field in Zeek is mapped to Arkime's `srcIp` field. The original Zeek fields are also left intact. To complicate the issue, the Arkime interface uses its own aliases to reference those fields: the source IP field is referenced as `ip.src` (Arkime's alias) in Arkime and `srcIp` or `zeek.orig_h` in Kibana.

The table below shows the mapping of some of these fields.

| Field Description |Arkime Field Alias(es)|Arkime-mapped Zeek Field(s)|Zeek Field(s)|
|---|:---:|:---:|:---:|
| [Community ID](https://github.com/corelight/community-id-spec) Flow Hash ||`communityId`|`zeek.community_id`|
| Destination IP |`ip.dst`|`dstIp`|`zeek.resp_h`|
| Destination MAC |`mac.dst`|`dstMac`|`zeek.resp_l2_addr`|
| Destination Port |`port.dst`|`dstPort`|`zeek.resp_p`|
| Duration |`session.length`|`length`|`zeek_conn.duration`|
| First Packet Time |`starttime`|`firstPacket`|`zeek.ts`, `@timestamp`|
| IP Protocol |`ip.protocol`|`ipProtocol`|`zeek.proto`|
| Last Packet Time |`stoptime`|`lastPacket`||
| MIME Type |`email.bodymagic`, `http.bodymagic`|`http.bodyMagic`|`zeek.filetype`, `zeek_files.mime_type`, `zeek_ftp.mime_type`, `zeek_http.orig_mime_types`, `zeek_http.resp_mime_types`, `zeek_irc.dcc_mime_type`|
| Protocol/Service |`protocols`|`protocol`|`zeek.proto`, `zeek.service`|
| Request Bytes |`databytes.src`, `bytes.src`|`srcBytes`, `srcDataBytes`|`zeek_conn.orig_bytes`, `zeek_conn.orig_ip_bytes`|
| Request Packets |`packets.src`|`srcPackets`|`zeek_conn.orig_pkts`|
| Response Bytes |`databytes.dst`, `bytes.dst`|`dstBytes`, `dstDataBytes`|`zeek_conn.resp_bytes`, `zeek_conn.resp_ip_bytes`|
| Response Packets |`packets.dst`|`dstPackets`|`zeek_con.resp_pkts`|
| Source IP |`ip.src`|`srcIp`|`zeek.orig_h`|
| Source MAC |`mac.src`|`srcMac`|`zeek.orig_l2_addr`|
| Source Port |`port.src`|`srcPort`|`zeek.orig_p`|
| Total Bytes |`databytes`, `bytes`|`totDataBytes`, `totBytes`||
| Total Packets |`packets`|`totPackets`||
| Username |`user`|`user`|`zeek.user`|
| Zeek Connection UID|||`zeek.uid`|
| Zeek File UID |||`zeek.fuid`|
| Zeek Log Type |||`zeek.logType`|

In addition to the fields listed above, Arkime provides several special field aliases for matching any field of a particular type. While these aliases do not exist in Kibana *per se*, they can be approximated as illustrated below.

| Matches Any | Arkime Special Field Example | Kibana/Zeek Equivalent Example |
|---|:---:|:---:|
| IP Address | `ip == 192.168.0.1` | `srcIp:192.168.0.1 OR dstIp:192.168.0.1` |
| Port | `port == [80, 443, 8080, 8443]` | `srcPort:(80 OR 443 OR 8080 OR 8443) OR dstPort:(80 OR 443 OR 8080 OR 8443)` |
| Country (code) | `country == [RU,CN]` | `zeek.destination_geo.country_code2:(RU OR CN) OR zeek.source_geo.country_code2:(RU OR CN) OR dns.GEO:(RU OR CN)` |
| Country (name) | | `zeek.destination_geo.country_name:(Russia OR China) OR zeek.source_geo.country_name:(Russia OR China)` |
| ASN | `asn == "*Mozilla*"` | `srcASN:*Mozilla* OR dstASN:*Mozilla* OR dns.ASN:*Mozilla*` |
| Host | `host == www.microsoft.com` | `zeek_http.host:www.microsoft.com (or zeek_dhcp.host_name, zeek_dns.host, zeek_ntlm.host, smb.host, etc.)` |
| Protocol (layers >= 4) | `protocols == tls` | `protocol:tls` |
| User | `user == EXISTS! && user != anonymous` | `_exists_:user AND (NOT user:anonymous)` |

For details on how to filter both Zeek logs and Arkime session records for a particular connection, see [Correlating Zeek logs and Arkime sessions](#ZeekArkimeFlowCorrelation).

## <a name="MalcolmFeatures"></a>Other Malcolm features

### <a name="ZeekFileExtraction"></a>Automatic file extraction and scanning

Malcolm can leverage Zeek's knowledge of network protocols to automatically detect file transfers and extract those files from PCAPs as Zeek processes them. This behavior can be enabled globally by modifying the `ZEEK_EXTRACTOR_MODE` [environment variable in `docker-compose.yml`](#DockerComposeYml), or on a per-upload basis for PCAP files uploaded via the [browser-based upload form](#Upload) when **Analyze with Zeek** is selected.

To specify which files should be extracted, the following values are acceptable in `ZEEK_EXTRACTOR_MODE`:

* `none`: no file extraction
* `interesting`: extraction of files with mime types of common attack vectors
* `mapped`: extraction of files with recognized mime types
* `known`: extraction of files for which any mime type can be determined
* `all`: extract all files

Extracted files can be examined through any of the following methods:

* submitting file hashes to [**VirusTotal**](https://www.virustotal.com/en/#search); to enable this method, specify the `VTOT_API2_KEY` [environment variable in `docker-compose.yml`](#DockerComposeYml)
* scanning files with [**ClamAV**](https://www.clamav.net/); to enable this method, set the `EXTRACTED_FILE_ENABLE_CLAMAV` [environment variable in `docker-compose.yml`](#DockerComposeYml) to `true`
* scanning files with [**Yara**](https://github.com/VirusTotal/yara); to enable this method, set the `EXTRACTED_FILE_ENABLE_YARA` [environment variable in `docker-compose.yml`](#DockerComposeYml) to `true`
* scanning PE (portable executable) files with [**Capa**](https://github.com/fireeye/capa); to enable this method, set the `EXTRACTED_FILE_ENABLE_CAPA` [environment variable in `docker-compose.yml`](#DockerComposeYml) to `true`

Files which are flagged via any of these methods will be logged as Zeek `signatures.log` entries, and can be viewed in the **Signatures** dashboard in Kibana.

The `EXTRACTED_FILE_PRESERVATION` [environment variable in `docker-compose.yml`](#DockerComposeYml) determines the behavior for preservation of Zeek-extracted files:

* `quarantined`: preserve only flagged files in `./zeek-logs/extract_files/quarantine`
* `all`: preserve flagged files in `./zeek-logs/extract_files/quarantine` and all other extracted files in `./zeek-logs/extract_files/preserved`
* `none`: preserve no extracted files

The `EXTRACTED_FILE_HTTP_SERVER_...` [environment variables in `docker-compose.yml`](#DockerComposeYml) configure access to the Zeek-extracted files path through the means of a simple HTTPS directory server. Beware that Zeek-extracted files may contain malware. As such, the files may be optionally encrypted upon download. 

### <a name="HostAndSubnetNaming"></a>Automatic host and subnet name assignment

#### <a name="HostNaming"></a>IP/MAC address to hostname mapping via `host-map.txt`

The `host-map.txt` file in the Malcolm installation directory can be used to define names for network hosts based on IP and/or MAC addresses in Zeek logs. The default empty configuration looks like this:
```
# IP or MAC address to host name map:
#   address|host name|required tag
#
# where:
#   address: comma-separated list of IPv4, IPv6, or MAC addresses
#          e.g., 172.16.10.41, 02:42:45:dc:a2:96, 2001:0db8:85a3:0000:0000:8a2e:0370:7334
#
#   host name: host name to be assigned when event address(es) match
#
#   required tag (optional): only check match and apply host name if the event
#                            contains this tag
#
```
Each non-comment line (not beginning with a `#`), defines an address-to-name mapping for a network host. For example:
```
127.0.0.1,127.0.1.1,::1|localhost|
192.168.10.10|office-laptop.intranet.lan|
06:46:0b:a6:16:bf|serial-host.intranet.lan|testbed
```
Each line consists of three `|`-separated fields: address(es), hostname, and, optionally, a tag which, if specified, must belong to a log for the matching to occur.

As Zeek logs are processed into Malcolm's Elasticsearch instance, the log's source and destination IP and MAC address fields (`zeek.orig_h`, `zeek.resp_h`, `zeek.orig_l2_addr`, and `zeek.resp_l2_addr`, respectively) are compared against the lists of addresses in `host-map.txt`. When a match is found, a new field is added to the log: `zeek.orig_hostname` or `zeek.resp_hostname`, depending on whether the matching address belongs to the originating or responding host. If the third field (the "required tag" field) is specified, a log must also contain that value in its `tags` field in addition to matching the IP or MAC address specified in order for the corresponding `_hostname` field to be added.

`zeek.orig_hostname` and `zeek.resp_hostname` may each contain multiple values. For example, if both a host's source IP address and source MAC address were matched by two different lines, `zeek.orig_hostname` would contain the hostname values from both matching lines.

#### <a name="SegmentNaming"></a>CIDR subnet to network segment name mapping via `cidr-map.txt`

The `cidr-map.txt` file in the Malcolm installation directory can be used to define names for network segments based on IP addresses in Zeek logs. The default empty configuration looks like this:
```
# CIDR to network segment format:
#   IP(s)|segment name|required tag
#
# where:
#   IP(s): comma-separated list of CIDR-formatted network IP addresses
#          e.g., 10.0.0.0/8, 169.254.0.0/16, 172.16.10.41
#
#   segment name: segment name to be assigned when event IP address(es) match
#
#   required tag (optional): only check match and apply segment name if the event
#                            contains this tag
#
```
Each non-comment line (not beginning with a `#`), defines an subnet-to-name mapping for a network host. For example:
```
192.168.50.0/24,192.168.40.0/24,10.0.0.0/8|corporate|
192.168.100.0/24|control|
192.168.200.0/24|dmz|
172.16.0.0/12|virtualized|testbed
```
Each line consists of three `|`-separated fields: CIDR-formatted subnet IP range(s), subnet name, and, optionally, a tag which, if specified, must belong to a log for the matching to occur.

As Zeek logs are processed into Malcolm's Elasticsearch instance, the log's source and destination IP address fields (`zeek.orig_h` and `zeek.resp_h`, respectively) are compared against the lists of addresses in `cidr-map.txt`. When a match is found, a new field is added to the log: `zeek.orig_segment` or `zeek.resp_segment`, depending on whether the matching address belongs to the originating or responding host. If the third field (the "required tag" field) is specified, a log must also contain that value in its `tags` field in addition to its IP address falling within the subnet specified in order for the corresponding `_segment` field to be added.

`zeek.orig_segment` and `zeek.resp_segment` may each contain multiple values. For example, if `cidr-map.txt` specifies multiple overlapping subnets on different lines, `zeek.orig_segment` would contain the hostname values from both matching lines if `zeek.orig_h` belonged to both subnets.

If both `zeek.orig_segment` and `zeek.resp_segment` are added to a log, and if they contain different values, the tag `cross_segment` will be added to the log's `tags` field for convenient identification of cross-segment traffic. This traffic could be easily visualized using Arkime's **Connections** graph, by setting the **Src:** value to **Originating Network Segment** and the **Dst:** value to **Responding Network Segment**:

![Cross-segment traffic in Connections](./docs/images/screenshots/moloch_connections_segments.png)

#### <a name="NameMapUI"></a>Defining hostname and CIDR subnet names interface

As an alternative to manually editing `cidr-map.txt` and `host-map.txt`, a **Host and Subnet Name Mapping** editor is available at [https://localhost/name-map-ui/](https://localhost/name-map-ui/) if you are connecting locally. Upon loading, the editor is populated from `cidr-map.txt`, `host-map.txt` and `net-map.json`. 

This editor provides the following controls:

* 🔎 **Search mappings** - narrow the list of visible items using a search filter
* **Type**, **Address**, **Name** and **Tag** *(column headings)* - sort the list of items by clicking a column header
* 📝 *(per item)* - modify the selected item
* 🚫 *(per item)* - remove the selected item
* 🖳 **host** / 🖧 **segment**, **Address**, **Name**, **Tag (optional)** and 💾 - save the item with these values (either adding a new item or updating the item being modified)
* 📥 **Import** - clear the list and replace it with the contents of an uploaded `net-map.json` file
* 📤 **Export** - format and download the list as a `net-map.json` file
* 💾 **Save Mappings** - format and store `net-map.json` in the Malcolm directory (replacing the existing `net-map.json` file)
* 🔁 **Restart Logstash** - restart log ingestion, parsing and enrichment

![Host and Subnet Name Mapping Editor](./docs/images/screenshots/malcolm_name_map_ui.png)

#### <a name="ApplyMapping"></a>Applying mapping changes

When changes are made to either `cidr-map.txt`, `host-map.txt` or `net-map.json`, Malcolm's Logstash container must be restarted. The easiest way to do this is to restart malcolm via `restart` (see [Stopping and restarting Malcolm](#StopAndRestart)) or by clicking the 🔁 **Restart Logstash** button in the [name mapping interface](#NameMapUI) interface.

Restarting Logstash may take several minutes, after which log ingestion will be resumed.

## <a name="IndexManagement"></a>Elasticsearch index management

See [Index State Management](https://opendistro.github.io/for-elasticsearch-docs/docs/ism/) in the Open Distro for Elasticsearch documentation on Index State Management [policies](https://opendistro.github.io/for-elasticsearch-docs/docs/ism/policies/), [managed indices](https://opendistro.github.io/for-elasticsearch-docs/docs/ism/managedindices/), [settings](https://opendistro.github.io/for-elasticsearch-docs/docs/ism/settings/) and [APIs](https://opendistro.github.io/for-elasticsearch-docs/docs/ism/api/).

Elasticsearch index management only deals with disk space consumed by Elasticsearch indices: it does not have anything to do with PCAP file storage. The `MANAGE_PCAP_FILES` environment variable in the [`docker-compose.yml`](#DockerComposeYml) file can be used to allow Arkime to prune old PCAP files based on available disk space.

## <a name="Alerting"></a>Alerting

See [Alerting](https://opendistro.github.io/for-elasticsearch-docs/docs/alerting/) in the Open Distro for Elasticsearch documentation.

When using an email account to send alerts, you must [authenticate each sender account](https://opendistro.github.io/for-elasticsearch-docs/docs/alerting/monitors/#authenticate-sender-account) before you can send an email. The [`auth_setup`](#AuthSetup) script can be used to securely store the email account credentials:

```
./scripts/auth_setup 

Store administrator username/password for local Malcolm access? (Y/n): n

(Re)generate self-signed certificates for HTTPS access (Y/n): n

(Re)generate self-signed certificates for a remote log forwarder (Y/n): n

Store username/password for forwarding Logstash events to a secondary, external Elasticsearch instance (y/N): n

Store username/password for email alert sender account (y/N): y

Open Distro alerting destination name: destination_alpha

Email account username: analyst@example.org
analyst@example.org password: 
analyst@example.org password (again): 
Email alert sender account variables stored: opendistro.alerting.destination.email.destination_alpha.password, opendistro.alerting.destination.email.destination_alpha.username
```

This action should only be performed while Malcolm is [stopped](#StopAndRestart): otherwise the credentials will not be stored correctly.

## <a name="OtherBeats"></a>Using Beats to forward host logs to Malcolm

Because Malcolm uses components of the open source data analysis platform [Elastic Stack](https://www.elastic.co/elastic-stack), it can accept various host logs sent from [Beats](https://www.elastic.co/beats/#the-beats-family), Elastic Stack's lightweight data shippers. See [./scripts/beats](./scripts/beats) for more information.

## <a name="ISO"></a>Malcolm installer ISO

Malcolm's Docker-based deployment model makes Malcolm able to run on a variety of platforms. However, in some circumstances (for example, as a long-running appliance as part of a security operations center, or inside of a virtual machine) it may be desirable to install Malcolm as a dedicated standalone installation.

Malcolm can be packaged into an installer ISO based on the current [stable release](https://wiki.debian.org/DebianStable) of [Debian](https://www.debian.org/). This [customized Debian installation](https://wiki.debian.org/DebianLive) is preconfigured with the bare minimum software needed to run Malcolm.

### <a name="ISOBuild"></a>Generating the ISO

Official downloads of the Malcolm installer ISO are not provided: however, it can be built easily on an internet-connected Linux host running current versions of [VirtualBox](https://www.virtualbox.org/) and [Vagrant](https://www.vagrantup.com/) (with the [`vagrant-reload`](https://github.com/aidanns/vagrant-reload) plugin).

To perform a clean build the Malcolm installer ISO, navigate to your local Malcolm working copy and run:

```
$ ./malcolm-iso/build_via_vagrant.sh -f
…
Starting build machine...
Bringing machine 'default' up with 'virtualbox' provider...
…
```

Building the ISO may take 30 minutes or more depending on your system. As the build finishes, you will see the following message indicating success:

```
…
Finished, created "/malcolm-build/malcolm-iso/malcolm-3.0.0.iso"
…
```

By default, Malcolm's Docker images are not packaged with the installer ISO, assuming instead that you will pull the [latest images](https://hub.docker.com/u/malcolmnetsec) with a `docker-compose pull` command as described in the [Quick start](#QuickStart) section. If you wish to build an ISO with the latest Malcolm images included, follow the directions to create [pre-packaged installation files](#Packager), which include a tarball with a name like `malcolm_YYYYMMDD_HHNNSS_xxxxxxx_images.tar.gz`. Then, pass that images tarball to the ISO build script with a `-d`, like this:

```
$ ./malcolm-iso/build_via_vagrant.sh -f -d malcolm_YYYYMMDD_HHNNSS_xxxxxxx_images.tar.gz
…
```

A system installed from the resulting ISO will load the Malcolm Docker images upon first boot. This method is desirable when the ISO is to be installed in an "air gapped" environment or for distribution to non-networked machines.

### <a name="ISOInstallation"></a>Installation

The installer is designed to require as little user input as possible. For this reason, there are NO user prompts and confirmations about partitioning and reformatting hard disks for use by the operating system. The  installer assumes that all non-removable storage media (eg., SSD, HDD, NVMe, etc.) are available for use and ⛔🆘😭💀 ***will partition and format them without warning*** 💀😭🆘⛔.

The installer will ask for several pieces of information prior to installing the Malcolm base operating system:

* Hostname
* Domain name
* Root password – (optional) a password for the privileged root account which is rarely needed
* User name: the name for the non-privileged service account user account under which the Malcolm runs
* User password – a password for the non-privileged sensor account
* Encryption password (optional) – if the encrypted installation option was selected at boot time, the encryption password must be entered every time the system boots

At the end of the installation process, you will be prompted with a few self-explanatory yes/no questions:

* **Disable IPv6?**
* **Automatically login to the GUI session?**
* **Should the GUI session be locked due to inactivity?**
* **Display the [Standard Mandatory DoD Notice and Consent Banner](https://www.stigviewer.com/stig/application_security_and_development/2018-12-24/finding/V-69349)?** *(only applies when installed on U.S. government information systems)*

Following these prompts, the installer will reboot and the Malcolm base operating system will boot.

### <a name="ISOSetup"></a>Setup

When the system boots for the first time, the Malcolm Docker images will load if the installer was built with pre-packaged installation files as described above. Wait for this operation to continue (the progress dialog will disappear when they have finished loading) before continuing the setup.

Open a terminal (click the red terminal 🗔 icon next to the Debian swirl logo 🍥 menu button in the menu bar). At this point, setup is similar to the steps described in the [Quick start](#QuickStart) section. Navigate to the Malcolm directory (`cd ~/Malcolm`) and run [`auth_setup`](#AuthSetup) to configure authentication. If the ISO didn't have pre-packaged Malcolm images, or if you'd like to retrieve the latest updates, run `docker-compose pull`. Finalize your configuration by running `scripts/install.py --configure` and follow the prompts as illustrated in the [installation example](#InstallationExample).

Once Malcolm is configured, you can [start Malcolm](#Starting) via the command line or by clicking the circular yellow Malcolm icon in the menu bar.

### <a name="ConfigTime"></a>Time synchronization

If you wish to set up time synchronization via [NTP](http://www.ntp.org/) or `htpdate`, open a terminal and run `sudo configure-interfaces.py`. Select **Continue**, then choose **Time Sync**. Here you can configure the operating system to keep its time synchronized with either an NTP server (using the NTP protocol), another Malcolm instance, or another HTTP/HTTPS server. On the next dialog, choose the time synchronization method you wish to configure.

If **htpdate** is selected, you will be prompted to enter the IP address or hostname and port of an HTTP/HTTPS server (for a Malcolm instance, port `9200` may be used) and the time synchronization check frequency in minutes. A test connection will be made to determine if the time can be retrieved from the server.

If *ntpdate* is selected, you will be prompted to enter the IP address or hostname of the NTP server.

Upon configuring time synchronization, a "Time synchronization configured successfully!" message will be displayed.

### <a name="Hardening"></a>Hardening

The Malcolm aggregator base operating system targets the following guidelines for establishing a secure configuration posture:

* DISA STIG (Security Technical Implementation Guides) [ported](https://github.com/hardenedlinux/STIG-4-Debian) from [DISA RHEL 7 STIG](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/) v1r1 to a Debian 9 base platform
* [CIS Debian Linux 9 Benchmark](https://www.cisecurity.org/cis-benchmarks/cis-benchmarks-faq/) with additional recommendations by the [hardenedlinux/harbian-audit](https://github.com/hardenedlinux/harbian-audit) project

#### <a name="STIGExceptions"></a>STIG compliance exceptions

[Currently](https://github.com/hardenedlinux/STIG-4-Debian/blob/master/stig-debian.txt) there are 158 compliance checks that can be verified automatically and 23 compliance checks that must be verified manually.

The Malcolm aggregator base operating system claims the following exceptions to STIG compliance:

| # | ID  | Title | Justification |
| --- | --- | --- | --- |
| 1 | [SV-86535r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-71911) | When passwords are changed a minimum of eight of the total number of characters must be changed. | Account/password policy exception: As an aggregator running Malcolm is intended to be used as an appliance rather than a general user-facing software platform, some exceptions to password enforcement policies are claimed. |
| 2 | [SV-86537r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-71913) | When passwords are changed a minimum of four character classes must be changed. | Account/password policy exception |
| 3 | [SV-86549r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-71925) | Passwords for new users must be restricted to a 24 hours/1 day minimum lifetime. | Account/password policy exception |
| 4 | [SV-86551r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-71927) | Passwords must be restricted to a 24 hours/1 day minimum lifetime. | Account/password policy exception |
| 5 | [SV-86553r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-71929) | Passwords for new users must be restricted to a 60-day maximum lifetime. | Account/password policy exception |
| 6 | [SV-86555r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-71931) | Existing passwords must be restricted to a 60-day maximum lifetime. | Account/password policy exception |
| 7 | [SV-86557r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-71933) | Passwords must be prohibited from reuse for a minimum of five generations. | Account/password policy exception |
| 8 | [SV-86565r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-71941) | The operating system must disable account identifiers (individuals, groups, roles, and devices) if the password expires. | Account/password policy exception |
| 9 | [SV-86567r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-71943) | Accounts subject to three unsuccessful logon attempts within 15 minutes must be locked for the maximum configurable period. | Account/password policy exception |
| 10 | [SV-86569r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-71945) | If three unsuccessful root logon attempts within 15 minutes occur the associated account must be locked. | Account/password policy exception |
| 11 | [SV-86603r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2018-11-28/finding/V-71979) | The … operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components of local packages without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization. | As the base distribution is not using embedded signatures, `debsig-verify` would reject all packages (see comment in `/etc/dpkg/dpkg.cfg`). Enabling it after installation would disallow any future updates. |
| 12 | [SV-86607r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-71983) | USB mass storage must be disabled. | The ability to ingest data (such as PCAP files) from a mounted USB mass storage device is a requirement of the system. |
| 13 | [SV-86609r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-71985) | File system automounter must be disabled unless required. | The ability to ingest data (such as PCAP files) from a mounted USB mass storage device is a requirement of the system. |
| 14 | [SV-86705r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72081) | The operating system must shut down upon audit processing failure, unless availability is an overriding concern. If availability is a concern, the system must alert the designated staff (System Administrator [SA] and Information System Security Officer [ISSO] at a minimum) in the event of an audit processing failure. | As maximizing availability is a system requirement, audit processing failures will be logged on the device rather than halting the system. |
| 15 | [SV-86713r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72089) | The operating system must immediately notify the System Administrator (SA) and Information System Security Officer ISSO (at a minimum) when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity. | same as above |
| 16 | [SV-86715r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-72093) | The operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached. | same as above |
| 17 | [SV-86597r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-71973) | A file integrity tool must verify the baseline operating system configuration at least weekly. | This functionality is not configured by default, but it could be configured post-install using [Auditbeat](https://www.elastic.co/products/beats/auditbeat) or `aide` |
| 18 | [SV-86697r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-72073) | The file integrity tool must use FIPS 140-2 approved cryptographic hashes for validating file contents and directories. | same as above |
| 19 | [SV-86707r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-72083) | The operating system must off-load audit records onto a different system or media from the system being audited. | same as above |
| 20 | [SV-86709r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72085) | The operating system must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited. | same as above  |
| 21 | [SV-86833r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-72209) | The system must send rsyslog output to a log aggregation server. | same as above  |
| 22 | [SV-87815r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-73163) | The audit system must take appropriate action when there is an error sending audit records to a remote system. | same as above  |
| 23 | [SV-86693r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72069) | The file integrity tool must be configured to verify Access Control Lists (ACLs). | As this is not a multi-user system, the ACL check would be irrelevant. |
| 24 | [SV-86837r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2016-12-16/finding/V-38666) | The system must use and update a DoD-approved virus scan program. | As this is a network traffic analysis appliance rather than an end-user device, regular user files will not be created. A virus scan program would impact device performance and would be unnecessary. |
| 25 | [SV-86839r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72215) | The system must update the virus scan program every seven days or more frequently. | As this is a network traffic analysis appliance rather than an end-user device, regular user files will not be created. A virus scan program would impact device performance and would be unnecessary. |
| 26 | [SV-86847r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72223) | All network connections associated with a communication session must be terminated at the end of the session or after 10 minutes of inactivity from the user at a command prompt, except to fulfill documented and validated mission requirements. | Malcolm be controlled from the command line in a manual capture scenario, so timing out a session based on command prompt inactivity would be inadvisable. | 
| 27 | [SV-86893r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72269) | The operating system must, for networked systems, synchronize clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS). | While [time synchronization](#ConfigTime) is supported on the Malcolm aggregator base operating system, an exception is claimed for this rule as the device may be configured to sync to servers other than the ones listed in the STIG. |
| 28 | [SV-86905r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72281) | For systems using DNS resolution, at least two name servers must be configured. | STIG recommendations for DNS servers are not enforced on the Malcolm aggregator base operating system to allow for use in a variety of network scenarios. |
| 29 | [SV-86919r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-72295) | Network interfaces must not be in promiscuous mode. | One purpose of the Malcolm aggregator base operating system is to sniff and capture network traffic. |
| 30 | [SV-86931r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72307) | An X Windows display manager must not be installed unless approved. | A locked-down X Windows session is required for the sensor's kiosk display. |
| 31 | [SV-86519r3](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-71895) | The operating system must set the idle delay setting for all connection types. | As this is a network traffic aggregation and analysis appliance rather than an end-user device, timing out displays or connections would not be desirable. |
| 32 | [SV-86523r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-71899) | The operating system must initiate a session lock for the screensaver after a period of inactivity for graphical user interfaces. | This option is configurable during install time. Some installations of the Malcolm aggregator base operating system may be on appliance hardware not equipped with a keyboard by default, in which case it may not be desirable to lock the session.|
| 33 | [SV-86525r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-71901) | The operating system must initiate a session lock for graphical user interfaces when the screensaver is activated. | This option is configurable during install time. Some installations of the Malcolm aggregator base operating system may be on appliance hardware not equipped with a keyboard by default, in which case it may not be desirable to lock the session. |
| 34 | [SV-86589r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-71965) | The operating system must uniquely identify and must authenticate organizational users (or processes acting on behalf of organizational users) using multifactor authentication. | As this is a network traffic capture appliance rather than an end-user device or a multiuser network host, this requirement is not applicable. |
| 35 | [SV-86921r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-72297) | The system must be configured to prevent unrestricted mail relaying. | Does not apply as the Malcolm aggregator base operating system not does run a mail service. |
| 36 | [SV-86929r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72305) | If the Trivial File Transfer Protocol (TFTP) server is required, the TFTP daemon must be configured to operate in secure mode. | Does not apply as the Malcolm aggregator base operating system does not run a TFTP server. |
| 37 | [SV-86935r3](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72311) | The Network File System (NFS) must be configured to use RPCSEC_GSS. | Does not apply as the Malcolm aggregator base operating system does not run an NFS server. |
| 38 | [SV-87041r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72417) | The operating system must have the required packages for multifactor authentication installed. | As this is a network traffic capture appliance rather than an end-user device or a multiuser network host, this requirement is not applicable. |
| 39 | [SV-87051r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-72427) | The operating system must implement multifactor authentication for access to privileged accounts via pluggable authentication modules (PAM). | As this is a network traffic capture appliance rather than an end-user device or a multiuser network host, this requirement is not applicable. |
| 40 | [SV-87059r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-72435) | The operating system must implement smart card logons for multifactor authentication for access to privileged accounts. | As this is a network traffic capture appliance rather than an end-user device or a multiuser network host, this requirement is not applicable. |
| 41 | [SV-87829r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-73177) | Wireless network adapters must be disabled. | As an appliance intended to capture network traffic in a variety of network environments, wireless adapters may be needed to capture and/or report wireless traffic. |
| 42 | [SV-86699r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72075) | The system must not allow removable media to be used as the boot loader unless approved. | the Malcolm aggregator base operating system supports a live boot mode that can be booted from removable media. |

Please review the notes for these additional rules. While not claiming an exception, they may be implemented or checked in a different way than outlined by the RHEL STIG as the Malcolm aggregator base operating system is not built on RHEL or for other reasons.

| # | ID  | Title | Note |
| --- | --- | --- | --- |
| 1 | [SV-86585r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-71961) | Systems with a Basic Input/Output System (BIOS) must require authentication upon booting into single-user and maintenance modes. | Although the [compliance check script](https://github.com/hardenedlinux/STIG-4-Debian) does not detect it, booting into recovery mode *does* in fact require the root password. |
| 2 | [SV-86587r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-71963) | Systems using Unified Extensible Firmware Interface (UEFI) must require authentication upon booting into single-user and maintenance modes. | Although the [compliance check script](https://github.com/hardenedlinux/STIG-4-Debian) does not detect it, booting into recovery mode *does* in fact require the root password. |
| 3 | [SV-86651r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72027) | All files and directories contained in local interactive user home directories must have mode 0750 or less permissive. | Depending on when the [compliance check script](https://github.com/hardenedlinux/STIG-4-Debian) is run, some ephemeral files may exist in the service account's home directory which will cause this check to fail. For practical purposes the Malcolm aggregator base operating system's configuration does, however, comply.
| 4 | [SV-86623r3](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-71999) | Vendor packaged system security patches and updates must be installed and up to date. | When the the Malcolm aggregator base operating system sensor appliance software is built, all of the latest applicable security patches and updates are included in it. How future updates are to be handled is still in design. |
| 6 | [SV-86691r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-72067) | The operating system must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards. | the Malcolm aggregator base operating system does use FIPS-compatible libraries for cryptographic functions. However, the kernel parameter being checked by the [compliance check script](https://github.com/hardenedlinux/STIG-4-Debian) is incompatible with some of the systems initialization scripts.|

In addition, DISA STIG rules SV-86663r1, SV-86695r2, SV-86759r3, SV-86761r3, SV-86763r3, SV-86765r3, SV-86595r1, and SV-86615r2 relate to the SELinux kernel which is not used in the Malcolm aggregator base operating system, and are thus skipped.

#### <a name="CISExceptions"></a>CIS benchmark compliance exceptions

[Currently](https://github.com/hardenedlinux/harbian-audit/tree/master/bin/hardening) there are 271 checks to determine compliance with the CIS Debian Linux 9 Benchmark.

The Malcolm aggregator base operating system claims exceptions from the recommendations in this benchmark in the following categories:

**1.1 Install Updates, Patches and Additional Security Software** - When the the Malcolm aggregator appliance software is built, all of the latest applicable security patches and updates are included in it. How future updates are to be handled is still in design.

**1.3 Enable verify the signature of local packages** - As the base distribution is not using embedded signatures, `debsig-verify` would reject all packages (see comment in `/etc/dpkg/dpkg.cfg`). Enabling it after installation would disallow any future updates.

**2.14 Add nodev option to /run/shm Partition**, **2.15 Add nosuid Option to /run/shm Partition**, **2.16 Add noexec Option to /run/shm Partition** - The Malcolm aggregator base operating system does not mount `/run/shm` as a separate partition, so these recommendations do not apply.

**2.18 Disable Mounting of cramfs Filesystems**, **2.19 Disable Mounting of freevxfs Filesystems**, **2.20 Disable Mounting of jffs2 Filesystems**, **2.21 Disable Mounting of hfs Filesystems**, **2.22 Disable Mounting of hfsplus Filesystems**, **2.23 Disable Mounting of squashfs Filesystems**, **2.24 Disable Mounting of udf Filesystems** - The Malcolm aggregator base operating system is not compiling a custom Linux kernel, so these filesystems are inherently supported as they are part Debian Linux's default kernel.

**4.6 Disable USB Devices** - The ability to ingest data (such as PCAP files) from a mounted USB mass storage device is a requirement of the system.

**6.1 Ensure the X Window system is not installed**, **6.2 Ensure Avahi Server is not enabled**, **6.3 Ensure print server is not enabled** - An X Windows session is provided for displaying dashboards. The library packages `libavahi-common-data`, `libavahi-common3`, and `libcups2` are dependencies of some of the X components used by the Malcolm aggregator base operating system, but the `avahi` and `cups` services themselves are disabled.

**6.17 Ensure virus scan Server is enabled**, **6.18 Ensure virus scan Server update is enabled** - As this is a network traffic analysis appliance rather than an end-user device, regular user files will not be created. A virus scan program would impact device performance and would be unnecessary.

**7.2.4 Log Suspicious Packets**, **7.2.7 Enable RFC-recommended Source Route Validation**, **7.4.1 Install TCP Wrappers** - As Malcolm may operate as a network traffic capture appliance sniffing packets on a network interface configured in promiscuous mode, these recommendations do not apply.

**8.4.1 Install aide package** and **8.4.2 Implement Periodic Execution of File Integrity** - This functionality is not configured by default, but it could be configured post-install using [Auditbeat](https://www.elastic.co/products/beats/auditbeat) or `aide`.

**8.1.1.2 Disable System on Audit Log Full**, **8.1.1.3 Keep All Auditing Information**, **8.1.1.5 Ensure set remote_server for audit service**, **8.1.1.6 Ensure enable_krb5 set to yes for remote audit service**, **8.1.1.7 Ensure set action for audit storage volume is fulled**, **8.1.1.9 Set space left for auditd service**, a few other audit-related items under section **8.1**, **8.2.5 Configure rsyslog to Send Logs to a Remote Log Host** - As maximizing availability is a system requirement, audit processing failures will be logged on the device rather than halting the system. `auditd` is set up to syslog when its local storage capacity is reached.

Password-related recommendations under **9.2** and **10.1** - The library package `libpam-pwquality` is used in favor of `libpam-cracklib` which is what the [compliance scripts](https://github.com/hardenedlinux/harbian-audit/tree/master/bin/hardening) are looking for. Also, as an appliance running Malcolm is intended to be used as an appliance rather than a general user-facing software platform, some exceptions to password enforcement policies are claimed.

**9.3.13 Limit Access via SSH** - The Malcolm aggregator base operating system does not create multiple regular user accounts: only `root` and an aggregator service account are used. SSH access for `root` is disabled. SSH login with a password is also disallowed: only key-based authentication is accepted. The service account accepts no keys by default. As such, the `AllowUsers`, `AllowGroups`, `DenyUsers`, and `DenyGroups` values in `sshd_config` do not apply.

**9.5 Restrict Access to the su Command** - The Malcolm aggregator base operating system does not create multiple regular user accounts: only `root` and an aggregator service account are used.

**10.1.10 Set maxlogins for all accounts** and **10.5 Set Timeout on ttys** - The Malcolm aggregator base operating system does not create multiple regular user accounts: only `root` and an aggregator service account are used.

**12.10 Find SUID System Executables**, **12.11 Find SGID System Executables** - The few files found by [these](https://github.com/hardenedlinux/harbian-audit/blob/master/bin/hardening/12.10_find_suid_files.sh) [scripts](https://github.com/hardenedlinux/harbian-audit/blob/master/bin/hardening/12.11_find_sgid_files.sh) are valid exceptions required by the Malcolm aggregator base operating system's core requirements.

Please review the notes for these additional guidelines. While not claiming an exception, the Malcolm aggregator base operating system may implement them in a manner different than is described by the [CIS Debian Linux 9 Benchmark](https://www.cisecurity.org/cis-benchmarks/cis-benchmarks-faq/) or the [hardenedlinux/harbian-audit](https://github.com/hardenedlinux/harbian-audit) audit scripts.

**4.1 Restrict Core Dumps** - The Malcolm aggregator base operating system disables core dumps using a configuration file for `ulimit` named `/etc/security/limits.d/limits.conf`. The [audit script](https://github.com/hardenedlinux/harbian-audit/blob/master/bin/hardening/4.1_restrict_core_dumps.sh) checking for this does not check the `limits.d` subdirectory, which is why this is incorrectly flagged as noncompliant.

**5.4 Ensure ctrl-alt-del is disabled** - The Malcolm aggregator base operating system disables the `ctrl+alt+delete` key sequence by executing `systemctl disable ctrl-alt-del.target` during installation and the command `systemctl mask ctrl-alt-del.target` at boot time.

**6.19 Configure Network Time Protocol (NTP)** - While [time synchronization](#ConfigTime) is supported on the Malcolm aggregator base operating system, an exception is claimed for this rule as the network sensor device may be configured to sync to servers in a different way than specified in the benchmark.

**7.4.4 Create /etc/hosts.deny**, **7.7.1 Ensure Firewall is active**, **7.7.4.1 Ensure default deny firewall policy**, **7.7.4.3 Ensure default deny firewall policy**, **7.7.4.4 Ensure outbound and established connections are configured** - The Malcolm aggregator base operating system **is** configured with an appropriately locked-down software firewall (managed by "Uncomplicated Firewall" `ufw`). However, the methods outlined in the CIS benchmark recommendations do not account for this configuration. 

**8.7 Verifies integrity all packages** - The [script](https://github.com/hardenedlinux/harbian-audit/blob/master/bin/hardening/8.7_verify_integrity_packages.sh) which verifies package integrity only "fails" because of missing (status `??5??????` displayed by the utility) language ("locale") files, which are removed as part of the Malcolm aggregator base operating system's trimming-down process. All non-locale-related system files pass intergrity checks.

## <a name="Issues"></a>Known issues

### PCAP file export error when Zeek logs are in Arkime search results

Arkime has a nice feature that allows you to export PCAP files matching the filters currently populating the search field. However, Arkime viewer will raise an exception if records created from Zeek logs are found among the search results to be exported. For this reason, if you are using the export PCAP feature it is recommended that you apply the **PCAP Files** view to filter your search results prior to doing the export.

### Manual Kibana index pattern refresh

Because some fields are created in Elasticsearch dynamically when Zeek logs are ingested by Logstash, they may not have been present when Kibana configures its index pattern field mapping during initialization. As such, those fields will not show up in Kibana visualizations until Kibana’s copy of the field list is refreshed. Malcolm periodically refreshes this list, but if fields are missing from your visualizations you may wish to do it manually.

After Malcolm ingests your data (or, more specifically, after it has ingested a new log type it has not seen before) you may manually refresh Kibana’s field list by clicking **Management** → **Index Patterns**, then selecting the `sessions2-*` index pattern and clicking the reload **🗘** button near the upper-right of the window.

![Refreshing Kibana's cached index pattern](./docs/images/screenshots/kibana_refresh_index.png)

## <a name="InstallationExample"></a>Installation example using Ubuntu 20.04 LTS

Here's a step-by-step example of getting [Malcolm from GitHub](https://github.com/idaholab/Malcolm/tree/master), configuring your system and your Malcolm instance, and running it on a system running Ubuntu Linux. Your mileage may vary depending on your individual system configuration, but this should be a good starting point.

The commands in this example should be executed as a non-root user.

You can use `git` to clone Malcolm into a local working copy, or you can download and extract the artifacts from the [latest release](https://github.com/idaholab/Malcolm/releases).

To install Malcolm from the latest Malcolm release, browse to the [Malcolm releases page on GitHub](https://github.com/idaholab/Malcolm/releases) and download at a minimum `install.py` and the `malcolm_YYYYMMDD_HHNNSS_xxxxxxx.tar.gz` file, then navigate to your downloads directory:
```
user@host:~$ cd Downloads/
user@host:~/Downloads$ ls
malcolm_common.py install.py  malcolm_20190611_095410_ce2d8de.tar.gz
```

If you are obtaining Malcolm using `git` instead, run the following command to clone Malcolm into a local working copy:
```
user@host:~$ git clone https://github.com/idaholab/Malcolm
Cloning into 'Malcolm'...
remote: Enumerating objects: 443, done.
remote: Counting objects: 100% (443/443), done.
remote: Compressing objects: 100% (310/310), done.
remote: Total 443 (delta 81), reused 441 (delta 79), pack-reused 0
Receiving objects: 100% (443/443), 6.87 MiB | 18.86 MiB/s, done.
Resolving deltas: 100% (81/81), done.

user@host:~$ cd Malcolm/
```

Next, run the `install.py` script to configure your system. Replace `user` in this example with your local account username, and follow the prompts. Most questions have an acceptable default you can accept by pressing the `Enter` key. Depending on whether you are installing Malcolm from the release tarball or inside of a git working copy, the questions below will be slightly different, but for the most part are the same.
```
user@host:~/Downloads$ sudo ./install.py
Installing required packages: ['apache2-utils', 'make', 'openssl']

"docker info" failed, attempt to install Docker? (Y/n): y

Attempt to install Docker using official repositories? (Y/n): y
Installing required packages: ['apt-transport-https', 'ca-certificates', 'curl', 'gnupg-agent', 'software-properties-common']
Installing docker packages: ['docker-ce', 'docker-ce-cli', 'containerd.io']
Installation of docker packages apparently succeeded

Add a non-root user to the "docker" group? (y/n): y

Enter user account: user

Add another non-root user to the "docker" group? (y/n): n

"docker-compose version" failed, attempt to install docker-compose? (Y/n): y

Install docker-compose directly from docker github? (Y/n): y
Download and installation of docker-compose apparently succeeded


fs.file-max increases allowed maximum for file handles
fs.file-max= appears to be missing from /etc/sysctl.conf, append it? (Y/n): y

fs.inotify.max_user_watches increases allowed maximum for monitored files
fs.inotify.max_user_watches= appears to be missing from /etc/sysctl.conf, append it? (Y/n): y

fs.inotify.max_queued_events increases queue size for monitored files
fs.inotify.max_queued_events= appears to be missing from /etc/sysctl.conf, append it? (Y/n): y

fs.inotify.max_user_instances increases allowed maximum monitor file watchers
fs.inotify.max_user_instances= appears to be missing from /etc/sysctl.conf, append it? (Y/n): y


vm.max_map_count increases allowed maximum for memory segments
vm.max_map_count= appears to be missing from /etc/sysctl.conf, append it? (Y/n): y


net.core.somaxconn increases allowed maximum for socket connections
net.core.somaxconn= appears to be missing from /etc/sysctl.conf, append it? (Y/n): y


vm.swappiness adjusts the preference of the system to swap vs. drop runtime memory pages
vm.swappiness= appears to be missing from /etc/sysctl.conf, append it? (Y/n): y


vm.dirty_background_ratio defines the percentage of system memory fillable with "dirty" pages before flushing
vm.dirty_background_ratio= appears to be missing from /etc/sysctl.conf, append it? (Y/n): y


vm.dirty_ratio defines the maximum percentage of dirty system memory before committing everything
vm.dirty_ratio= appears to be missing from /etc/sysctl.conf, append it? (Y/n): y


/etc/security/limits.d/limits.conf increases the allowed maximums for file handles and memlocked segments
/etc/security/limits.d/limits.conf does not exist, create it? (Y/n): y
```

At this point, **if you are installing from the a release tarball** you will be asked if you would like to extract the contents of the tarball and to specify the installation directory:
```
Extract Malcolm runtime files from /home/user/Downloads/malcolm_20190611_095410_ce2d8de.tar.gz (Y/n): y

Enter installation path for Malcolm [/home/user/Downloads/malcolm]: /home/user/Malcolm
Malcolm runtime files extracted to /home/user/Malcolm
```

Alternatively, **if you are configuring Malcolm from within a git working copy**, `install.py` will now exit. Run `install.py` again like you did at the beginning of the example, only remove the `sudo` and add `--configure` to run `install.py` in "configuration only" mode. 
```
user@host:~/Malcolm$ ./scripts/install.py --configure
```

Now that any necessary system configuration changes have been made, the local Malcolm instance will be configured:
```
Malcolm processes will run as UID 1000 and GID 1000. Is this OK? (Y/n): 

Setting 10g for Elasticsearch and 3g for Logstash. Is this OK? (Y/n): y

Restart Malcolm upon system or Docker daemon restart? (y/N): y

Select Malcolm restart behavior ('no', 'on-failure', 'always', 'unless-stopped'): unless-stopped

Authenticate against Lightweight Directory Access Protocol (LDAP) server? (y/N): n

Configure snapshot repository for Elasticsearch index state management? (y/N): n

Store snapshots locally in /home/user/Malcolm/elasticsearch-backup? (Y/n): y

Automatically analyze all PCAP files with Zeek? (y/N): y

Perform reverse DNS lookup locally for source and destination IP addresses in Zeek logs? (y/N): n

Perform hardware vendor OUI lookups for MAC addresses? (Y/n): y

Expose Logstash port to external hosts? (y/N): n

Forward Logstash logs to external Elasticstack instance? (y/N): n

Enable file extraction with Zeek? (y/N): y

Select file extraction behavior ('none', 'known', 'mapped', 'all', 'interesting'): interesting

Select file preservation behavior ('quarantined', 'all', 'none'): quarantined

Scan extracted files with ClamAV? (y/N): y

Scan extracted files with Yara? (y/N): y

Scan extracted PE files with Capa? (y/N): y

Lookup extracted file hashes with VirusTotal? (y/N): n

Download updated scanner signatures periodically? (Y/n): y

Should Malcolm capture network traffic to PCAP files? (y/N): y

Specify capture interface(s) (comma-separated): eth0

Capture packets using netsniff-ng? (Y/n): y

Capture packets using tcpdump? (y/N): n

Malcolm has been installed to /home/user/Malcolm. See README.md for more information.
Scripts for starting and stopping Malcolm and changing authentication-related settings can be found
in /home/user/Malcolm/scripts.
```

At this point you should **reboot your computer** so that the new system settings can be applied. After rebooting, log back in and return to the directory to which Malcolm was installed (or to which the git working copy was cloned).

Now we need to [set up authentication](#AuthSetup) and generate some unique self-signed SSL certificates. You can replace `analyst` in this example with whatever username you wish to use to log in to the Malcolm web interface.
```
user@host:~/Malcolm$ ./scripts/auth_setup
Store administrator username/password for local Malcolm access? (Y/n): 

Administrator username: analyst
analyst password: 
analyst password (again): 

(Re)generate self-signed certificates for HTTPS access (Y/n): 

(Re)generate self-signed certificates for a remote log forwarder (Y/n): 

Store username/password for forwarding Logstash events to a secondary, external Elasticsearch instance (y/N): 

Store username/password for email alert sender account (y/N): 
```

For now, rather than [build Malcolm from scratch](#Build), we'll pull images from [Docker Hub](https://hub.docker.com/u/malcolmnetsec):
```
user@host:~/Malcolm$ docker-compose pull
Pulling elasticsearch ... done
Pulling file-monitor  ... done
Pulling filebeat      ... done
Pulling freq          ... done
Pulling htadmin       ... done
Pulling kibana        ... done
Pulling logstash      ... done
Pulling arkime        ... done
Pulling name-map-ui   ... done
Pulling nginx-proxy   ... done
Pulling pcap-capture  ... done
Pulling pcap-monitor  ... done
Pulling upload        ... done
Pulling zeek          ... done

user@host:~/Malcolm$ docker images
REPOSITORY                                          TAG                 IMAGE ID            CREATED             SIZE
malcolmnetsec/arkime                                3.0.0               xxxxxxxxxxxx        39 hours ago        683MB
malcolmnetsec/elasticsearch-od                      3.0.0               xxxxxxxxxxxx        40 hours ago        690MB
malcolmnetsec/file-monitor                          3.0.0               xxxxxxxxxxxx        39 hours ago        470MB
malcolmnetsec/file-upload                           3.0.0               xxxxxxxxxxxx        39 hours ago        199MB
malcolmnetsec/filebeat-oss                          3.0.0               xxxxxxxxxxxx        39 hours ago        555MB
malcolmnetsec/freq                                  3.0.0               xxxxxxxxxxxx        39 hours ago        390MB
malcolmnetsec/htadmin                               3.0.0               xxxxxxxxxxxx        39 hours ago        180MB
malcolmnetsec/kibana-helper                         3.0.0               xxxxxxxxxxxx        40 hours ago        141MB
malcolmnetsec/kibana-od                             3.0.0               xxxxxxxxxxxx        40 hours ago        1.16GB
malcolmnetsec/logstash-oss                          3.0.0               xxxxxxxxxxxx        39 hours ago        1.41GB
malcolmnetsec/name-map-ui                           3.0.0               xxxxxxxxxxxx        39 hours ago        137MB
malcolmnetsec/nginx-proxy                           3.0.0               xxxxxxxxxxxx        39 hours ago        120MB
malcolmnetsec/pcap-capture                          3.0.0               xxxxxxxxxxxx        39 hours ago        111MB
malcolmnetsec/pcap-monitor                          3.0.0               xxxxxxxxxxxx        39 hours ago        157MB
malcolmnetsec/zeek                                  3.0.0               xxxxxxxxxxxx        39 hours ago        887MB
```

Finally, we can start Malcolm. When Malcolm starts it will stream informational and debug messages to the console. If you wish, you can safely close the console or use `Ctrl+C` to stop these messages; Malcolm will continue running in the background.
```
user@host:~/Malcolm$ ./scripts/start
Creating network "malcolm_default" with the default driver
Creating malcolm_elasticsearch_1 ... done
Creating malcolm_file-monitor_1  ... done
Creating malcolm_filebeat_1      ... done
Creating malcolm_freq_1          ... done
Creating malcolm_htadmin_1       ... done
Creating malcolm_kibana_1        ... done
Creating malcolm_logstash_1      ... done
Creating malcolm_name-map-ui_1   ... done
Creating malcolm_arkime_1        ... done
Creating malcolm_nginx-proxy_1   ... done
Creating malcolm_pcap-capture_1  ... done
Creating malcolm_pcap-monitor_1  ... done
Creating malcolm_upload_1        ... done
Creating malcolm_zeek_1          ... done

In a few minutes, Malcolm services will be accessible via the following URLs:
------------------------------------------------------------------------------
  - Arkime: https://localhost/
  - Kibana: https://localhost/kibana/
  - PCAP Upload (web): https://localhost/upload/
  - PCAP Upload (sftp): sftp://username@127.0.0.1:8022/files/
  - Host and subnet name mapping editor: https://localhost/name-map-ui/
  - Account management: https://localhost:488/
…
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
…
Attaching to malcolm_elasticsearch_1, malcolm_file-monitor_1, malcolm_filebeat_1, malcolm_freq_1, malcolm_htadmin_1, malcolm_kibana_1, malcolm_logstash_1, malcolm_name-map-ui_1, malcolm_arkime_1, malcolm_nginx-proxy_1, malcolm_pcap-capture_1, malcolm_pcap-monitor_1, malcolm_upload_1, malcolm_zeek_1
…
```

It will take several minutes for all of Malcolm's components to start up. Logstash will take the longest, probably 3 to 5 minutes. You'll know Logstash is fully ready when you see Logstash spit out a bunch of starting up messages, ending with this:
```
…
logstash_1  | [2019-06-11T15:45:42,009][INFO ][logstash.agent    ] Pipelines running {:count=>4, :running_pipelines=>[:"malcolm-output", :"malcolm-input", :"malcolm-zeek", :"malcolm-enrichment"], :non_running_pipelines=>[]}
logstash_1  | [2019-06-11T15:45:42,599][INFO ][logstash.agent    ] Successfully started Logstash API endpoint {:port=>9600}
…
```

You can now open a web browser and navigate to one of the [Malcolm user interfaces](#UserInterfaceURLs).

## <a name="UpgradePlan"></a>Upgrading Malcolm

At this time there is not an "official" upgrade procedure to get from one version of Malcolm to the next, as it may vary from platform to platform. However, the process is fairly simple can be done by following these steps:

### Update the underlying system

You may wish to get the official updates for the underlying system's software packages before you proceed. Consult the documentation of your operating system for how to do this.

If you are upgrading an Malcolm instance installed from [Malcolm installation ISO](#ISOInstallation), follow scenario 2 below. Due to the Malcolm base operating system's [hardened](#Hardening) configuration, when updating the underlying system, temporarily set the umask value to Debian default (`umask 0022` in the root shell in which updates are being performed) instead of the more restrictive Malcolm default. This will allow updates to be applied with the right permissions.

### Scenario 1: Malcolm is a GitHub clone

If you checked out a working copy of the Malcolm repository from GitHub with a `git clone` command, here are the basic steps to performing an upgrade:

1. stop Malcolm
    * `./scripts/stop`
2. stash changes to `docker-compose.yml` and other files
    * `git stash save "pre-upgrade Malcolm configuration changes"`
3. pull changes from GitHub repository
    * `git pull --rebase`
4. pull new Docker images (this will take a while)
    * `docker-compose pull`
5. apply saved configuration change stashed earlier
    * `git stash pop`
6. if you see `Merge conflict` messages, resolve the [conflicts](https://git-scm.com/book/en/v2/Git-Branching-Basic-Branching-and-Merging#_basic_merge_conflicts) with your favorite text editor
7. you may wish to re-run `install.py --configure` as described in [System configuration and tuning](#ConfigAndTuning) in case there are any new `docker-compose.yml` parameters for Malcolm that need to be set up
8. start Malcolm
    * `./scripts/start`
9. you may be prompted to [configure authentication](#AuthSetup) if there are new authentication-related files that need to be generated
    * you probably do not need to re-generate self-signed certificates

### Scenario 2: Malcolm was installed from a packaged tarball

If you installed Malcolm from [pre-packaged installation files](https://github.com/idaholab/malcolm#Packager), here are the basic steps to perform an upgrade:

1. stop Malcolm
    * `./scripts/stop`
2. uncompress the new pre-packaged installation files (using `malcolm_YYYYMMDD_HHNNSS_xxxxxxx.tar.gz` as an example, the file and/or directory names will be different depending on the release)
    * `tar xf malcolm_YYYYMMDD_HHNNSS_xxxxxxx.tar.gz`
3. backup current Malcolm scripts, configuration files and certificates
    * `mkdir -p ./upgrade_backup_$(date +%Y-%m-%d)`
    * `cp -r filebeat/ htadmin/ logstash/ nginx/ auth.env cidr-map.txt docker-compose.yml host-map.txt net-map.json ./scripts ./README.md ./upgrade_backup_$(date +%Y-%m-%d)/`
3. replace scripts and local documentation in your existing installation with the new ones
    * `rm -rf ./scripts ./README.md`
    * `cp -r ./malcolm_YYYYMMDD_HHNNSS_xxxxxxx/scripts ./malcolm_YYYYMMDD_HHNNSS_xxxxxxx/README.md ./`
4. replace (overwrite) `docker-compose.yml` file with new version
    * `cp ./malcolm_YYYYMMDD_HHNNSS_xxxxxxx/docker-compose.yml ./docker-compose.yml`
5. re-run `./scripts/install.py --configure` as described in [System configuration and tuning](#ConfigAndTuning)
6. using a file comparison tool (e.g., `diff`, `meld`, `Beyond Compare`, etc.), compare `docker-compose.yml` and the `docker-compare.yml` file you backed up in step 3, and manually migrate over any customizations you wish to preserve from that file (e.g., `PCAP_FILTER`, `MAXMIND_GEOIP_DB_LICENSE_KEY`, `MANAGE_PCAP_FILES`; [anything else](#DockerComposeYml) you may have edited by hand in `docker-compose.yml` that's not prompted for in `install.py --configure`)
7. pull the new docker images (this will take a while)
    * `docker-compose pull` to pull them from Docker Hub or `docker-compose load -i malcolm_YYYYMMDD_HHNNSS_xxxxxxx_images.tar.gz` if you have an offline tarball of the Malcolm docker images
8. start Malcolm
    * `./scripts/start`
9. you may be prompted to [configure authentication](#AuthSetup) if there are new authentication-related files that need to be generated
    * you probably do not need to re-generate self-signed certificates

### Post-upgrade

#### Monitoring Malcolm

If you are technically-minded, you may wish to follow the debug output provided by `./scripts/start` (or `./scripts/logs` if you need to re-open the log stream after you've closed it), although there is a lot there and it may be hard to distinguish whether or not something is okay.

Running `docker-compose ps -a` should give you a good idea if all of Malcolm's Docker containers started up and, in some cases, may be able to indicate if the containers are "healthy" or not.

After upgrading following one of the previous outlines, give Malcolm several minutes to get started. Once things are up and running, open one of Malcolm's [web interfaces](#UserInterfaceURLs) to verify that things are working.

#### Loading new Kibana dashboards and visualizations

Once the upgraded instance Malcolm has started up, you'll probably want to import the new dashboards and visualizations for Kibana. You can signal Malcolm to load the new visualizations by opening Kibana, clicking **Management** → **Index Patterns**, then selecting the `sessions2-*` index pattern and clicking the delete **🗑** button near the upper-right of the window. Confirm the **Delete index pattern?** prompt by clicking **Delete**. Close the Kibana browser window. After a few minutes the missing index pattern will be detected and Kibana will be signalled to load its new dashboards and visualizations.

## <a name="Forks"></a>Forks

[CISA](https://www.cisa.gov/) maintains the original source code repository for Malcolm at [https://github.com/cisagov/Malcolm](https://github.com/cisagov/Malcolm). The [Idaho National Lab](https://inl.gov/)'s fork of Malcolm, which is currently kept up-to-date with CISA's upstream development, can be found at [https://github.com/idaholab/Malcolm](https://github.com/idaholab/Malcolm).

## <a name="Footer"></a>Copyright

[Malcolm](https://github.com/idaholab/Malcolm) is Copyright 2021 Battelle Energy Alliance, LLC, and is developed and released through the cooperation of the [Cybersecurity and Infrastructure Security Agency](https://www.cisa.gov/) of the [U.S. Department of Homeland Security](https://www.dhs.gov/).

See [`License.txt`](./License.txt) for the terms of its release.

### Contact information of author(s):

[Seth Grover](mailto:malcolm.netsec@gmail.com?subject=Malcolm)

## Other Software
Idaho National Laboratory is a cutting edge research facility which is constantly producing high quality research and software. Feel free to take a look at our other software and scientific offerings at:

[Primary Technology Offerings Page](https://www.inl.gov/inl-initiatives/technology-deployment)

[Supported Open Source Software](https://github.com/idaholab)

[Raw Experiment Open Source Software](https://github.com/IdahoLabResearch)

[Unsupported Open Source Software](https://github.com/IdahoLabCuttingBoard)
