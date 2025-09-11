# <a name="ZeekIntel"></a>Zeek Intelligence Framework

* [Zeek Intelligence Framework](#ZeekIntel)
    - [STIX™ and TAXII™](#ZeekIntelSTIX)
    - [MISP](#ZeekIntelMISP)
    - [Google Threat Intelligence](#ZeekIntelGoogle)
    - [Mandiant](#ZeekIntelMandiant)
    - [Endorsement Disclaimer](#IntelFeedDisclaimer)

To quote Zeek's [Intelligence Framework](https://docs.zeek.org/en/master/frameworks/intel.html) documentation, "The goals of Zeek’s Intelligence Framework are to consume intelligence data, make it available for matching, and provide infrastructure to improve performance and memory utilization. Data in the Intelligence Framework is an atomic piece of intelligence such as an IP address or an e-mail address. This atomic data will be packed with metadata such as a freeform source field, a freeform descriptive field, and a URL which might lead to more information about the specific item." Zeek [intelligence](https://docs.zeek.org/en/master/scripts/base/frameworks/intel/main.zeek.html) [indicator types](https://docs.zeek.org/en/master/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Type) include IP addresses, URLs, file names, hashes, email addresses, and more.

Malcolm doesn't come bundled with intelligence files from any particular feed, but they can be easily included into a local instance. On [startup]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/shared/bin/zeek_intel_setup.sh), Malcolm's `ghcr.io/idaholab/malcolm/zeek` container enumerates the subdirectories under `./zeek/intel` (which is [bind mounted](https://docs.docker.com/storage/bind-mounts/) into the container's runtime) and configures Zeek so those intelligence files will be automatically included in its local policy. Subdirectories under `./zeek/intel` that contain their own `__load__.zeek` file will be `@load`-ed as-is, while subdirectories containing "loose" intelligence files will be [loaded](https://docs.zeek.org/en/master/frameworks/intel.html#loading-intelligence) automatically with a `redef Intel::read_files` directive.

Note that Malcolm does not manage updates for these intelligence files. Users use the update mechanism suggested by the feeds' maintainers to keep intelligence files up to date, or use a [TAXII](#ZeekIntelSTIX), [MISP](#ZeekIntelMISP), [Google](#ZeekIntelGoogle), or [Mandiant](#ZeekIntelMandiant) feed as described below.

Adding and deleting intelligence files under this directory will take effect upon [restarting Malcolm](running.md#StopAndRestart). Alternately, users can use the `ZEEK_INTEL_REFRESH_CRON_EXPRESSION` environment variable containing a [cron expression](https://en.wikipedia.org/wiki/Cron#CRON_expression) to specify the interval at which the intel files should be refreshed. This can also be done manually without restarting Malcolm by running the following command from the Malcolm installation directory:

```
docker compose exec --user $(id -u) zeek /usr/local/bin/docker_entrypoint.sh true
```

As multiple instances of this container may be running in a Malcolm deployment (i.e., a `zeek-live` container for [monitoring local network interfaces](live-analysis.md#LocalPCAP) and a `zeek` container for scanning [uploaded PCAPs](upload.md#Upload)), only the non-live container is responsible for creating and managing the Zeek intel files, which are then shared and used by both types of container instances.

Additional settings governing Malcolm's behavior when pulling from threat intelligence feeds may be specified during Malcolm configuration (see the [**end-to-end Malcolm installation example**](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig)). The global [`ZEEK_INTEL_FEED_SINCE`](malcolm-config.md#MalcolmConfigEnvVars) value can be overridden per-feed by adding a `since:` value to the corresponding configuration YAML file described below.

For a public example of Zeek intelligence files, see Critical Path Security's [repository](https://github.com/CriticalPathSecurity/Zeek-Intelligence-Feeds), which aggregates data from various other threat feeds into Zeek's format.

## <a name="ZeekIntelSTIX"></a>STIX™ and TAXII™

In addition to loading Zeek intelligence files on startup, Malcolm will [automatically generate]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/shared/bin/zeek_intel_from_threat_feed.py) a Zeek intelligence file for all [Structured Threat Information Expression (STIX™)](https://oasis-open.github.io/cti-documentation/stix/intro.html) [v2.0](https://docs.oasis-open.org/cti/stix/v2.0/stix-v2.0-part1-stix-core.html)/[v2.1](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html) JSON files found under `./zeek/intel/STIX`.

Additionally, if a [YAML](https://yaml.org/) file named `taxii.yaml` is found in `./zeek/intel/STIX`, that file will be read and processed as a list of [TAXII™](https://oasis-open.github.io/cti-documentation/taxii/intro.html) [2.0](http://docs.oasis-open.org/cti/taxii/v2.0/cs01/taxii-v2.0-cs01.html)/[2.1](https://docs.oasis-open.org/cti/taxii/v2.1/csprd02/taxii-v2.1-csprd02.html) feeds. This file should minimally include:

```yaml
- type: taxii
  version: 2.1
  url: https://example.com/taxii/api2/
  collection: "*"
```

These other parameters can also optionally be provided:

```yaml
  username: guest
  password: guest
```

Alternatively, if a text file named `.stix_input.txt` is found in `./zeek/intel/STIX`, that file will be read and processed as described above. The feeds are specified one per line, according to the following format (the username and password are optional):

```
taxii|version|discovery_url|collection_name|username|password
```

For example:

```
taxii|2.0|http://example.org/taxii/|IP Blocklist|guest|guest
taxii|2.1|https://example.com/taxii/api2/|URL Blocklist
…
```

Malcolm will attempt to query the TAXII feed(s) for `indicator` STIX objects and convert them to the Zeek intelligence format as described above. There are publicly available TAXII 2.x-compatible services provided by a number of organizations including [Anomali Labs](https://www.anomali.com/resources/limo) and [MITRE](https://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/attck%E2%84%A2-content-available-in-stix%E2%84%A2-20-via); or users may choose from several open-source offerings to roll their own TAXII 2 server (e.g., [oasis-open/cti-taxii-server](https://github.com/oasis-open/cti-taxii-server), [freetaxii/server](https://github.com/freetaxii/server), [StephenOTT/TAXII-Server](https://github.com/StephenOTT/TAXII-Server), etc.).

Note that only **indicators** of [**cyber-observable objects**](https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_mlbmudhl16lr) matched with the **equals (`=`)** [comparison operator](https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_t11hn314cr7w) against a **single value** can be expressed as Zeek intelligence items. More complex STIX indicators will be silently ignored.

Malcolm uses the [stix2](https://pypi.org/project/stix2/) and [taxii2-client](https://pypi.org/project/taxii2-client/) Python libraries to access STIX™/TAXII™ threat intelligence feeds.

## <a name="ZeekIntelMISP"></a>MISP

In addition to loading Zeek intelligence files on startup, Malcolm will [automatically generate]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/shared/bin/zeek_intel_from_threat_feed.py) a Zeek intelligence file for all [Malware Information Sharing Platform (MISP)](https://www.misp-project.org/datamodels/) JSON files found under `./zeek/intel/MISP`.

Additionally, if a [YAML](https://yaml.org/) file named `misp.yaml` is found in `./zeek/intel/MISP`, that file will be read and processed as a list of [MISP feed](https://misp.gitbooks.io/misp-book/content/managing-feeds/#feeds) URLs. This file should minimally include:

```yaml
- type: misp
  url: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

These other parameters can also optionally be provided:

```yaml
  auth_key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Alternatively, if a special file named `.misp_input.txt` is found in `./zeek/intel/MISP`, that file will be read and processed as described above. The feeds are specified one per line, according to the following format (the authentication key is optional):
```
misp|misp_url|auth_key
```

For example:

```
misp|https://example.com/data/feed-osint/manifest.json|df97338db644c64fbfd90f3e03ba8870
misp|https://example.com/doc/misp/|
misp|https://example.com/attributes|a943f5ff506ee6198e996333e0b672b1
misp|https://example.com/events|a943f5ff506ee6198e996333e0b672b1
…
```

Malcolm will attempt to connect to the MISP feed(s) and retrieve [`Attribute`](https://www.misp-standard.org/rfc/misp-standard-core.html#name-attribute) objects of MISP events and convert them to the Zeek intelligence format as described above. There are publicly available [MISP feeds](https://www.misp-project.org/feeds/) and [communities](https://www.misp-project.org/communities/), or users [may run](https://github.com/MISP/misp-docker) their [own MISP instance](https://www.misp-project.org/2019/09/25/hostev-vs-own-misp.html/).

Upon Malcolm connects to the URLs for the MISP feeds in `.misp_input.txt`, it will attempt to determine the format of the data served and process it accordingly. This could be presented as:

* a manifest JSON file
* a directory listing containing a file named `manifest.json`
* a directory listing of JSON files without a `manifest.json` file
* a list of [Events](https://www.misp-project.org/openapi/#tag/Events) returned for a request via the [MISP Automation API](https://www.misp-project.org/openapi/) made to a MISP platform's [`/events` endpoint](https://www.misp-project.org/openapi/#tag/Events/operation/restSearchEvents)
* a list of [Attributes](https://www.misp-project.org/openapi/#tag/Attributes) returned for a request via the [MISP Automation API](https://www.misp-project.org/openapi/) made to a MISP platform's [`/attributes` endpoint](https://www.misp-project.org/openapi/#tag/Attributes/operation/restSearchAttributes)

Note that only a subset of MISP [attribute types](https://www.misp-project.org/datamodels/#attribute-categories-vs-types) can be expressed with the Zeek intelligence [indicator types](https://docs.zeek.org/en/master/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Type). MISP attributes with other types will be silently ignored.

Malcolm uses the [MISP/PyMISP](https://github.com/MISP/PyMISP) Python library to access MISP threat intelligence feeds.

## <a name="ZeekIntelGoogle"></a>Google Threat Intelligence

If a [YAML](https://yaml.org/) file named `google.yaml` is found in `./zeek/intel/Google`, that file will be read and processed as parameters for the [Google Threat Intelligence](https://cloud.google.com/security/products/threat-intelligence) service. This file should minimally include:

```yaml
- type: google
  api_key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

The `collection_type` parameter may be optionally provided, consisting of a comma-separated list of the values supported by the Google Threat Intelligence [collections API](https://gtidocs.virustotal.com/reference/list-threats).

```yaml
  collection_type: report,campaign,threat-actor,malware-family
```

Additionally, the `filters` parameter may be optionally provided, consisting of filters as supported by the Google Threat Intelligence [collections API](https://gtidocs.virustotal.com/reference/list-threats#searches-observations). See these [examples](https://gtidocs.virustotal.com/reference/list-threats#examples) of filtering syntax. Note: filtering by collection type should be done with the `collection_type` parameter described above and not as part of `filters`.

```yaml
  filters: 'motivation:espionage targeted_industry:government targeted_region:US'
```

Filter values that contain spaces should be enclosed in quotation marks:

```yaml
filters: 'targeted_industry:"Energy & Utilities"'
```

While there is no comprehensive list of possible values for [these filters](https://gtidocs.virustotal.com/reference/list-threats#allowed-filters-by-object-collection_type), here are some examples:

<details>
  <summary><code>source_region</code> and <code>targeted_region</code></summary>
  <ul>
    <li>Country codes may specified using the <a href="https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2">ISO code 2</a> standard.</li>
  </ul>
</details>
<details>
  <summary><code>motivation</code></summary>
  <ul>
    <li>Attack / Destruction</li>
    <li>Espionage</li>
    <li>Financial Gain</li>
    <li>Hacktivism</li>
    <li>Influence</li>
    <li>Surveillance</li>
    <li>Unknown</li>
  </ul>
</details>
<details>
  <summary><code>targeted_industry</code></summary>
  <ul>
    <li>Academia - University</li>
    <li>Activists</li>
    <li>Aerospace</li>
    <li>Agriculture</li>
    <li>Automotive</li>
    <li>Bank</li>
    <li>Biomedical</li>
    <li>Casino</li>
    <li>Chemical</li>
    <li>Citizens</li>
    <li>Civil Aviation</li>
    <li>Civil society</li>
    <li>Construction</li>
    <li>Country</li>
    <li>Cryptocurrency</li>
    <li>Defense</li>
    <li>Education</li>
    <li>Electric</li>
    <li>Electronic</li>
    <li>Energy</li>
    <li>Entertainment</li>
    <li>Finance</li>
    <li>Food</li>
    <li>Game</li>
    <li>Government, Administration</li>
    <li>Health</li>
    <li>Higher education</li>
    <li>High tech</li>
    <li>Hospitality</li>
    <li>Industrial</li>
    <li>Infrastructure</li>
    <li>Intelligence</li>
    <li>Investment</li>
    <li>IT</li>
    <li>IT - Security</li>
    <li>Journalist</li>
    <li>Legal</li>
    <li>Logistic</li>
    <li>Manufacturing</li>
    <li>News - Media</li>
    <li>NGO</li>
    <li>Oil and Gas</li>
    <li>Opposition</li>
    <li>Payment</li>
    <li>Pharmacy</li>
    <li>Political party</li>
    <li>Private sector</li>
    <li>Religion</li>
    <li>Research - Innovation</li>
    <li>Retail</li>
    <li>Security Service</li>
    <li>Separatists</li>
    <li>Technology</li>
    <li>Telecoms</li>
    <li>Think Tanks</li>
    <li>Transport</li>
    <li>Travel</li>
    <li>Water</li>
  </ul>
</details>
<details>
<summary><code>capability</code></summary>
  <ul>
    <li>Access logical volumes</li>
    <li>Access raw disk</li>
    <li>Access virtual disk</li>
    <li>Active Directory Trust Enumeration</li>
    <li>Acts as a watchdog to maintain the in-memory persistence of another process or processes</li>
    <li>Adds to local root certificate</li>
    <li>Adds user account</li>
    <li>Allocates memory</li>
    <li>Allocates process memory</li>
    <li>Alter thread</li>
    <li>Anti-AV: AhnLab</li>
    <li>Anti-AV: Avast</li>
    <li>Anti-AV: AVG</li>
    <li>Anti-AV: BitDefender</li>
    <li>Anti-AV capabilities</li>
    <li>Anti-AV: eScan</li>
    <li>Anti-AV: Kaspersky</li>
    <li>Anti-AV: McAfee</li>
    <li>Anti-AV: NOD32</li>
    <li>Anti-AV: Norton</li>
    <li>Anti-AV: Qihoo</li>
    <li>Anti-AV: Sophos</li>
    <li>Anti-AV: Symantec</li>
    <li>Anti-AV: Trend Micro</li>
    <li>Anti-AV: Windows Defender</li>
    <li>Anti-AV: Windows Firewall</li>
    <li>Anti-debug capabilities</li>
    <li>Anti-debug: IDA</li>
    <li>Anti-debug: Ollydbg</li>
    <li>Anti-debug: Windbg</li>
    <li>Anti-forensic capabilities</li>
    <li>Anti-VM capabilities</li>
    <li>Anti-VM: Hyper-V</li>
    <li>Anti-VM: Parallels</li>
    <li>Anti-VM: QEMU</li>
    <li>Anti-VM: Sandboxie</li>
    <li>Anti-VM: Time-based methods</li>
    <li>Anti-VM: User activity</li>
    <li>Anti-VM: VirtualBox</li>
    <li>Anti-VM: VirtualPC</li>
    <li>Anti-VM: VMware</li>
    <li>Anti-VM: VMware I/O port</li>
    <li>Anti-VM: WINE</li>
    <li>Anti-VM: Xen</li>
    <li>Attaches user process memory</li>
    <li>Automated data capture</li>
    <li>Binary control capabilities</li>
    <li>Boots the system in safe mode</li>
    <li>Brute-force IEC-104 IOA</li>
    <li>Bypass Mark-of-the-Web (MOTW)</li>
    <li>Bypass security controls Capabilities</li>
    <li>Bypass Windows UAC</li>
    <li>Calculates Adler-32 hashes</li>
    <li>Calculates bcrypt hashes</li>
    <li>Calculates djb2 hashes</li>
    <li>Calculates FNV-1a hashes</li>
    <li>Calculates FNV hashes</li>
    <li>Calculates hashes</li>
    <li>Calculates hashes using CRC32</li>
    <li>Calculates hashes using CRC32B</li>
    <li>Calculates Luhn checksums</li>
    <li>Calculates MD4 hashes</li>
    <li>Calculates MD5 hashes</li>
    <li>Calculates MurmurHash2 hashes</li>
    <li>Calculates MurmurHash3 hashes</li>
    <li>Calculates RSHash hashes</li>
    <li>Calculates SHA-1 hashes</li>
    <li>Calculates SHA-224 hashes</li>
    <li>Calculates SHA-256 hashes</li>
    <li>Calculates SHA-512 hashes</li>
    <li>Calculates Tiger hashes</li>
    <li>Can mine data via WMI</li>
    <li>Capable of bruteforcing</li>
    <li>Capable of Collecting ICS Program</li>
    <li>Capable of collecting locally stored email</li>
    <li>Capable of creating local user accounts</li>
    <li>Capable of DDOSing hosts</li>
    <li>Capable of manipulating the clipboard</li>
    <li>Capable of modifying file permissions on Linux</li>
    <li>Capable of modifying file permissions on Windows</li>
    <li>Capable of privilege escalation via access token impersonation</li>
    <li>Capture Active Directory data</li>
    <li>Capture ATM dispenser service provider information</li>
    <li>Capture audio</li>
    <li>Capture battery information</li>
    <li>Capture BIOS information</li>
    <li>Capture browser bookmarks</li>
    <li>Capture browser cookies</li>
    <li>Capture browser history</li>
    <li>Capture certificate-based credentials</li>
    <li>Capture clipboard contents</li>
    <li>Capture cookies</li>
    <li>Capture CPU information</li>
    <li>Capture credentials</li>
    <li>Capture credentials stored by Chrome</li>
    <li>Capture credentials stored by FileZilla</li>
    <li>Capture credentials stored by Firefox</li>
    <li>Capture credentials stored by Internet Explorer</li>
    <li>Capture credentials stored by Microsoft Credential Manager</li>
    <li>Capture credentials stored by Microsoft Edge browser</li>
    <li>Capture credentials stored by Microsoft Outlook</li>
    <li>Capture credentials stored by Mozilla Thunderbird</li>
    <li>Capture credentials stored by Opera</li>
    <li>Capture credentials stored by OSX Keychain</li>
    <li>Capture credentials stored by password manager solutions</li>
    <li>Capture credentials stored by Pidgin</li>
    <li>Capture credentials stored by Windows registry</li>
    <li>Capture credentials stored by WINSCP</li>
    <li>Capture credentials via DCSync</li>
    <li>Capture cryptocurrency wallet files</li>
    <li>Capture disk information</li>
    <li>Capture domain information</li>
    <li>Capture email credentials</li>
    <li>Capture email messages or contents</li>
    <li>Capture file and directory listings</li>
    <li>Capture files and their contents</li>
    <li>Capture files that contain credentials</li>
    <li>Capture firmware information</li>
    <li>Capture FTP credentials</li>
    <li>Capture Group Policy Object data</li>
    <li>Capture host files</li>
    <li>Capture hostname</li>
    <li>Capture HTTP-based credentials</li>
    <li>Capture Internet cache</li>
    <li>Capture keyboard layout</li>
    <li>Capture keystrokes</li>
    <li>Capture LSASS memory</li>
    <li>Capture MAC address</li>
    <li>Capture memory</li>
    <li>Capture memory status</li>
    <li>Capture microphone audio</li>
    <li>Capture network configuration</li>
    <li>Capture network connection state</li>
    <li>Capture network interfaces</li>
    <li>Capture network packet capture (PCAP) data</li>
    <li>Capture Network Share information</li>
    <li>Capture network traffic</li>
    <li>Capture OPC Information</li>
    <li>Capture operating system information</li>
    <li>Capture Password File</li>
    <li>Capture payment card data</li>
    <li>Capture POP3 credentials</li>
    <li>Capture private certificates</li>
    <li>Capture proxy information</li>
    <li>Capture session information</li>
    <li>Capture Skype credentials</li>
    <li>Capture smart card data</li>
    <li>Capture SQL data</li>
    <li>Capture stored contacts</li>
    <li>Capture stored email contacts</li>
    <li>Capture system information</li>
    <li>Capture system language</li>
    <li>Capture system locale information</li>
    <li>Capture system network information</li>
    <li>Capture TCP network connection state</li>
    <li>Capture token information</li>
    <li>Capture Two Factor Autentication (2FA) codes</li>
    <li>Capture UDP network connection state</li>
    <li>Capture video</li>
    <li>Capture video with camera</li>
    <li>Capture web-based data</li>
    <li>Capture WiFi credentials</li>
    <li>Capture Windows registry data</li>
    <li>Change directories</li>
    <li>Check directory existence</li>
    <li>Checks HTTP response status code</li>
    <li>Closes windows</li>
    <li>Collect image files</li>
    <li>Collects physical location</li>
    <li>Collect video files</li>
    <li>Command and Control via the MQTT Pub/Sub Protocol Capability</li>
    <li>Command line capabilities</li>
    <li>Communiates using SSH</li>
    <li>Communicates bidirectionally with a web service</li>
    <li>Communicates using a binary protocol</li>
    <li>Communicates using a dead drop resolver</li>
    <li>Communicates using a fallback channel</li>
    <li>Communicates using a proxy</li>
    <li>Communicates using a remote graphical interface</li>
    <li>Communicates using a reverse shell</li>
    <li>Communicates using CODESYS</li>
    <li>Communicates using DNS</li>
    <li>Communicates using DNS A records</li>
    <li>Communicates using DNS null records</li>
    <li>Communicates using DNS TXT records</li>
    <li>Communicates using domain fronting</li>
    <li>Communicates using domain masquerading</li>
    <li>Communicates using Exchange Web Services (EWS)</li>
    <li>Communicates using FTP</li>
    <li>Communicates using GTP.</li>
    <li>Communicates using HTTP</li>
    <li>Communicates using HTTP/2</li>
    <li>Communicates using HTTPS</li>
    <li>Communicates using ICMP</li>
    <li>Communicates using IEC 60870-5-104</li>
    <li>Communicates using IMAP</li>
    <li>Communicates using IRC</li>
    <li>Communicates using KCP</li>
    <li>Communicates using MIME</li>
    <li>Communicates using MODBUS</li>
    <li>Communicates using MQTT</li>
    <li>Communicates using multi-stage channels</li>
    <li>Communicates using OPC</li>
    <li>Communicates using OSCAR</li>
    <li>Communicates using pipes</li>
    <li>Communicates using POP3</li>
    <li>Communicates using raw sockets</li>
    <li>Communicates using RDP</li>
    <li>Communicates using RPC</li>
    <li>Communicates using SCTP</li>
    <li>Communicates using SFTP</li>
    <li>Communicates using SMB</li>
    <li>Communicates using SMB Bruteforce</li>
    <li>Communicates using SMTP</li>
    <li>Communicates using SSL</li>
    <li>Communicates using TCP</li>
    <li>Communicates using the Remote Frame Buffer Protocol (as used by VNC)</li>
    <li>Communicates using the Tox protocol</li>
    <li>Communicates using TLS</li>
    <li>Communicates using Tor</li>
    <li>Communicates using UDP</li>
    <li>Communicates using UDT</li>
    <li>Communicates using UPnP</li>
    <li>Communicates using USB</li>
    <li>Communicates via the Socket.IO WebSocket Library for NodeJS</li>
    <li>Communicates via the Websocket protocol</li>
    <li>Communicate using DNS over UDP</li>
    <li>Communicate via VMCI socket</li>
    <li>Communications capabilities</li>
    <li>Compiles a .NET assembly from source code</li>
    <li>Compresses using gzip</li>
    <li>Compresses using ZIP</li>
    <li>Compression capabilities</li>
    <li>Configuration capabilities</li>
    <li>Configuration update</li>
    <li>Connects to a named pipe</li>
    <li>Connect to a socket</li>
    <li>Connect to TCP socket</li>
    <li>Constructs mutex</li>
    <li>Copy files</li>
    <li>Create a named pipe</li>
    <li>Create a service</li>
    <li>Create a socket</li>
    <li>Create directories</li>
    <li>Create files</li>
    <li>Create or drop a polymorhpic file</li>
    <li>Creates HTTP Server</li>
    <li>Creates processes</li>
    <li>Creates processes in suspended state</li>
    <li>Creates shorcut</li>
    <li>Creates user accounts</li>
    <li>Creates Windows regisry keys or values</li>
    <li>Create TCP socket</li>
    <li>Create thread</li>
    <li>Create UDP socket</li>
    <li>Create Windows registry key</li>
    <li>Create Windows registry key value</li>
    <li>Credential theft by Prompt</li>
    <li>Cryptocurrency mining capabilities</li>
    <li>Data theft capabilities</li>
    <li>Data theft (exfiltration) capabilities</li>
    <li>Decodes Base64</li>
    <li>Decodes custom Base64 alphabet</li>
    <li>Decodes hex data</li>
    <li>Decodes URL (Percent)</li>
    <li>Decodes using JSON</li>
    <li>Decoding capabilities</li>
    <li>Decompression Capabilities</li>
    <li>Decrypt Internet Explorer credentials</li>
    <li>Decryption capabilities</li>
    <li>Decrypts using 3DES</li>
    <li>Decrypts using AES</li>
    <li>Decrypts using RC4</li>
    <li>Decrypts using RSA</li>
    <li>Decrypts using XOR</li>
    <li>Delete a service</li>
    <li>Delete directories</li>
    <li>Delete email</li>
    <li>Delete files</li>
    <li>Deletes clipboard content</li>
    <li>Deletes user account</li>
    <li>Deletes Volume Shadow Copy files</li>
    <li>Deletes Windows registry keys</li>
    <li>Deletes Windows registry keys or values</li>
    <li>Deletes Windows registry values</li>
    <li>Deltes Widnows Backup Catalog</li>
    <li>Denial of Service</li>
    <li>Determines public IP address of host</li>
    <li>Directory manipulation</li>
    <li>Download files</li>
    <li>Downloads configuration data</li>
    <li>Driver Capabilities</li>
    <li>Dumps process memory</li>
    <li>Email capabilities</li>
    <li>Emnumerates Local Account</li>
    <li>Encodes communications using Base64</li>
    <li>Encodes communications using BasE91</li>
    <li>Encodes communications using custom Base64 alphabet</li>
    <li>Encodes communications using Hex</li>
    <li>Encodes using Base32</li>
    <li>Encodes using Base64</li>
    <li>Encodes using custom Base64 alphabet</li>
    <li>Encodes using Hex</li>
    <li>Encodes using JSON</li>
    <li>Encoding capabilities</li>
    <li>Encoding capabilities for network communications</li>
    <li>Encryption capabilities</li>
    <li>Encryption capabilities for network communications</li>
    <li>Encrypt or decrypt files</li>
    <li>Encrypts data with 3DES</li>
    <li>Encrypts data with a custom RC4 algorithm</li>
    <li>Encrypts data with AES</li>
    <li>Encrypts data with AES-128</li>
    <li>Encrypts data with AES-256</li>
    <li>Encrypts data with Blowfish</li>
    <li>Encrypts data with Camellia</li>
    <li>Encrypts data with CAST-128</li>
    <li>Encrypts data with ChaCha</li>
    <li>Encrypts data with Curve25519</li>
    <li>Encrypts data with DES</li>
    <li>Encrypts data with ElGamal</li>
    <li>Encrypts data with HC-128</li>
    <li>Encrypts data with Microsoft DPAPI</li>
    <li>Encrypts data with RC2</li>
    <li>Encrypts data with RC4</li>
    <li>Encrypts data with RC5</li>
    <li>Encrypts data with RC6</li>
    <li>Encrypts data with Rijndael</li>
    <li>Encrypts data with RSA</li>
    <li>Encrypts data with Salsa20</li>
    <li>Encrypts data with SEAL</li>
    <li>Encrypts data with Sosemanuk</li>
    <li>Encrypts data with TEA</li>
    <li>Encrypts data with Twofish</li>
    <li>Encrypts data with XChaCha20</li>
    <li>Encrypts data with XOR</li>
    <li>Encrypts data with XTEA</li>
    <li>Encrypts network communications with 3DES</li>
    <li>Encrypts network communications with AES</li>
    <li>Encrypts network communications with AES-256</li>
    <li>Encrypts network communications with DES</li>
    <li>Encrypts network communications with RC4</li>
    <li>Encrypts network communications with RSA</li>
    <li>Encrypts network communications with XOR</li>
    <li>Enumerate current user</li>
    <li>Enumerates applications</li>
    <li>Enumerates Domain Accounts</li>
    <li>Enumerates Email Accounts</li>
    <li>Enumerates groups</li>
    <li>Enumerates hardware</li>
    <li>Enumerates local groups</li>
    <li>Enumerates security applications</li>
    <li>Enumerates windows</li>
    <li>Enumerate users</li>
    <li>Event Log Access</li>
    <li>Event Log Capabilities</li>
    <li>Execute files</li>
    <li>Executes by Windows API</li>
    <li>Executes commands from the command line</li>
    <li>Executes using a scheduled task</li>
    <li>Executes using msxsl</li>
    <li>Executes via DLL loading</li>
    <li>Executes via mshta</li>
    <li>Executes via .NET assembly loading</li>
    <li>Execution capabilities</li>
    <li>Exfiltrates data in an automated way</li>
    <li>Exfiltrates data over alternate protocol</li>
    <li>Exfiltrates data over C2 channel</li>
    <li>Exfiltrates data over USB</li>
    <li>Exfiltrates data over web service</li>
    <li>Exfiltrates data to cloud storage</li>
    <li>Extracts HTTP body</li>
    <li>File manipulation</li>
    <li>Filters netowrk traffic</li>
    <li>Find files</li>
    <li>Find process by name</li>
    <li>Find process with process identifier (PID)</li>
    <li>Finds a process</li>
    <li>Finds file resources</li>
    <li>Finds location of a window</li>
    <li>Finds location of Windows taskbar</li>
    <li>Fixed or removable drive manipulation</li>
    <li>Gets common file path</li>
    <li>Gets environmental variable value</li>
    <li>Gets file attribute</li>
    <li>Gets mutex handle</li>
    <li>Gets window text</li>
    <li>GPP Credential Theft</li>
    <li>Hidden File System</li>
    <li>Hides a file</li>
    <li>Hides processes</li>
    <li>Hides thread</li>
    <li>Hides windows</li>
    <li>Hides Windows taskbar</li>
    <li>HTTP body capabilities</li>
    <li>HTTP header capabilities</li>
    <li>HTTP request capabilities</li>
    <li>HTTP response capabilities</li>
    <li>Impersonates user accounts</li>
    <li>Injects content into web pages</li>
    <li>Injects into RDP processes</li>
    <li>Installs Driver</li>
    <li>Internet Explorer manipulation</li>
    <li>Keylog via application hook</li>
    <li>Keylog via polling</li>
    <li>Kill thread</li>
    <li>Lateral Movement capabilities</li>
    <li>Lateral movement via admin network shares</li>
    <li>Lateral movement via SMB</li>
    <li>Launch Internet Explorer</li>
    <li>List directories</li>
    <li>Listens on a port and acts as a proxy</li>
    <li>Listens on a port and transmits commands</li>
    <li>Listens on a port or socket</li>
    <li>Listens on a port to receive commands</li>
    <li>List Explorer process information</li>
    <li>List files</li>
    <li>List file sizes</li>
    <li>List file versions</li>
    <li>List process modules</li>
    <li>List process threads</li>
    <li>List RDP process information</li>
    <li>List registry entries</li>
    <li>Lists drives</li>
    <li>List services</li>
    <li>Lists processes</li>
    <li>Lists processes for security applications</li>
    <li>Load code or plugins</li>
    <li>Loads data from a PE resource</li>
    <li>Loads or downloads C#</li>
    <li>Loads or downloads data</li>
    <li>Loads or downloads Java</li>
    <li>Loads or downloads JavaScript</li>
    <li>Loads or downloads Lua source code or bytecode</li>
    <li>Loads or downloads MSIL or CIL</li>
    <li>Loads or downloads plugins</li>
    <li>Loads or downloads PowerShell</li>
    <li>Loads or downloads Python code</li>
    <li>Loads or downloads shellcode</li>
    <li>Loads or downloads Visual Basic Scripts</li>
    <li>Locks a workstation</li>
    <li>Locks files</li>
    <li>Locks mutex</li>
    <li>Log manipulation</li>
    <li>Logs off user account</li>
    <li>Manipulates file attribute</li>
    <li>Manipulates GUI windows</li>
    <li>Manipulates process memory</li>
    <li>Maximizes windows</li>
    <li>Mines phone calls</li>
    <li>Mines SMS messages</li>
    <li>Minimizes windows</li>
    <li>Modifies file and injects code</li>
    <li>Modifies file permissions</li>
    <li>Modifies running processes</li>
    <li>Modify a service</li>
    <li>Modify files</li>
    <li>Modify process privileges</li>
    <li>Move files</li>
    <li>Moves laterally via exploit</li>
    <li>Mutex capabilities</li>
    <li>Network-based DoS capabilities</li>
    <li>Obfuscation capabilities</li>
    <li>Obtains configuration data at runtime</li>
    <li>Obtains configuration data at runtime from a downloaded file</li>
    <li>Obtains configuration data at runtime from a separate file</li>
    <li>Obtains configuration data at runtime from the command line</li>
    <li>Obtains configuration data at runtime from the registry</li>
    <li>Obtains or sets configuration data during install</li>
    <li>Opens CD-ROM drive</li>
    <li>Opens files</li>
    <li>Opens the clipboard</li>
    <li>Open Windows registry key</li>
    <li>Overwrite or wipe file data by emptying Recycle Bin</li>
    <li>Overwrite or wipe file data by emptying Recycle Bin quietly</li>
    <li>Overwrite or wipe Internet cache</li>
    <li>Overwriting capabilities</li>
    <li>Password Cracks</li>
    <li>Password Sprays</li>
    <li>Performs anti-disassembly obfucscation</li>
    <li>Performs CD-ROM operations</li>
    <li>Performs GUI operations</li>
    <li>Performs keyboard operations</li>
    <li>Performs mouse operations</li>
    <li>Performs network traffic operations</li>
    <li>Performs operations using the Windows taskbar</li>
    <li>Performs process injection</li>
    <li>Performs reflective process injection</li>
    <li>Persistence capabilities</li>
    <li>Persistence via launchd process</li>
    <li>Persistence via load order</li>
    <li>Persistence via Microsoft IIS</li>
    <li>Persistence via Network Logon Script</li>
    <li>Persistence via screensaver</li>
    <li>Persistence via shortcut</li>
    <li>Persistence via Systemd services</li>
    <li>Persistence via SysV init scripts</li>
    <li>Persistence via Windows registry Run key</li>
    <li>Persistence via Winlogon</li>
    <li>Persistence via WMI</li>
    <li>Persists as a Windows service</li>
    <li>Persists via Active Setup registry key</li>
    <li>Persists via a scheduled task</li>
    <li>Persists via bash profile</li>
    <li>Persists via bashrc</li>
    <li>Persists via boot sector</li>
    <li>Persists via cron</li>
    <li>Persists via DLL side-loading</li>
    <li>Persists via Microsoft COM</li>
    <li>Persists via the Windows registry</li>
    <li>Persists via the Windows Startup folder</li>
    <li>Persists via Windows BITS jobs</li>
    <li>Persists within browser extension</li>
    <li>Persist via Microsoft IIS Plug-in (ISAPI Filter)</li>
    <li>Persist via OSX plist Launch Agent</li>
    <li>Point-of-Sale targeting or manipulation</li>
    <li>Powers off a monitor</li>
    <li>Privilege escalation capabilities</li>
    <li>Privilege escalation via access token</li>
    <li>Privilege escalation via access token duplication</li>
    <li>Privilege escalation via DLL search order hijacking</li>
    <li>Process Doppelganging</li>
    <li>Process Hollowing</li>
    <li>Process Hooking</li>
    <li>Process injection of DLLs</li>
    <li>Process injection of PEs</li>
    <li>Process injection through APC</li>
    <li>Process injection through Proc memory</li>
    <li>Process injection through ptrace system calls</li>
    <li>Process injection via threads</li>
    <li>Process manipulation</li>
    <li>Process Parent PID Spoofing</li>
    <li>Psuedo random number generation capabilities</li>
    <li>Query service information</li>
    <li>Query service status</li>
    <li>Query Windows registry</li>
    <li>Query Windows registry key</li>
    <li>Query Windows registry key values</li>
    <li>Read a file through a named pipe</li>
    <li>Read files</li>
    <li>Reads configuration data from the registry</li>
    <li>Reads configuration from an external file</li>
    <li>Reads HTTP header</li>
    <li>Reads log files</li>
    <li>Reads memory</li>
    <li>Reads process memory</li>
    <li>Reads the clipboard</li>
    <li>Receive data</li>
    <li>Registers Driver</li>
    <li>Rename files</li>
    <li>Replace process</li>
    <li>Replaces the clipboard contents</li>
    <li>Report current configuration</li>
    <li>Resets user account password</li>
    <li>Resizes Volume Shadow Copy files</li>
    <li>Resolves Windows program files directory</li>
    <li>Resource manipulation</li>
    <li>Restarts the system</li>
    <li>Resume thread</li>
    <li>Run as service</li>
    <li>Scan for Microsoft SQL Server</li>
    <li>Scanning capabilities</li>
    <li>Scans Admin Shares</li>
    <li>Scans ARP</li>
    <li>Scans for Elasticsearch servers</li>
    <li>Scans for OPC servers</li>
    <li>Scans for SSDP devices</li>
    <li>Scans SMB</li>
    <li>Screen capture</li>
    <li>Search capabilities</li>
    <li>Search via regular expression</li>
    <li>Self-delete</li>
    <li>Self-uninstall</li>
    <li>Self-update</li>
    <li>Send data</li>
    <li>Send email</li>
    <li>Service manipulation</li>
    <li>Sets environmental variable</li>
    <li>Sets file attribute</li>
    <li>Sets HTTP header</li>
    <li>Set socket configuration</li>
    <li>Sets Wallpaper</li>
    <li>Shuts down the system</li>
    <li>Simulates ctrl+alt+del</li>
    <li>Sleep</li>
    <li>Sleep Time Execution</li>
    <li>Specialized C2 capabilities</li>
    <li>Spoof process</li>
    <li>Spreads via removeable media</li>
    <li>Start a service</li>
    <li>Starts Driver</li>
    <li>Stop a service</li>
    <li>Stored Data Manipulation</li>
    <li>Suspend thread</li>
    <li>Swaps buttons on the mouse</li>
    <li>Tampers with Linux firewall</li>
    <li>Tampers with Linux Firewall IP Tables</li>
    <li>Tampers with Windows eventlog</li>
    <li>Tampers with Windows firewall</li>
    <li>Tampers with Windows processes</li>
    <li>Tampers with Windows process mitigation policy</li>
    <li>Tampers with Windows recovery features</li>
    <li>Tampers with Windows safe mode</li>
    <li>TCP Scan</li>
    <li>Terminates processes</li>
    <li>Timestomping capabilities</li>
    <li>Tries to lock mutex</li>
    <li>Tunnels network traffic</li>
    <li>Unlocks mutex</li>
    <li>Updates beacon interval</li>
    <li>Upload directory contents</li>
    <li>Upload files</li>
    <li>User account manipulation</li>
    <li>User account password capabilities</li>
    <li>User prompt manipulation</li>
    <li>Uses Amazon as part of C2</li>
    <li>Uses Amazon AWS S3 as part of C2</li>
    <li>Uses AOL Instant Messenger as part of C2</li>
    <li>Uses apLib compression</li>
    <li>Uses apLib decompression</li>
    <li>Uses Baidu as part of C2</li>
    <li>Uses Daum as part of C2</li>
    <li>Uses Discord as part of C2</li>
    <li>Uses DropBox as part of C2</li>
    <li>Uses environmental variables</li>
    <li>Uses Facebook as part of C2</li>
    <li>Uses Fotolog as part of C2</li>
    <li>Uses Geocities for C2</li>
    <li>Uses GitHub as part of C2</li>
    <li>Uses Google as part of C2</li>
    <li>Uses Google Code as part of C2</li>
    <li>Uses Google Docs as part of C2</li>
    <li>Uses Google Drive as part of C2</li>
    <li>Uses Google Mail as part of C2</li>
    <li>Uses Google Plus as part of C2</li>
    <li>Uses gzip decompression</li>
    <li>Uses hard-coded configuration data</li>
    <li>Uses IBM community as part of C2</li>
    <li>Uses Imgur as part of C2</li>
    <li>Uses Linear Congruential Generator (LCG) algorithm in Delphi</li>
    <li>Uses LinkedIn as part of C2</li>
    <li>Uses LZ compression</li>
    <li>Uses LZNT1 compression</li>
    <li>Uses LZNT1 decompression</li>
    <li>Uses LZO compression</li>
    <li>Uses Mersenne Twister PRNG algorithm</li>
    <li>Uses Microsoft as part of C2</li>
    <li>Uses Microsoft Graph API as Command and Control (C&C)</li>
    <li>Uses Microsoft MSDN as part of C2</li>
    <li>Uses Microsoft OneDrive as part of C2</li>
    <li>Uses Microsoft TechNet as part of C2</li>
    <li>Uses Naver email service for C2</li>
    <li>Uses Netvigator Email as part of C2</li>
    <li>Uses Ngrok as part of C&C</li>
    <li>Uses PAQ compression</li>
    <li>Uses Pastebin as part of C2</li>
    <li>Uses pCloud as part of C2</li>
    <li>Uses QuickLZ decompression</li>
    <li>Uses RedHat OpenShift as part of C2</li>
    <li>Uses Slack as a part of C2</li>
    <li>Uses Stack Overflow as part of C2</li>
    <li>Uses Statcounter for C2</li>
    <li>Uses Steam gaming platform as part of C2</li>
    <li>Uses steganography</li>
    <li>Uses Telegram as part of C2</li>
    <li>Uses transactional NTFS</li>
    <li>Uses Tumblr as part of C2</li>
    <li>Uses Twitter as part of C2</li>
    <li>Uses VMware web services for C2</li>
    <li>Uses WMIC to execute a command</li>
    <li>Uses WMI to execute a command</li>
    <li>Uses wscript to execute a command</li>
    <li>Uses Yahoo as part of C2</li>
    <li>Uses Yahoo Babelfish as part of C2</li>
    <li>Uses Yahoo Groups as part of C2</li>
    <li>Uses Yandex as part of C2</li>
    <li>Uses zlib compression</li>
    <li>Uses zlib decompression</li>
    <li>Volume Shadow Copy Capabilities</li>
    <li>Windows registry capabilities</li>
    <li>Wipes or overwrites disks</li>
    <li>Wipes or overwrites files</li>
    <li>Wipes or overwrites itself</li>
    <li>Wipes or overwrites logs</li>
    <li>Wipes or overwrites the Master Boot Record (MBR)</li>
    <li>Wipes or overwrites the Volume Boot Record (VBR)</li>
    <li>Wiping ICS Specific Files</li>
    <li>Write a file through a named pipe</li>
    <li>Writes memory</li>
    <li>Writes to log files</li>
    <li>Writes to the clipboard</li>
    <li>Writes Windows registry keys</li>
    <li>Writes Windows registry keys or values</li>
    <li>Writes Windows registry values</li>
  </ul>
</details>
<details>
  <summary><code>operating_system</code></summary>
  <ul>
  <li>Android</li>
  <li>BSD</li>
  <li>FreeBSD</li>
  <li>ios</li>
  <li>Linux</li>
  <li>Mac</li>
  <li>Unix</li>
  <li>VMkernel</li>
  <li>Windows</li>
  </ul>
</details>
<details>
  <summary><code>malware_role</code></summary>
  <ul>
    <li>Archiver</li>
    <li>ATM Malware</li>
    <li>Backdoor</li>
    <li>Backdoor - Botnet</li>
    <li>Backdoor - Webshell</li>
    <li>Bootkit</li>
    <li>Builder</li>
    <li>Controller</li>
    <li>Credential Stealer</li>
    <li>Cryptocurrency Miner</li>
    <li>Data Miner</li>
    <li>Disruption Tool</li>
    <li>Downloader</li>
    <li>Dropper</li>
    <li>Dropper - Memory Only</li>
    <li>File Infector</li>
    <li>Framework</li>
    <li>Installer</li>
    <li>Keylogger</li>
    <li>Lateral Movement Tool</li>
    <li>Launcher</li>
    <li>Lightweight Backdoor</li>
    <li>Point-of-Sale Malware</li>
    <li>Privilege Escalation Tool</li>
    <li>Ransomware</li>
    <li>Reconnaissance Tool</li>
    <li>Remote Control and Administration Tool</li>
    <li>Remote Exploitation Tool</li>
    <li>Rootkit</li>
    <li>Screen Capture Tool</li>
    <li>Sniffer</li>
    <li>Spambot</li>
    <li>Tunneler</li>
    <li>Uploader</li>
    <li>Utility</li>
  </ul>
</details>

Malcolm uses the [VirusTotal/vt-py](https://github.com/VirusTotal/vt-py) Python library to access Google Threat Intelligence feeds.

## <a name="ZeekIntelMandiant"></a>Mandiant

If a [YAML](https://yaml.org/) file named `mandiant.yaml` is found in `./zeek/intel/Mandiant`, that file will be read and processed as parameters for the [Mandiant Threat Intelligence](https://www.mandiant.com/threats) service. This file should minimally include:

```yaml
- type: mandiant
  api_key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  secret_key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

These other parameters can also optionally be provided:

```yaml
  bearer_token: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  api_base_url: https://api.intelligence.mandiant.com
  minimum_mscore: 60
  exclude_osint: False
  include_campaigns: False
  include_category: True
  include_misp: True
  include_reports: False
  include_threat_rating: False
```

Malcolm uses the [google/mandiant-ti-client](https://github.com/google/mandiant-ti-client) Python library to access Mandiant threat intelligence feeds.

## <a name="IntelFeedDisclaimer"></a>Disclaimer

Neither Malcolm's development team nor its funding sources endorse any commercial product or service, nor do they attest to the suitability or effectiveness of these products and services for any particular use case. Any reference to specific commercial products, processes, or services by trademark, manufacturer, or otherwise should not be interpreted as an endorsement, recommendation, or preference.