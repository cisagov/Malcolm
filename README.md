# Malcolm

![](./docs/images/logo/Malcolm_outline_banner_dark.png)

[Malcolm]({{ site.github.repository_url }}) is a powerful network traffic analysis tool suite designed with the following goals in mind:

* **Easy to use** – Malcolm accepts network traffic data in the form of full packet capture (PCAP) files and Zeek (formerly Bro) logs. These artifacts can be uploaded via a simple browser-based interface or captured live and forwarded to Malcolm using lightweight forwarders. In either case, the data is automatically normalized, enriched, and correlated for analysis.
* **Powerful traffic analysis** – Visibility into network communications is provided through two intuitive interfaces: OpenSearch Dashboards, a flexible data visualization plugin with dozens of prebuilt dashboards providing an at-a-glance overview of network protocols; and Arkime (formerly Moloch), a powerful tool for finding and identifying the network sessions comprising suspected security incidents.
* **Streamlined deployment** – Malcolm operates as a cluster of Docker containers, isolated sandboxes which each serve a dedicated function of the system. This Docker-based deployment model, combined with a few simple scripts for setup and run-time management, makes Malcolm suitable to be deployed quickly across a variety of platforms and use cases, whether it be for long-term deployment on a Linux server in a security operations center (SOC) or for incident response on a Macbook for an individual engagement.
* **Secure communications** – All communications with Malcolm, both from the user interface and from remote log forwarders, are secured with industry standard encryption protocols.
* **Permissive license** – Malcolm is comprised of several widely used open source tools, making it an attractive alternative to security solutions requiring paid licenses.
* **Expanding control systems visibility** – While Malcolm is great for general-purpose network traffic analysis, its creators see a particular need in the community for tools providing insight into protocols used in industrial control systems (ICS) environments. Ongoing Malcolm development will aim to provide additional parsers for common ICS protocols.

Although all of the open source tools which make up Malcolm are already available and in general use, Malcolm provides a framework of interconnectivity which makes it greater than the sum of its parts. And while there are many other network traffic analysis solutions out there, ranging from complete Linux distributions like Security Onion to licensed products like Splunk Enterprise Security, the creators of Malcolm feel its easy deployment and robust combination of tools fill a void in the network security space that will make network traffic analysis accessible to many in both the public and private sectors as well as individual enthusiasts.

In short, Malcolm provides an easily deployable network analysis tool suite for full packet capture artifacts (PCAP files) and Zeek logs. While Internet access is required to build it, it is not required at runtime.

## Documentation

See the [**Malcolm documentation**](docs/README.md).

## Share your feedback

You can help steer Malcolm's development by sharing your ideas and feedback. Please take a few minutes to complete [this survey ↪](https://forms.gle/JYt9QwA5C4SYX8My6) (hosted on Google Forms) so we can understand the members of the Malcolm community and their use cases for this tool.

## <a name="BuildBadges"></a>Automated Builds Status

See [**Building from source**](docs/development.md#Build) to read how you can use GitHub [workflow files]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/.github/workflows/) to build Malcolm.

![api-build-and-push-ghcr]({{ site.github.repository_url }}/workflows/api-build-and-push-ghcr/badge.svg)
![arkime-build-and-push-ghcr]({{ site.github.repository_url }}/workflows/arkime-build-and-push-ghcr/badge.svg)
![dashboards-build-and-push-ghcr]({{ site.github.repository_url }}/workflows/dashboards-build-and-push-ghcr/badge.svg)
![dashboards-helper-build-and-push-ghcr]({{ site.github.repository_url }}/workflows/dashboards-helper-build-and-push-ghcr/badge.svg)
![file-monitor-build-and-push-ghcr]({{ site.github.repository_url }}/workflows/file-monitor-build-and-push-ghcr/badge.svg)
![file-upload-build-and-push-ghcr]({{ site.github.repository_url }}/workflows/file-upload-build-and-push-ghcr/badge.svg)
![filebeat-build-and-push-ghcr]({{ site.github.repository_url }}/workflows/filebeat-build-and-push-ghcr/badge.svg)
![freq-build-and-push-ghcr]({{ site.github.repository_url }}/workflows/freq-build-and-push-ghcr/badge.svg)
![htadmin-build-and-push-ghcr]({{ site.github.repository_url }}/workflows/htadmin-build-and-push-ghcr/badge.svg)
![logstash-build-and-push-ghcr]({{ site.github.repository_url }}/workflows/logstash-build-and-push-ghcr/badge.svg)
![name-map-ui-build-and-push-ghcr]({{ site.github.repository_url }}/workflows/name-map-ui-build-and-push-ghcr/badge.svg)
![nginx-build-and-push-ghcr]({{ site.github.repository_url }}/workflows/nginx-build-and-push-ghcr/badge.svg)
![opensearch-build-and-push-ghcr]({{ site.github.repository_url }}/workflows/opensearch-build-and-push-ghcr/badge.svg)
![pcap-capture-build-and-push-ghcr]({{ site.github.repository_url }}/workflows/pcap-capture-build-and-push-ghcr/badge.svg)
![pcap-monitor-build-and-push-ghcr]({{ site.github.repository_url }}/workflows/pcap-monitor-build-and-push-ghcr/badge.svg)
![suricata-build-and-push-ghcr]({{ site.github.repository_url }}/workflows/suricata-build-and-push-ghcr/badge.svg)
![zeek-build-and-push-ghcr]({{ site.github.repository_url }}/workflows/zeek-build-and-push-ghcr/badge.svg)
![malcolm-iso-build-docker-wrap-push-ghcr]({{ site.github.repository_url }}/workflows/malcolm-iso-build-docker-wrap-push-ghcr/badge.svg)
![sensor-iso-build-docker-wrap-push-ghcr]({{ site.github.repository_url }}/workflows/sensor-iso-build-docker-wrap-push-ghcr/badge.svg)

## <a name="Footer"></a>Copyright

[Malcolm]({{ site.github.repository_url }}) is Copyright 2022 Battelle Energy Alliance, LLC, and is developed and released through the cooperation of the [Cybersecurity and Infrastructure Security Agency](https://www.cisa.gov/) of the [U.S. Department of Homeland Security](https://www.dhs.gov/).

See [`License.txt`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/License.txt) for the terms of its release.

## <a name="Contact"></a>Contact information of author(s):

[malcolm@inl.gov](mailto:malcolm@inl.gov?subject=Malcolm)

[![Join the chat at https://gitter.im/malcolmnetsec/community](https://badges.gitter.im/malcolmnetsec/community.svg)](https://gitter.im/malcolmnetsec/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
