# Malcolm

![](./docs/images/logo/Malcolm_outline_banner_dark.png)

Malcolm is a powerful network traffic analysis tool suite designed with the following goals in mind:

* **Easy to use** – Malcolm accepts network traffic data in the form of full packet capture (PCAP) files and Zeek (formerly Bro) logs. These artifacts can be uploaded via a simple browser-based interface or captured live and forwarded to Malcolm using lightweight forwarders. In either case, the data is automatically normalized, enriched, and correlated for analysis.
* **Powerful traffic analysis** – Visibility into network communications is provided through two intuitive interfaces: OpenSearch Dashboard, a flexible data visualization plugin with dozens of prebuilt dashboards providing an at-a-glance overview of network protocols; and Arkime (formerly Moloch), a powerful tool for finding and identifying the network sessions comprising suspected security incidents.
* **Streamlined deployment** – Malcolm operates as a cluster of Docker containers – isolated sandboxes that each serve a dedicated function of the system. This Docker-based deployment model, combined with a few simple scripts for setup and run-time management, makes Malcolm suitable to be deployed quickly across a variety of platforms and use cases; whether it be for long-term deployment on a Linux server in a security operations center (SOC) or for incident response on a Macbook for an individual engagement.
* **Secure communications** – All communications with Malcolm, both from the user interface and from remote log forwarders, are secured with industry standard encryption protocols.
* **Permissive license** – Malcolm is comprised of several widely used open-source tools, making it an attractive alternative to security solutions requiring paid licenses.
* **Expanding control systems visibility** – While Malcolm is great for general-purpose network traffic analysis, its creators see a particular need in the community for tools providing insight into protocols used in industrial control systems (ICS) environments. Ongoing Malcolm development will aim to provide additional parsers for common ICS protocols.

Although all the open-source tools that make up Malcolm are already available and in general use, Malcolm provides a framework of interconnectivity that makes it greater than the sum of its parts.

In short, Malcolm provides an easily deployable network analysis tool suite for full PCAP files and Zeek logs. While Internet access is required to build Malcolm, internet access is not required at runtime.

## Documentation

See the [**Malcolm documentation**](docs/README.md).

## Share your feedback

You can help steer Malcolm's development by sharing your ideas and feedback. Please take a few minutes to complete [this survey ↪](https://forms.gle/JYt9QwA5C4SYX8My6) (hosted on Google Forms) so we can understand the members of the Malcolm community and their use cases for this tool.

## <a name="Footer"></a>Copyright and License

Malcolm is Copyright 2023 Battelle Energy Alliance, LLC, and is developed and released through the cooperation of the [Cybersecurity and Infrastructure Security Agency](https://www.cisa.gov/) of the [U.S. Department of Homeland Security](https://www.dhs.gov/).

Malcolm is licensed under the Apache License, version 2.0. See `LICENSE.txt` for the terms of its release.

## <a name="Contact"></a>Contact information of author(s):

[malcolm@inl.gov](mailto:malcolm@inl.gov?subject=Malcolm)
