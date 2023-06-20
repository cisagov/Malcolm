# <a name="Dashboards"></a>OpenSearch Dashboards

* [OpenSearch Dashboards](#Dashboards)
    - [Discover](#Discover)
        + [Screenshots](#DiscoverGallery)
    - [Visualizations and dashboards](#DashboardsVisualizations)
        + [Prebuilt visualizations and dashboards](#PrebuiltVisualizations)
            * [Screenshots](#PrebuiltVisualizationsGallery)
        + [Building visualizations and dashboards](#BuildDashboard)
            * [Screenshots](#NewVisualizationsGallery)

While Arkime provides very nice visualizations, especially for network traffic, [OpenSearch Dashboards](https://opensearch.org/docs/latest/dashboards/index/) (an open-source general-purpose data visualization tool for OpenSearch) can be used to create custom visualizations (tables, charts, graphs, dashboards, etc.) using the same data.

The OpenSearch Dashboards container can be accessed at **https://localhost/dashboards/** if connecting locally. Several preconfigured dashboards for Zeek logs are included in Malcolm's OpenSearch Dashboards configuration.

OpenSearch Dashboards has several components for data searching and visualization:

## <a name="Discover"></a>Discover

The **Discover** view enables users to view events on a record-by-record basis (similar to a *session* record in Arkime or an individual line from a Zeek log). See the official [Kibana User Guide](https://www.elastic.co/guide/en/kibana/7.10/index.html) (OpenSearch Dashboards is an open-source fork of Kibana, which is no longer open-source software) for information on using the Discover view:

* [Discover](https://www.elastic.co/guide/en/kibana/7.10/discover.html)
* [Searching Your Data](https://www.elastic.co/guide/en/kibana/7.10/search.html)

### <a name="DiscoverGallery"></a>Screenshots

![Discover view](./images/screenshots/dashboards_discover.png)

![Viewing the details of a session in Discover](./images/screenshots/dashboards_discover_table.png)

![Filtering by tags to display only sessions with public IP addresses](./images/screenshots/dashboards_add_filter.png)

![Changing the fields displayed in Discover](./images/screenshots/dashboards_fields_list.png)

![Opening a previously-saved search](./images/screenshots/dashboards_open_search.png)

## <a name="DashboardsVisualizations"></a>Visualizations and dashboards

### <a name="PrebuiltVisualizations"></a>Prebuilt visualizations and dashboards

Malcolm comes with dozens of prebuilt visualizations and dashboards for the network traffic represented by each of the Zeek log types. Click **Dashboard** to see a list of these dashboards. As is the case with all OpenSearch Dashboards visualizations, all of the charts, graphs, maps, and tables are interactive and can be clicked on to narrow or expand the scope of the data under investigation. Similarly, click **Visualize** to explore the prebuilt visualizations used to build the dashboards.

Inspiration for many of Malcolm's prebuilt visualizations for Zeek logs was originally drawn from [Security Onion](https://github.com/Security-Onion-Solutions/securityonion)'s excellent Kibana dashboards.

#### <a name="PrebuiltVisualizationsGallery"></a>Screenshots

![The Security Overview highlights security-related network events](./images/screenshots/dashboards_security_overview.png)

![The ICS/IoT Security Overview dashboard displays information about ICS and IoT network traffic](./images/screenshots/dashboards_ics_iot_security_overview.png)

![The Connections dashboard displays information about the "top talkers" across all types of sessions](./images/screenshots/dashboards_connections.png)

![The HTTP dashboard displays important details about HTTP traffic](./images/screenshots/dashboards_http.png)

![There are several Connections visualizations using locations from GeoIP lookups](./images/screenshots/dashboards_latlon_map.png)

![OpenSearch Dashboards includes both coordinate and region map types](./images/screenshots/dashboards_region_map.png)

![The Suricata Alerts dashboard highlights traffic which matched Suricata signatures](./images/screenshots/dashboards_suricata_alerts.png)

![The Zeek Notices dashboard highlights things which Zeek determine are potentially bad](./images/screenshots/dashboards_notices.png)

![The Zeek Signatures dashboard displays signature hits, such as antivirus hits on files extracted from network traffic](./images/screenshots/dashboards_signatures.png)

![The Software dashboard displays the type, name, and version of software seen communicating on the network](./images/screenshots/dashboards_software.png)

![The PE (portable executables) dashboard displays information about executable files transferred over the network](./images/screenshots/dashboards_portable_executables.png)

![The SMTP dashboard highlights details about SMTP traffic](./images/screenshots/dashboards_smtp.png)

![The SSL dashboard displays information about SSL versions, certificates, and TLS JA3 fingerprints](./images/screenshots/dashboards_ssl.png)

![The files dashboard displays metrics about the files transferred over the network](./images/screenshots/dashboards_files_source.png)

![This dashboard provides insight into DNP3 (Distributed Network Protocol), a protocol used commonly in electric and water utilities](./images/screenshots/dashboards_dnp3.png)

![Modbus is a standard protocol found in many industrial control systems (ICS)](./images/screenshots/dashboards_modbus.png)

![BACnet is a communications protocol for Building Automation and Control (BAC) networks](./images/screenshots/dashboards_bacnet.png)

![EtherCAT is an Ethernet-based fieldbus system](./images/screenshots/dashboards_ecat.png)

![EtherNet/IP is an industrial network protocol that adapts the Common Industrial Protocol to standard Ethernet](./images/screenshots/dashboards_ethernetip.png)

![PROFINET is an industry technical standard for data communication over Industrial Ethernet](./images/screenshots/dashboards_profinet.png)

![S7comm is a Siemens proprietary protocol that runs between programmable logic controllers (PLCs) of the Siemens family](./images/screenshots/dashboards_s7comm.png)

### <a name="BuildDashboard"></a>Building visualizations and dashboards

See the official [Kibana User Guide](https://www.elastic.co/guide/en/kibana/7.10/index.html) and [OpenSearch Dashboards](https://opensearch.org/docs/latest/dashboards/index/) (OpenSearch Dashboards is an open-source fork of Kibana, which is no longer open-source software) documentation for information on creating custom visualizations and dashboards:

* [OpenSearch Dashboards](https://opensearch.org/docs/latest/dashboards/index/)
* [Kibana Dashboards](https://www.elastic.co/guide/en/kibana/7.10/dashboard.html)
* [TimeLion](https://www.elastic.co/guide/en/kibana/7.12/timelion.html)

#### <a name="NewVisualizationsGallery"></a>Screenshots

![OpenSearch dashboards boasts many types of visualizations for displaying your data](./images/screenshots/dashboards_new_visualization.png)