# Hedgehog Linux 
## Network Traffic Capture Appliance

![](./docs/logo/hedgehog-color-w-text.png)

Hedgehog Linux is a Debian-based operating system built to

* monitor network interfaces
* capture packets to PCAP files
* detect file transfers in network traffic and extract and scan those files for threats
* generate and forward Zeek logs, Arkime sessions and other information to [Malcolm](https://github.com/idaholab/Malcolm)

![sensor-iso-build-docker-wrap-push-ghcr](https://github.com/idaholab/Malcolm/workflows/sensor-iso-build-docker-wrap-push-ghcr/badge.svg)

### <a name="TableOfContents"></a>Table of Contents

* [Sensor installation](#Installation)
    - [Image boot options](#BootOptions)
    - [Installer](#Installer)
* [Boot](#Boot)
    - [Kiosk mode](#KioskMode)
* [Configuration](#Configuration)
    - [Interfaces, hostname, and time synchronization](#ConfigRoot)
        + [Hostname](#ConfigHostname)
        + [Interfaces](#ConfigIface)
        + [Time synchronization](#ConfigTime)
    - [Capture, forwarding, and autostart services](#ConfigUser)
        + [Capture](#ConfigCapture)
            * [Automatic file extraction and scanning](#ZeekFileExtraction)
        + [Forwarding](#ConfigForwarding)
            * [filebeat](#filebeat): Zeek log forwarding
            * [arkime-capture](#arkime-capture): Arkime session forwarding
            * [metricbeat](#metricbeat): resource statistics forwarding
            * [auditbeat](#auditbeat): audit log forwarding
            * [filebeat-syslog](#syslogbeat): syslog forwarding
            * [heatbeat](#heatbeat): temperature forwarding
        + [Autostart services](#ConfigAutostart)
        + [Zeek Intelligence Framework](#ZeekIntel)
* [Appendix A - Generating the ISO](#ISOBuild)
* [Appendix B - Configuring SSH access](#ConfigSSH)
* [Appendix C - Troubleshooting](#Troubleshooting)
* [Appendix D - Hardening](#Hardening)
    - [STIG compliance exceptions](#STIGExceptions)
    - [CIS benchmark compliance exceptions](#CISExceptions)
* [Appendix E - Upgrades](#UpgradePlan)
* [Copyright](#Footer)

# <a name="Installation"></a>Sensor installation

## <a name="BootOptions"></a>Image boot options

The Hedgehog Linux installation image, when provided on an optical disc, USB thumb drive, or other removable medium, can be used to install or reinstall the sensor software.

![Sensor installation image boot menu](./docs/images/boot_options.png)

The boot menu of the sensor installer image provides several options:

* **Live system** and **Live system (fully in RAM)** may also be used to run the sensor in a "live USB" mode without installing any software or making any persistent configuration changes on the sensor hardware.
* **Install Hedgehog Linux** and **Install Hedgehog Linux (encrypted)** are used to [install the sensor](#Installer) onto the current system. Both selections install the same operating system and sensor software, the only difference being that the **encrypted** option encrypts the hard disks with a password (provided in a subsequent step during installation) that must be provided each time the sensor boots. There is some CPU overhead involved in an encrypted installation, so it is recommended that encrypted installations only be used for mobile installations (eg., on a sensor that may be shipped or carried for an incident response) and that the unencrypted option be used for fixed sensors in secure environments.
* **Install Hedgehog Linux (advanced configuration)** allows you to configure installation fully using all of the [Debian installer](https://www.debian.org/releases/stable/amd64/) settings and should only be selected for advanced users who know what they're doing.
* **Rescue system** is included for debugging and/or system recovery and should not be needed in most cases.

## <a name="Installer"></a>Installer

The sensor installer is designed to require as little user input as possible. For this reason, there are NO user prompts and confirmations about partitioning and reformatting hard disks for use by the sensor. The  installer assumes that all non-removable storage media (eg., SSD, HDD, NVMe, etc.) are available for use and ⛔🆘😭💀 ***will partition and format them without warning*** 💀😭🆘⛔.

The installer will ask for a few pieces of information prior to installing the sensor operating system:

* **Root password** – a password for the privileged root account which is rarely needed (only during the configuration of the sensors network interfaces and setting the sensor host name)
* **User password** – a password for the non-privileged sensor account under which the various sensor capture and forwarding services run
* **Encryption password** (optional) – if the encrypted installation option was selected at boot time, the encryption password must be entered every time the sensor boots

Each of these passwords must be entered twice to ensure they were entered correctly.

![Example of the installer's password prompt](./docs/images/users_and_passwords.png)

After the passwords have been entered, the installer will proceed to format the system drive and install Hedgehog Linux.

![Installer progress](./docs/images/installer_progress.png)

At the end of the installation process, you will be prompted with a few self-explanatory yes/no questions:

* **Disable IPv6?**
* **Automatically login to the GUI session?**
* **Should the GUI session be locked due to inactivity?**
* **Display the [Standard Mandatory DoD Notice and Consent Banner](https://www.stigviewer.com/stig/application_security_and_development/2018-12-24/finding/V-69349)?** *(only applies when installed on U.S. government information systems)*

Following these prompts, the installer will reboot and Hedgehog Linux will boot.

# <a name="Boot"></a>Boot

Each time the sensor boots, a grub boot menu will be shown briefly, after which the sensor will proceed to load.

## <a name="KioskMode"></a>Kiosk mode

![Kiosk mode sensor menu: resource statistics](./docs/images/kiosk_mode_sensor_menu.png)

The sensor automatically logs in as the sensor user account and runs in **kiosk mode**, which is intended to show an at-a-glance view of the its resource utilization. Clicking the **☰** icon in allows you to switch between the resource statistics view and the services view.

![Kiosk mode sensor menu: services](./docs/images/kiosk_mode_services_menu.png)

The kiosk's services screen (designed with large clickable labels for small portable touch screens) can be used to start and stop essential services, get a status report of the currently running services, and clean all captured data from the sensor.

!["Clean Sensor" confirmation prompt before deleting sensor data](./docs/images/kiosk_mode_wipe_prompt.png)

!["Sensor Status" report from the kiosk services menu](./docs/images/kiosk_mode_status.png)

# <a name="Configuration"></a>Configuration

Kiosk mode can be exited by connecting an external USB keyboard and pressing **Alt+F4**, upon which the *sensor* user's desktop is shown.

![Sensor login session desktop](./docs/images/desktop.png)

Several icons are available in the top menu bar:

* **Terminal** - opens a command prompt in a terminal emulator
* **Browser** - opens a web browser
* **Kiosk** – returns the sensor to kiosk mode
* **README** – displays this document
* **Sensor status** – displays a list with the status of each sensor service
* **Configure capture and forwarding** – opens a dialog for configuring the sensor's capture and forwarding services, as well as specifying which services should autostart upon boot
* **Configure interfaces and hostname** – opens a dialog for configuring the sensor's network interfaces and setting the sensor's hostname
* **Restart sensor services** - stops and restarts all of the [autostart services](#ConfigAutostart)

## <a name="ConfigRoot"></a>Interfaces, hostname, and time synchronization

### <a name="ConfigHostname"></a>Hostname

The first step of sensor configuration is to configure the network interfaces and sensor hostname. Double-clicking the **Configure Interfaces and Hostname** desktop icon (or, if you are at a command line prompt, running `configure-interfaces`) will prompt you for the root password you created during installation, after which the configuration welcome screen is shown. Select **Continue** to proceed.

You may next select whether to configure the network interfaces, hostname, or time synchronization.

![Selection to configure network interfaces, hostname, or time synchronization](./docs/images/root_config_mode.png)

Selecting **Hostname**, you will be presented with a summary of the current sensor identification information, after which you may specify a new sensor hostname.  This name will be used to tag all events forwarded from this sensor in the events' **host.name** field.

![Specifying a new sensor hostname](./docs/images/hostname_setting.png)

### <a name="ConfigIface"></a>Interfaces

Returning to the configuration mode selection, choose **Interface**. You will be prompted if you would like help identifying network interfaces. If you select **Yes**, you will be prompted to select a network interface, after which that interface's link LED will blink for 10 seconds to help you in its identification. This network interface identification aid will continue to prompt you to identify further network interfaces until you select **No**.

You will be presented with a list of interfaces to configure as the sensor management interface. This is the interface the sensor itself will use to communicate with the network in order to, for example, forward captured logs to an aggregate server. In order to do so, the management interface must be assigned an IP address. This is generally **not** the interface used for capturing data. Select the interface to which you wish to assign an IP address. The interfaces are listed by name and MAC address and the associated link speed is also displayed if it can be determined. For interfaces without a connected network cable, generally a `-1` will be displayed instead of the interface speed.

![Management interface selection](./docs/images/select_iface.png)

Depending on the configuration of your network, you may now specify how the management interface will be assigned an IP address. In order to communicate with an event aggregator over the management interface, either **static** or **dhcp** must be selected.

![Interface address source](./docs/images/iface_mode.png)

If you select static, you will be prompted to enter the IP address, netmask, and gateway to assign to the management interface.

![Static IP configuration](./docs/images/iface_static.png)

In either case, upon selecting **OK** the network interface will be brought down, configured, and brought back up, and the result of the operation will be displayed. You may choose **Quit** upon returning to the configuration tool's welcome screen.

### <a name="ConfigTime"></a>Time synchronization

Returning to the configuration mode selection, choose **Time Sync**. Here you can configure the sensor to keep its time synchronized with either an NTP server (using the NTP protocol) or a local [Malcolm](https://github.com/idaholab/Malcolm) aggregator or another HTTP/HTTPS server. On the next dialog, choose the time synchronization method you wish to configure.

![Time synchronization method](./docs/images/time_sync_mode.png)

If **htpdate** is selected, you will be prompted to enter the IP address or hostname and port of an HTTP/HTTPS server (for a Malcolm instance, port `9200` may be used) and the time synchronization check frequency in minutes. A test connection will be made to determine if the time can be retrieved from the server.

![*htpdate* configuration](./docs/images/htpdate_setup.png)

If *ntpdate* is selected, you will be prompted to enter the IP address or hostname of the NTP server.

![NTP configuration](./docs/images/ntp_host.png)

Upon configuring time synchronization, a "Time synchronization configured successfully!" message will be displayed, after which you will be returned to the welcome screen.

## <a name="ConfigUser"></a>Capture, forwarding, and autostart services

Double-clicking the **Configure Capture and Forwarding** icon (or, if you are at a command prompt, running `configure-capture`) will launch the configuration tool for capture and forwarding. The root password is not required as it was for the interface and hostname configuration, as sensor services are run under the non-privileged sensor account. Select **Continue** to proceed. You may select from a list of configuration options.

![Select configuration mode](./docs/images/capture_config_main.png)

### <a name="ConfigCapture"></a>Capture

Choose **Configure Capture** to configure parameters related to traffic capture and local analysis. You will be prompted if you would like help identifying network interfaces. If you select **Yes**, you will be prompted to select a network interface, after which that interface's link LED will blink for 10 seconds to help you in its identification. This network interface identification aid will continue to prompt you to identify further network interfaces until you select **No**.

You will be presented with a list of network interfaces and prompted to select one or more capture interfaces. An interface used to capture traffic is generally a different interface than the one selected previously as the management interface, and each capture interface should be connected to a network tap or span port for traffic monitoring. Capture interfaces are usually not assigned an IP address as they are only used to passively “listen” to the traffic on the wire. The interfaces are listed by name and MAC address and the associated link speed is also displayed if it can be determined. For interfaces without a connected network cable, generally a `-1` will be displayed instead of the interface speed.

![Select capture interfaces](./docs/images/capture_iface_select.png)

Upon choosing the capture interfaces and selecting OK, you may optionally provide a capture filter. This filter will be used to limit what traffic the PCAP service ([`tcpdump`](https://www.tcpdump.org/)) and the traffic analysis service ([`zeek`](https://www.zeek.org/)) will see. Capture filters are specified using [Berkeley Packet Filter (BPF)](http://biot.com/capstats/bpf.html) syntax. Clicking **OK** will attempt to validate the capture filter, if specified, and will present a warning if the filter is invalid.

![Specify capture filters](./docs/images/capture_filter.png)

Next you must specify the paths where captured PCAP files and Zeek logs will be stored locally on the sensor. If the installation worked as expected, these paths should be prepopulated to reflect paths on the volumes formatted at install time for the purpose storing these artifacts. Usually these paths will exist on separate storage volumes. Enabling the PCAP and Zeek log pruning autostart services (see the section on autostart services below) will enable monitoring of these paths to ensure that their contents do not consume more than 90% of their respective volumes' space. Choose **OK** to continue.

![Specify capture paths](./docs/images/capture_paths.png)

#### <a name="ZeekFileExtraction"></a>Automatic file extraction and scanning

Hedgehog Linux can leverage Zeek's knowledge of network protocols to automatically detect file transfers and extract those files from network traffic as Zeek sees them.

To specify which files should be extracted, specify the Zeek file carving mode:

![Zeek file carving mode](./docs/images/zeek_file_carve_mode.png)

If you're not sure what to choose, either of **mapped (except common plain text files)** (if you want to carve and scan almost all files) or **interesting** (if you only want to carve and scan files with [mime types of common attack vectors](./interface/sensor_ctl/zeek/extractor_override.interesting.zeek)) is probably a good choice.

Next, specify which carved files to preserve (saved on the sensor under `/capture/bro/capture/extract_files/quarantine` by default). In order to not consume all of the sensor's available storage space, the oldest preserved files will be pruned along with the oldest Zeek logs as described below with **AUTOSTART_PRUNE_ZEEK** in the [autostart services](#ConfigAutostart) section.

You'll be prompted to specify which engine(s) to use to analyze extracted files. Extracted files can be examined through any of three methods:

![File scanners](./docs/images/zeek_file_carve_scanners.png)

* scanning files with [**ClamAV**](https://www.clamav.net/); to enable this method, select **ZEEK_FILE_SCAN_CLAMAV** when specifying scanners for Zeek-carved files
* submitting file hashes to [**VirusTotal**](https://www.virustotal.com/en/#search); to enable this method, select **ZEEK_FILE_SCAN_VTOT** when specifying scanners for Zeek-carved files, then manually edit `/opt/sensor/sensor_ctl/control_vars.conf` and specify your [VirusTotal API key](https://developers.virustotal.com/reference) in `VTOT_API2_KEY`
* scanning files with [**Yara**](https://github.com/VirusTotal/yara); to enable this method, select **ZEEK_FILE_SCAN_YARA** when specifying scanners for Zeek-carved files
* scanning portable executable (PE) files with [**Capa**](https://github.com/fireeye/capa); to enable this method, select **ZEEK_FILE_SCAN_CAPA** when specifying scanners for Zeek-carved files

Files which are flagged as potentially malicious will be logged as Zeek `signatures.log` entries, and can be viewed in the **Signatures** dashboard in [OpenSearch Dashboards](https://github.com/idaholab/Malcolm#DashboardsVisualizations) when forwarded to Malcolm.

![File quarantine](./docs/images/file_quarantine.png)

Finally, you will then be presented with the list of configuration variables that will be used for capture, including the values which you have configured up to this point in this section. Upon choosing **OK** these values will be written back out to the sensor configuration file located at `/opt/sensor/sensor_ctl/control_vars.conf`. It is not recommended that you edit this file manually. After confirming these values, you will be presented with a confirmation that these settings have been written to the configuration file, and you will be returned to the welcome screen.

![Capture parameters summary](./docs/images/capture_confirm.png)

### <a name="ConfigForwarding"></a>Forwarding

Select **Configure Forwarding** to set up forwarding logs and statistics from the sensor to an aggregator server, such as [Malcolm](https://github.com/idaholab/Malcolm).

![Configure forwarders](./docs/images/forwarder_config.png)

There are five forwarder services used on the sensor, each for forwarding a different type of log or sensor metric.

### <a name="filebeat"></a>filebeat: Zeek log forwarding

[Filebeat](https://www.elastic.co/products/beats/filebeat) is used to forward [Zeek](https://www.zeek.org/) logs to a remote [Logstash](https://www.elastic.co/products/logstash) instance for further enrichment prior to insertion into an [OpenSearch](https://opensearch.org/) database.

To configure filebeat, first provide the log path (the same path previously configured for Zeek log file generation). You must also provide the IP address of the Logstash instance to which the logs are to be forwarded, and the port on which Logstash is listening. These logs are forwarded using the Beats protocol, generally over port 5044. Depending on your network configuration, you may need to open this port in your firewall to allow this connection from the sensor to the aggregator.

![Configure filebeat for Zeek log forwrding](./docs/images/filebeat_dest.png)

Next you are asked whether the connection used for Zeek log forwarding should be done **unencrypted** or over **SSL**. Unencrypted communication requires less processing overhead and is simpler to configure, but the contents of the logs may be visible to anyone who is able to intercept that traffic.

![Filebeat SSL certificate verification](./docs/images/filebeat_ssl.png)

If **SSL** is chosen, you must choose whether to enable [SSL certificate verification](https://www.elastic.co/guide/en/beats/filebeat/current/configuring-ssl-logstash.html). If you are using a self-signed certificate (such as the one automatically created during [Malcolm's configuration](https://github.com/idaholab/Malcolm#configure-authentication), choose **None**.

![Unencrypted vs. SSL encryption for Zeek log forwarding](./docs/images/filebeat_ssl_verify.png)

The last step for SSL-encrypted Zeek log forwarding is to specify the SSL certificate authority, certificate, and key files. These files must match those used by the Logstash instance receiving the Zeek logs on the aggregator. If Malcolm's `auth_setup` script was used to generate these files they would be found in the `filebeat/certs/` subdirectory of the Malcolm installation and must be manually copied to the sensor (stored under `/opt/sensor/sensor_ctl/filebeat/` or in any other path accessible to the sensor account). Specify the location of the certificate authorities file (eg., `ca.crt`), the certificate file (eg., `client.crt`), and the key file (eg., `client.key`).

![SSL certificate files](./docs/images/filebeat_certs.png)

The Logstash instance receiving the events must be similarly configured with matching SSL certificate and key files. Under Malcolm, the `BEATS_SSL` variable must be set to true in Malcolm's `docker-compose.yml` file and the SSL files must exist in the `logstash/certs/` subdirectory of the Malcolm installation.

Once you have specified all of the filebeat parameters, you will be presented with a summary of the settings related to the forwarding of these logs. Selecting **OK** will cause the parameters to be written to filebeat's configuration keystore under `/opt/sensor/sensor_ctl/filebeat` and you will be returned to the configuration tool's welcome screen.

![Confirm filebeat settings](./docs/images/filebeat_confirm.png)

### <a name="arkime-capture"></a>capture: Arkime session forwarding

[capture](https://github.com/arkime/arkime/tree/master/capture) is not only used to capture PCAP files, but also the parse raw traffic into sessions and forward this session metadata to an [OpenSearch](https://opensearch.org/) database so that it can be viewed in [Arkime viewer](https://arkime.com/), whether standalone or as part of a [Malcolm](https://github.com/idaholab/Malcolm) instance. If you're using Hedgehog Linux with Malcolm, please read [Correlating Zeek logs and Arkime sessions](https://github.com/idaholab/Malcolm#ZeekArkimeFlowCorrelation) in the Malcolm documentation for more information.

First, select the OpenSearch connection transport protocol, either **HTTPS** or **HTTP**. If the metrics are being forwarded to Malcolm, select **HTTPS** to encrypt messages from the sensor to the aggregator using TLS v1.2 using ECDHE-RSA-AES128-GCM-SHA256. If **HTTPS** is chosen, you must choose whether to enable SSL certificate verification. If you are using a self-signed certificate (such as the one automatically created during [Malcolm's configuration](https://github.com/idaholab/Malcolm#configure-authentication)), choose **None**.

![OpenSearch connection protocol](./docs/images/metricbeat_elastic_protocol.png) ![OpenSearch SSL verification](./docs/images/metricbeat_elastic_ssl.png)

Next, enter the **OpenSearch host** IP address (ie., the IP address of the aggregator) and port. These metrics are written to an OpenSearch database using a RESTful API, usually using port 9200. Depending on your network configuration, you may need to open this port in your firewall to allow this connection from the sensor to the aggregator.

![OpenSearch host and port](./docs/images/arkime-capture-ip-port.png)

You will be asked to enter authentication credentials for the sensor's connections to the aggregator's OpenSearch API. After you've entered the username and the password, the sensor will attempt a test connection to OpenSearch using the connection information provided.

![OpenSearch username](./docs/images/elasticsearch-username.png) ![OpenSearch password](./docs/images/elasticsearch_password.png) ![Successful OpenSearch connection](./docs/images/metricbeat_elasticsearch_success.png)

Finally, you will be shown a dialog for a list of IP addresses used to populate an access control list (ACL) for hosts allowed to connect back to the sensor for retrieving session payloads from its PCAP files for display in Arkime viewer. The list will be prepopulated with the IP address entered a few screens prior to this one.

![PCAP retrieval ACL](./docs/images/malcolm_arkime_reachback_acl.png)

Finally, you'll be given the opportunity to review the all of the Arkime `capture` options you've specified. Selecting **OK** will cause the parameters to be saved and you will be returned to the configuration tool's welcome screen.

![capture settings confirmation](./docs/images/arkime_confirm.png) ![capture settings applied successfully](./docs/images/arkime_success.png)

### <a name="metricbeat"></a>metricbeat: resource statistics forwarding

The sensor uses [metricbeat](https://www.elastic.co/products/beats/metricbeat) to forward system resource metrics (CPU, network I/O, disk I/O, memory utilization, etc.) to an OpenSearch database using a RESTful API using HTTP/HTTPS as the transport protocol. Select **metricbeat** from the forwarding configuration mode options.

Metricbeat gathers system resource metrics at an interval you specify. The default interval is 30 seconds, but it can be set to any value between 1 and 60 seconds.

![Metricbeat interval](./docs/images/metricbeat_interval.png)

Next, select the OpenSearch connection transport protocol, either **HTTPS** or **HTTP**. If the metrics are being forwarded to Malcolm, select **HTTPS** to encrypt messages from the sensor to the aggregator using TLS v1.2 using ECDHE-RSA-AES128-GCM-SHA256. If **HTTPS** is chosen, you must choose whether to enable SSL certificate verification. If you are using a self-signed certificate (such as the one automatically created during [Malcolm's configuration](https://github.com/idaholab/Malcolm#configure-authentication), choose **None**.

![OpenSearch connection protocol](./docs/images/metricbeat_elastic_protocol.png) ![OpenSearch SSL verification](./docs/images/metricbeat_elastic_ssl.png)

Next, enter the **OpenSearch host** IP address (ie., the IP address of the aggregator) and port. These metrics are written to an OpenSearch database using a RESTful API, usually using port 9200. Depending on your network configuration, you may need to open this port in your firewall to allow this connection from the sensor to the aggregator.

![OpenSearch host and port](./docs/images/metricbeat_elastic_host.png)

Next, you will be asked if you wish to configure **OpenSearch Dashboards** connectivity. [OpenSearch Dashboards](https://opensearch.org/docs/latest/dashboards/index/) is an open source general-purpose data visualization tool for OpenSearch. If you choose **Yes** and proceed to configure Dashboards connectivity, metricbeat will create custom search indexes, visualizations, and dashboards for Dashboards to display the sensor's resource metrics.

You will be prompted to specify the **connection protocol** and (for HTTPS) **SSL verification** for Dashboards. These values should probably be the same ones you chose for OpenSearch. You will also be prompted for the **Dashboards host** IP address and **port**. The IP address will probably be the same one you specified for OpenSearch. The default Dashboards port is 5601.

The final settings required to configure Dashboards are whether or not to configure **OpenSearch Dashboards** and the local directory on the sensor containing the dashboards to be imported. The default values are probably what you want.

Finally, you will be asked to enter authentication credentials for the sensor's connections to the aggregator's OpenSearch and Dashboards APIs.

After you've entered the username and the password, the sensor will attempt test connections to the OpenSearch and Dashboards APIs using the connection information provided.

![OpenSearch/Dashboards username](./docs/images/metricbeat_elastic_username.png) ![OpenSearch/Dashboards password](./docs/images/metricbeat_elastic_password.png) ![Successful OpenSearch connection](./docs/images/metricbeat_elasticsearch_success.png) ![Successful Dashboards connection](./docs/images/metricbeat_kibana_success.png)

Finally, you'll be given the opportunity to review the all of the metricbeat options you've specified. Selecting **OK** will cause the parameters to be written to metricbeat's configuration keystore under `/opt/sensor/sensor_ctl/metricbeat` and you will be returned to the configuration tool's welcome screen.

![Metricbeat settings confirmation](./docs/images/metricbeat_confirm.png) ![Metricbeat settings applied successfully](./docs/images/metricbeat_success.png)

### <a name="auditbeat"></a>auditbeat: audit log forwarding

The sensor uses [auditbeat](https://www.elastic.co/products/beats/auditbeat) to forward auditd logs, process and socket statistics, and sensor system file integrity information to an OpenSearch database. Its configuration is almost identical to that of metricbeat in the previous section. Select **auditbeat** from the forwarding configuration mode options and follow the same steps outlined above to set up this forwarder.

The sensor implements STIG (Security Technical Implementation Guidelines) rules according to DISA RHEL 7 STIG V1 R1, ported to a Debian 9 base platform. Enabling audit log forwarding via auditbeat is required to satisfy the requirements regarding forwarding audit logs to a remote log server as defined in that specification.

### <a name="syslogbeat"></a>filebeat-syslog: syslog forwarding

The sensor uses [filebeat's syslog input](https://www.elastic.co/guide/en/beats/filebeat/master/filebeat-input-syslog.html) to forward the sensor's system logs to an OpenSearch database. Its configuration is almost identical to that of metricbeat in a previous section. Select **filebeat-syslog** from the forwarding configuration mode options and follow the same steps outlined above to set up this forwarder.

Enabling syslog forwarding via filebeat is required to satisfy the STIG requirements regarding sending system logs to a remote log server as defined in that specification.

### <a name="heatbeat"></a>heatbeat: temperature forwarding

The sensor employs a custom agent using the beats protocol to forward hardware metrics such as CPU and storage device temperatures, system voltages, and fan speeds (when applicable) to an OpenSearch database. Its configuration is almost identical to that of metricbeat in a previous section. Select **heatbeat** from the forwarding configuration mode options and follow the same steps outlined above to set up this forwarder.

### <a name="ConfigAutostart"></a>Autostart services

Once the forwarders have been configured, the final step is to **Configure Autostart Services**. Choose this option from the configuration mode menu after the welcome screen of the sensor configuration tool.

Despite configuring capture and/or forwarder services as described in previous sections, only services enabled in the autostart configuration will run when the sensor starts up. The available autostart processes are as follows (recommended services are in **bold text**):

* **AUTOSTART_AUDITBEAT** – [auditbeat](#auditbeat) audit log forwarder
* **AUTOSTART_CLAMAV_UPDATES** – Virus database update service for ClamAV (requires sensor to be connected to the internet)
* **AUTOSTART_FILEBEAT** – [filebeat](#filebeat) Zeek log forwarder 
* **AUTOSTART_HEATBEAT** – [sensor hardware](#heatbeat) (eg., CPU and storage device temperature) metrics forwarder
* **AUTOSTART_HEATBEAT_SENSORS** – the background process monitoring [hardware sensors](#heatbeat) for temperatures, voltages, fan speeds, etc. (this is required in addition to **AUTOSTART_HEATBEAT** metrics forwarding)
* **AUTOSTART_METRICBEAT** – system resource utilization [metrics forwarder](#metricbeat)
* **AUTOSTART_ARKIME** – [capture](#arkime-capture) PCAP engine for traffic capture, as well as traffic parsing and metadata insertion into OpenSearch for viewing in [Arkime](https://arkime.com/). If you are using Hedgehog Linux along with [Malcolm](https://github.com/idaholab/Malcolm) or another Arkime installation, this is probably the packet capture engine you want to use.
* *AUTOSTART_NETSNIFF* – [netsniff-ng](http://netsniff-ng.org/) PCAP engine for saving packet capture (PCAP) files
* **AUTOSTART_PRUNE_ZEEK** – storage space monitor to ensure that Zeek logs do not consume more than 90% of the total size of the storage volume to which Zeek logs are written
* **AUTOSTART_PRUNE_PCAP** – storage space monitor to ensure that PCAP files do not consume more than 90% of the total size of the storage volume to which PCAP files are written
* **AUTOSTART_SYSLOGBEAT** – filebeat [system log forwarder](#syslogbeat)
* *AUTOSTART_TCPDUMP* – [tcpdump](https://www.tcpdump.org/) PCAP engine for saving packet capture (PCAP) files
* **AUTOSTART_ZEEK** – [Zeek](https://www.zeek.org/) traffic analysis engine

Note that only one packet capture engine ([capture](https://arkime.com/), [netsniff-ng](http://netsniff-ng.org/), or [tcpdump](https://www.tcpdump.org/)) can be used.

![Autostart services](./docs/images/autostarts.png)

Once you have selected the autostart services, you will be prompted to confirm your selections. Doing so will cause these values to be written back out to the `/opt/sensor/sensor_ctl/control_vars.conf` configuration file.

![Autostart services confirmation](./docs/images/autostarts_confirm.png)

After you have completed configuring the sensor it is recommended that you reboot the sensor to ensure all new settings take effect. If rebooting is not an option, you may click the **Restart Sensor Services** menu icon in the top menu bar, or open a terminal and run:

```
/opt/sensor/sensor_ctl/shutdown && sleep 10 && /opt/sensor/sensor_ctl/supervisor.sh
```

This will cause the sensor services controller to stop, wait a few seconds, and restart. You can check the status of the sensor's processes by choosing **Sensor Status** from the sensor's kiosk mode, double-clicking the **Sensor Service Status** desktop icon, or running `/opt/sensor/sensor_ctl/status` from the command line:

```
$ /opt/sensor/sensor_ctl/status 
beats:auditbeat                  RUNNING   pid 14470, uptime 8 days, 20:22:32
beats:filebeat                   RUNNING   pid 14460, uptime 8 days, 20:22:32
beats:heatbeat                   RUNNING   pid 14481, uptime 8 days, 20:22:32
beats:metricbeat                 RUNNING   pid 14476, uptime 8 days, 20:22:32
beats:sensors                    RUNNING   pid 14484, uptime 8 days, 20:22:32
beats:syslogbeat                 RUNNING   pid 14471, uptime 8 days, 20:22:32
clamav:clamav-service            RUNNING   pid 14454, uptime 8 days, 20:22:32
clamav:clamav-updates            RUNNING   pid 14450, uptime 8 days, 20:22:32
arkime:arkime-capture            RUNNING   pid 14432, uptime 8 days, 20:22:32
arkime:arkime-viewer             RUNNING   pid 14431, uptime 8 days, 20:22:32
netsniff:netsniff-enp8s0         STOPPED   Not started
prune:prune-pcap                 RUNNING   pid 14446, uptime 8 days, 20:22:32
prune:prune-zeek                 RUNNING   pid 14442, uptime 8 days, 20:22:32
tcpdump:tcpdump-enp8s0           STOPPED   Not started
zeek:logger                      RUNNING   pid 14434, uptime 8 days, 20:22:32
zeek:virustotal                  RUNNING   pid 14435, uptime 8 days, 20:22:32
zeek:yara                        RUNNING   pid 14435, uptime 8 days, 20:22:32
zeek:capa                        RUNNING   pid 14435, uptime 8 days, 20:22:32
zeek:clamav                      RUNNING   pid 14435, uptime 8 days, 20:22:32
zeek:watcher                     RUNNING   pid 14441, uptime 8 days, 20:22:32
zeek:zeekctl                     RUNNING   pid 14433, uptime 8 days, 20:22:32
```

### <a name="ZeekIntel"></a>Zeek Intelligence Framework

To quote Zeek's [Intelligence Framework](https://docs.zeek.org/en/master/frameworks/intel.html) documentation, "The goals of Zeek’s Intelligence Framework are to consume intelligence data, make it available for matching, and provide infrastructure to improve performance and memory utilization. Data in the Intelligence Framework is an atomic piece of intelligence such as an IP address or an e-mail address. This atomic data will be packed with metadata such as a freeform source field, a freeform descriptive field, and a URL which might lead to more information about the specific item." Zeek [intelligence](https://docs.zeek.org/en/master/scripts/base/frameworks/intel/main.zeek.html) [indicator types](https://docs.zeek.org/en/master/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Type) include IP addresses, URLs, file names, hashes, email addresses, and more.

Hedgehog Linux doesn't come bundled with intelligence files from any particular feed, but they can be easily included into your local instance. Before Zeek starts, Hedgehog Linux configures it such that intelligence files will be automatically included in its local policy. Subdirectories under `/opt/sensor/sensor_ctl/zeek/intel` which contain their own `__load__.zeek` file will be `@load`-ed as-is, while subdirectories containing "loose" intelligence files will be [loaded](https://docs.zeek.org/en/master/frameworks/intel.html#loading-intelligence) automatically with a `redef Intel::read_files` directive.

Note that Hedgehog Linux does not manage updates for these intelligence files. You should use the update mechanism suggested by your feeds' maintainers to keep them up to date. Adding and deleting intelligence files under this directory will take effect upon restarting Zeek.

# <a name="ISOBuild"></a>Appendix A - Generating the ISO

Official downloads of the Hedgehog Linux installer ISO are not provided: however, it can be built easily on an internet-connected Linux host with Vagrant:

* [Vagrant](https://www.vagrantup.com/)
    - [`vagrant-reload`](https://github.com/aidanns/vagrant-reload) plugin
    - [`vagrant-sshfs`](https://github.com/dustymabe/vagrant-sshfs) plugin
    - [`bento/debian-11`](https://app.vagrantup.com/bento/boxes/debian-11) Vagrant box

The build should work with either the [VirtualBox](https://www.virtualbox.org/) provider or the [libvirt](https://libvirt.org/) provider:

* [VirtualBox](https://www.virtualbox.org/) [provider](https://www.vagrantup.com/docs/providers/virtualbox)
    - [`vagrant-vbguest`](https://github.com/dotless-de/vagrant-vbguest) plugin
* [libvirt](https://libvirt.org/) 
    - [`vagrant-libvirt`](https://github.com/vagrant-libvirt/vagrant-libvirt) provider plugin
    - [`vagrant-mutate`](https://github.com/sciurus/vagrant-mutate) plugin to convert [`bento/debian-11`](https://app.vagrantup.com/bento/boxes/debian-11) Vagrant box to `libvirt` format

To perform a clean build the Hedgehog Linux installer ISO, navigate to your local [Malcolm](https://github.com/idaholab/Malcolm/) working copy and run:

```
$ ./sensor-iso/build_via_vagrant.sh -f
…
Starting build machine...
Bringing machine 'default' up with 'virtualbox' provider...
…
```

Building the ISO may take 90 minutes or more depending on your system. As the build finishes, you will see the following message indicating success:

```
…
Finished, created "/sensor-build/hedgehog-5.2.4.iso"
…
```

Alternately, if you have forked Malcolm on GitHub, [workflow files](../.github/workflows/) are provided which contain instructions for GitHub to build the docker images and Hedgehog and [Malcolm](https://github.com/idaholab/Malcolm) installer ISOs, specifically [`sensor-iso-build-docker-wrap-push-ghcr.yml`](../.github/workflows/sensor-iso-build-docker-wrap-push-ghcr.yml) for the Hedgehog ISO. The resulting ISO file is wrapped in a Docker image that provides an HTTP server from which the ISO may be downloaded.

# <a name="ConfigSSH"></a>Appendix B - Configuring SSH access

SSH access to the sensor's non-privileged sensor account is only available using secure key-based authentication which can be enabled by adding a public SSH key to the **/home/sensor/.ssh/authorized_keys** file as illustrated below:

```
sensor@sensor:~$ mkdir -p ~/.ssh

sensor@sensor:~$ ssh analyst@172.16.10.48 "cat ~/.ssh/id_rsa.pub" >> ~/.ssh/authorized_keys
The authenticity of host '172.16.10.48 (172.16.10.48)' can't be established.
ECDSA key fingerprint is SHA256:...
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.16.10.48' (ECDSA) to the list of known hosts.
analyst@172.16.10.48's password:

sensor@sensor:~$ cat ~/.ssh/authorized_keys
ssh-rsa AAA...kff analyst@SOC
```

SSH access should only be configured when necessary.

# <a name="Troubleshooting"></a>Appendix C - Troubleshooting

Should the sensor not function as expected, first try rebooting the device. If the behavior continues, here are a few things that may help you diagnose the problem (items which may require Linux command line use are marked with **†**)

* Stop / start services – Using the sensor's kiosk mode, attempt a **Services Stop** followed by a **Services Start**, then check **Sensor Status** to see which service(s) may not be running correctly.
* Sensor configuration file – See `/opt/sensor/sensor_ctl/control_vars.conf` for sensor service settings. It is not recommended to manually edit this file unless you are sure of what you are doing.
* Sensor control scripts – There are scripts under ``/opt/sensor/sensor_ctl/`` to control sensor services (eg., `shutdown`, `start`, `status`, `stop`, etc.)
* Sensor debug logs – Log files under `/opt/sensor/sensor_ctl/log/` may contain clues to processes that are not working correctly. If you can determine which service is failing, you can attempt to reconfigure it using the instructions in the Configure Capture and Forwarding section of this document.
* `sensorwatch` script – Running `sensorwatch` on the command line will display the most recently modified PCAP and Zeek log files in their respective directories, how much storage space they are consuming, and the amount of used/free space on the volumes containing those files.

# <a name="Hardening"></a>Appendix D - Hardening

Hedgehog Linux targets the following guidelines for establishing a secure configuration posture:

* DISA STIG (Security Technical Implementation Guides) [ported](https://github.com/hardenedlinux/STIG-4-Debian) from [DISA RHEL 7 STIG](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/) v1r1 to a Debian 9 base platform
* [CIS Debian Linux 9 Benchmark](https://www.cisecurity.org/cis-benchmarks/cis-benchmarks-faq/) with additional recommendations by the [hardenedlinux/harbian-audit](https://github.com/hardenedlinux/harbian-audit) project

## <a name="STIGExceptions"></a>STIG compliance exceptions

[Currently](https://github.com/hardenedlinux/STIG-4-Debian/blob/master/stig-debian.txt) there are 158 compliance checks that can be verified automatically and 23 compliance checks that must be verified manually.

Hedgehog Linux claims the following exceptions to STIG compliance:

| # | ID  | Title | Justification |
| --- | --- | --- | --- |
| 1 | [SV-86535r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-71911) | When passwords are changed a minimum of eight of the total number of characters must be changed. | Account/password policy exception: As a sensor running Hedgehog Linux is intended to be used as an appliance rather than a general user-facing software platform, some exceptions to password enforcement policies are claimed. |
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
| 12 | [SV-86607r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-71983) | USB mass storage must be disabled. | The ability to copy data captured by the sensor to a mounted USB mass storage device is a requirement of the system. |
| 13 | [SV-86609r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-71985) | File system automounter must be disabled unless required. | The ability to copy data captured by the sensor to a mounted USB mass storage device is a requirement of the system. |
| 14 | [SV-86705r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72081) | The operating system must shut down upon audit processing failure, unless availability is an overriding concern. If availability is a concern, the system must alert the designated staff (System Administrator [SA] and Information System Security Officer [ISSO] at a minimum) in the event of an audit processing failure. | As maximizing availability is a system requirement, audit processing failures will be logged on the device rather than halting the system. |
| 15 | [SV-86713r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72089) | The operating system must immediately notify the System Administrator (SA) and Information System Security Officer ISSO (at a minimum) when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity. | As a sensor running Hedgehog Linux is intended to be used as an appliance rather than a general network host, notifications of this sort are sent in system logs forwarded to the OpenSearch database on the aggregator. `auditd` is set up to syslog when this storage volume is reached. |
| 16 | [SV-86715r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-72093) | The operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached. | As a sensor running Hedgehog Linux is intended to be used as an appliance rather than a general network host, notifications of this sort are sent in system logs forwarded to the OpenSearch database on the aggregator. `auditd` is set up to syslog when this storage volume is reached. |
| 17 | [SV-86837r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2016-12-16/finding/V-38666) | The system must use and update a DoD-approved virus scan program. | As this is a network traffic capture appliance rather than an end-user device and will not be internet-connected, regular user files will not be created. A virus scan program would impact device performance and would be unnecessary. |
| 18 | [SV-86839r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72215) | The system must update the virus scan program every seven days or more frequently. | As this is a network traffic capture appliance rather than an end-user device and will not be internet-connected, regular user files will not be created. A virus scan program would impact device performance and would be unnecessary. |
| 19 | [SV-86847r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72223) | All network connections associated with a communication session must be terminated at the end of the session or after 10 minutes of inactivity from the user at a command prompt, except to fulfill documented and validated mission requirements. | The sensor may be controlled from the command line in a manual capture scenario, so timing out a session based on command prompt inactivity would be inadvisable. | 
| 20 | [SV-86893r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72269) | The operating system must, for networked systems, synchronize clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS). | While [time synchronization](#ConfigTime) is supported on Hedgehog Linux, an exception is claimed for this rule as the network sensor device may be configured to sync to servers other than the ones listed in the STIG. |
| 21 | [SV-86905r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72281) | For systems using DNS resolution, at least two name servers must be configured. | STIG recommendations for DNS servers are not enforced on Hedgehog Linux to allow for use in a variety of network scenarios. |
| 22 | [SV-86919r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-72295) | Network interfaces must not be in promiscuous mode. | The purpose of Hedgehog Linux is to sniff and capture network traffic. |
| 23 | [SV-86931r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72307) | An X Windows display manager must not be installed unless approved. | A locked-down X Windows session is required for the sensor's kiosk display. |
| 24 | [SV-86519r3](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-71895) | The operating system must set the idle delay setting for all connection types. | As this is a network traffic capture appliance rather than an end-user device, timing out displays or connections would not be desireable. |
| 25 | [SV-86523r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-71899) | The operating system must initiate a session lock for the screensaver after a period of inactivity for graphical user interfaces. | This option is configurable during install time. Some installations of Hedgehog Linux may be on appliance hardware not equipped with a keyboard by default, in which case it may not be desirable to lock the session.|
| 26 | [SV-86525r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-71901) | The operating system must initiate a session lock for graphical user interfaces when the screensaver is activated. | This option is configurable during install time. Some installations of Hedgehog Linux may be on appliance hardware not equipped with a keyboard by default, in which case it may not be desirable to lock the session. |
| 27 | [SV-86589r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-71965) | The operating system must uniquely identify and must authenticate organizational users (or processes acting on behalf of organizational users) using multifactor authentication. | As this is a network traffic capture appliance rather than an end-user device or a multiuser network host, this requirement is not applicable. |
| 28 | [SV-86851r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72227) | The operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) authentication communications. | Does not apply as Hedgehog Linux does not use LDAP for authentication. |
| 29 | [SV-86921r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-72297) | The system must be configured to prevent unrestricted mail relaying. | Does not apply as Hedgehog Linux does not run a mail service. |
| 30 | [SV-86929r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72305) | If the Trivial File Transfer Protocol (TFTP) server is required, the TFTP daemon must be configured to operate in secure mode. | Does not apply as Hedgehog Linux does not run a TFTP server. |
| 31 | [SV-86935r3](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72311) | The Network File System (NFS) must be configured to use RPCSEC_GSS. | Does not apply as Hedgehog Linux does not run an NFS server. |
| 32 | [SV-87041r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72417) | The operating system must have the required packages for multifactor authentication installed. | As this is a network traffic capture appliance rather than an end-user device or a multiuser network host, this requirement is not applicable. |
| 33 | [SV-87051r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-72427) | The operating system must implement multifactor authentication for access to privileged accounts via pluggable authentication modules (PAM). | As this is a network traffic capture appliance rather than an end-user device or a multiuser network host, this requirement is not applicable. |
| 34 | [SV-87059r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-72435) | The operating system must implement smart card logons for multifactor authentication for access to privileged accounts. | As this is a network traffic capture appliance rather than an end-user device or a multiuser network host, this requirement is not applicable. |
| 35 | [SV-87829r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-73177) | Wireless network adapters must be disabled. | As an appliance intended to capture network traffic in a variety of network environments, wireless adapters may be needed to capture and/or report wireless traffic. |
| 36 | [SV-86699r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72075) | The system must not allow removable media to be used as the boot loader unless approved. | Hedgehog Linux supports a live boot mode that can be booted from removable media. |

Please review the notes for these additional rules. While not claiming an exception, they may be implemented or checked in a different way than outlined by the RHEL STIG as Hedgehog Linux is not built on RHEL or for other reasons.

| # | ID  | Title | Note |
| --- | --- | --- | --- |
| 1 | [SV-86585r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-71961) | Systems with a Basic Input/Output System (BIOS) must require authentication upon booting into single-user and maintenance modes. | Although the [compliance check script](https://github.com/hardenedlinux/STIG-4-Debian) does not detect it, booting into recovery mode *does* in fact require the root password. |
| 2 | [SV-86587r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-71963) | Systems using Unified Extensible Firmware Interface (UEFI) must require authentication upon booting into single-user and maintenance modes. | Although the [compliance check script](https://github.com/hardenedlinux/STIG-4-Debian) does not detect it, booting into recovery mode *does* in fact require the root password. |
| 3 | [SV-86651r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72027) | All files and directories contained in local interactive user home directories must have mode 0750 or less permissive. | Depending on when the [compliance check script](https://github.com/hardenedlinux/STIG-4-Debian) is run, some nonessential ephemeral files may exist in the `sensor` home directory which will cause this check to fail. For practical purposes Hedgehog Linux's configuration does, however, comply. This file list can be checked manually by running `find /home/sensor -type f -perm /027 -exec ls -l '{}' ';'`.|
| 4 | [SV-86693r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72069) | The file integrity tool must be configured to verify Access Control Lists (ACLs). | [Auditbeat](https://www.elastic.co/products/beats/auditbeat) is managing file integrity checks instead of the `aide` specified for use in the RHEL STIG. Additionally, as this is not a multi-user system, the ACL check would be irrelevant. |
| 5 | [SV-86597r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-71973) | A file integrity tool must verify the baseline operating system configuration at least weekly. | [Auditbeat](https://www.elastic.co/products/beats/auditbeat) is managing file integrity checks instead of the `aide` specified for use in the RHEL STIG. |
| 6 | [SV-86697r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-72073) | The file integrity tool must use FIPS 140-2 approved cryptographic hashes for validating file contents and directories. | [Auditbeat](https://www.elastic.co/products/beats/auditbeat) is managing file integrity checks instead of the `aide` specified for use in the RHEL STIG. Auditbeat uses SHA1 which is FIPS 140-2 approved. |
| 7 | [SV-86623r3](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-71999) | Vendor packaged system security patches and updates must be installed and up to date. | When the Hedgehog Linux sensor appliance software is built, all of the latest applicable security patches and updates are included in it. How future updates are to be handled is still in design. |
| 8 | [SV-86707r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-72083) | The operating system must off-load audit records onto a different system or media from the system being audited. | [Auditbeat](https://www.elastic.co/products/beats/auditbeat) offloads audit records to an OpenSearch database on another system, though this is not detected by the [compliance check script](https://github.com/hardenedlinux/STIG-4-Debian). |
| 9 | [SV-86709r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-72085) | The operating system must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited. | [Auditbeat](https://www.elastic.co/products/beats/auditbeat) offloads (via an encrypted channel) audit records to an OpenSearch database on another system, though this is not detected by the [compliance check script](https://github.com/hardenedlinux/STIG-4-Debian). |
| 10 | [SV-86833r1](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-72209) | The system must send rsyslog output to a log aggregation server. | Syslogs are forwarded to an OpenSearch database running on another system via [filebeat](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-syslog.html), though this is not detected by the [compliance check script](https://github.com/hardenedlinux/STIG-4-Debian). |
| 11 | [SV-87815r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-12-14/finding/V-73163) | The audit system must take appropriate action when there is an error sending audit records to a remote system. | [Auditbeat](https://www.elastic.co/products/beats/auditbeat) offloads audit records to an OpenSearch database on another system, though this is not detected by the [compliance check script](https://github.com/hardenedlinux/STIG-4-Debian). Local logs are generated when this network connection is broken, and it resumes automatically. |
| 12 | [SV-86691r2](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/2017-07-08/finding/V-72067) | The operating system must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards. | Hedgehog Linux does use FIPS-compatible libraries for cryptographic functions. However, the kernel parameter being checked by the [compliance check script](https://github.com/hardenedlinux/STIG-4-Debian) is incompatible with some of the systems initialization scripts.|

In addition, DISA STIG rules SV-86663r1, SV-86695r2, SV-86759r3, SV-86761r3, SV-86763r3, SV-86765r3, SV-86595r1, and SV-86615r2 relate to the SELinux kernel which is not used in Hedgehog Linux, and are thus skipped.

## <a name="CISExceptions"></a>CIS benchmark compliance exceptions

[Currently](https://github.com/hardenedlinux/harbian-audit/tree/master/bin/hardening) there are 271 checks to determine compliance with the CIS Debian Linux 9 Benchmark.

Hedgehog Linux claims exceptions from the recommendations in this benchmark in the following categories:

**1.1 Install Updates, Patches and Additional Security Software** - When the Hedgehog Linux sensor appliance software is built, all of the latest applicable security patches and updates are included in it. How future updates are to be handled is still in design.

**1.3 Enable verify the signature of local packages** - As the base distribution is not using embedded signatures, `debsig-verify` would reject all packages (see comment in `/etc/dpkg/dpkg.cfg`). Enabling it after installation would disallow any future updates.

**2.14 Add nodev option to /run/shm Partition**, **2.15 Add nosuid Option to /run/shm Partition**, **2.16 Add noexec Option to /run/shm Partition** - Hedgehog Linux does not mount `/run/shm` as a separate partition, so these recommendations do not apply.

**2.18 Disable Mounting of cramfs Filesystems**, **2.19 Disable Mounting of freevxfs Filesystems**, **2.20 Disable Mounting of jffs2 Filesystems**, **2.21 Disable Mounting of hfs Filesystems**, **2.22 Disable Mounting of hfsplus Filesystems**, **2.23 Disable Mounting of squashfs Filesystems**, **2.24 Disable Mounting of udf Filesystems** - Hedgehog Linux is not compiling a custom Linux kernel, so these filesystems are inherently supported as they are part Debian Linux's default kernel.

**4.6 Disable USB Devices** - The ability to copy data captured by the sensor to a mounted USB mass storage device is a requirement of the system.

**6.1 Ensure the X Window system is not installed**, **6.2 Ensure Avahi Server is not enabled**, **6.3 Ensure print server is not enabled** - A locked-down X Windows session is required for the sensor's kiosk display. The library packages `libavahi-common-data`, `libavahi-common3`, and `libcups2` are dependencies of some of the X components used by Hedgehog Linux, but the `avahi` and `cups` services themselves are disabled.

**6.17 Ensure virus scan Server is enabled**, **6.18 Ensure virus scan Server update is enabled** - As this is a network traffic capture appliance rather than an end-user device and will not be internet-connected, regular user files will not be created. A virus scan program would impact device performance and would be unnecessary.

**7.2.4 Log Suspicious Packets**, **7.2.7 Enable RFC-recommended Source Route Validation**, **7.4.1 Install TCP Wrappers** - As this is a network traffic capture appliance sniffing packets on a network interface configured in promiscuous mode, these recommendations do not apply.

Password-related recommendations under **9.2** and **10.1** - The library package `libpam-pwquality` is used in favor of `libpam-cracklib` which is what the [compliance scripts](https://github.com/hardenedlinux/harbian-audit/tree/master/bin/hardening) are looking for. Also, as a sensor running Hedgehog Linux is intended to be used as an appliance rather than a general user-facing software platform, some exceptions to password enforcement policies are claimed.

**9.3.13 Limit Access via SSH** - Hedgehog Linux does not create multiple regular user accounts: only `root` and a `sensor` service account are used. SSH access for `root` is disabled. SSH login with a password is also disallowed: only key-based authentication is accepted. The `sensor` service account accepts no keys by default. As such, the `AllowUsers`, `AllowGroups`, `DenyUsers`, and `DenyGroups` values in `sshd_config` do not apply.

**9.5 Restrict Access to the su Command** - Hedgehog Linux does not create multiple regular user accounts: only `root` and a `sensor` service account are used.

**10.1.10 Set maxlogins for all accounts** and **10.5 Set Timeout on ttys** - Hedgehog Linux does not create multiple regular user accounts: only `root` and a `sensor` service account are used.

**12.10 Find SUID System Executables**, **12.11 Find SGID System Executables** - The few files found by [these](https://github.com/hardenedlinux/harbian-audit/blob/master/bin/hardening/12.10_find_suid_files.sh) [scripts](https://github.com/hardenedlinux/harbian-audit/blob/master/bin/hardening/12.11_find_sgid_files.sh) are valid exceptions required by Hedgehog Linux's system requirements.

Please review the notes for these additional guidelines. While not claiming an exception, Hedgehog Linux may implement them in a manner different than is described by the [CIS Debian Linux 9 Benchmark](https://www.cisecurity.org/cis-benchmarks/cis-benchmarks-faq/) or the [hardenedlinux/harbian-audit](https://github.com/hardenedlinux/harbian-audit) audit scripts.

**4.1 Restrict Core Dumps** - Hedgehog Linux disables core dumps using a configuration file for `ulimit` named `/etc/security/limits.d/limits.conf`. The [audit script](https://github.com/hardenedlinux/harbian-audit/blob/master/bin/hardening/4.1_restrict_core_dumps.sh) checking for this does not check the `limits.d` subdirectory, which is why this is incorrectly flagged as noncompliant.

**5.4 Ensure ctrl-alt-del is disabled** - Hedgehog Linux disables the `ctrl+alt+delete` key sequence by executing `systemctl disable ctrl-alt-del.target` during installation and the command `systemctl mask ctrl-alt-del.target` at boot time.

**6.19 Configure Network Time Protocol (NTP)** - While [time synchronization](#ConfigTime) is supported on Hedgehog Linux, an exception is claimed for this rule as the network sensor device may be configured to sync to servers in a different way than specified in the benchmark.

**7.4.4 Create /etc/hosts.deny**, **7.7.1 Ensure Firewall is active**, **7.7.4.1 Ensure default deny firewall policy**, **7.7.4.3 Ensure default deny firewall policy**, **7.7.4.4 Ensure outbound and established connections are configured** - Hedgehog Linux **is** configured with an appropriately locked-down software firewall (managed by "Uncomplicated Firewall" `ufw`). However, the methods outlined in the CIS benchmark recommendations do not account for this configuration. 

**8.1.1.2 Disable System on Audit Log Full**, **8.1.1.3 Keep All Auditing Information**, **8.1.1.5 Ensure set remote server for audit service**, **8.1.1.6 Ensure enable_krb5 set to yes for remote audit service**, **8.1.1.7 Ensure set action for audit storage volume is fulled**, **8.1.1.9 Set space left for auditd service**, a few other audit-related items under section **8.1**, **8.2.5 Configure rsyslog to Send Logs to a Remote Log Host** - As maximizing availability is a system requirement, audit processing failures will be logged on the device rather than halting the system. Because Hedgehog Linux is intended to be used as an appliance rather than a general network host, notifications about its status are sent in system logs forwarded to the OpenSearch database on the aggregator. `auditd` is set up to syslog when this storage volume is reached. [Auditbeat](https://www.elastic.co/products/beats/auditbeat) offloads audit records to an OpenSearch database on another system, though this is not detected by the [CIS benchmark compliance scripts](https://github.com/hardenedlinux/harbian-audit/tree/master/bin/hardening). Local logs are generated when the network connection is broken, and it resumes automatically. Syslog messages are also similarly forwarded.

**8.4.1 Install aide package** and **8.4.2 Implement Periodic Execution of File Integrity** - [Auditbeat](https://www.elastic.co/products/beats/auditbeat) is managing file integrity checks instead of the `aide` utility.

**8.7 Verifies integrity all packages** - The [script](https://github.com/hardenedlinux/harbian-audit/blob/master/bin/hardening/8.7_verify_integrity_packages.sh) which verifies package integrity only "fails" because of missing (status `??5??????` displayed by the utility) language ("locale") files, which are removed as part of Hedgehog Linux's trimming-down process. All non-locale-related system files pass intergrity checks.

# <a name="UpgradePlan"></a>Appendix E - Upgrades

At this time there is not an "official" upgrade procedure to get from one release of Hedgehog Linux to the next. Upgrading the underlying operating system packages is generally straightforward, but not all of the Hedgehog Linux components are packaged into .deb archives yet as they should be, so for now it's a manual (and kind of nasty) process to Frankenstein an upgrade into existance. The author of this project intends to remedy this at some future point when time and resources allow.

If possible, it would save you **a lot** of trouble to just [re-ISO](#Installation) your Hedgehog installation and start fresh, backing up the files (in `/opt/sensor/sensor_ctl`) first and reconfiguring or restoring them as needed afterwards. 

However, if reinstalling the system is not an option, here is the basic process for doing a manual upgrade of Hedgehog Linux. It should be understood that this process is very likely to break your system, and there is **no** guarantee of any kind that any of this will work, or that these instructions are even complete or any support whatsoever regarding them. Really, it will be **much** easier if you re-ISO your installation. But for the brave among you, here you go. ⛔🆘😭💀

## Prerequisites

* A good understanding of the Linux command line
* An existing installation of Hedgehog Linux **with internet access**
* A copy of the Hedgehog Linux [ISO](#ISOBuild) for the version approximating the one you're upgrading to (i.e., the latest version), **and**
    - Either a separate VM with that ISO installed **OR**
    - A separate Linux workstation where you can manually mount that ISO to pull stuff off of it

## Upgrade

1. Obtain a root shell
    - `su -`
    
2. Temporarily set the umask value to Debian default instead of the more restrictive Hedgehog Linux default. This will allow updates to be applied with the right permissions.
    - `umask 0022` 

3. Create backups of some files
    - `cp /etc/apt/sources.list /etc/apt/sources.list.bak`

4. Set up alternate package sources, if needed
    - In an offline/airgapped scenario, you could use [apt-mirror](https://apt-mirror.github.io) to mirror Debian repos and [bandersnatch](https://github.com/pypa/bandersnatch/) to mirror PyPI sources, or [combine them](https://github.com/mmguero/espejo) with Docker. If you were to do this, you'd probably want to make the following changes (and **revert them after the upgrade**):        
        + create `/etc/apt/apt.conf.d/80ssl-exceptions` to ignore self-signed certificate warnings from using your apt-mirror
```
Acquire::https {
  Verify-Peer "false";
  Verify-Host "false";
}
```
        
        + modify `/etc/apt/source.list` to point to your apt-mirror:

```
deb https://XXXXXX:443/debian buster main contrib non-free
deb https://XXXXXX:443/debian-security buster/updates main contrib non-free
deb https://XXXXXX:443/debian buster-updates main contrib non-free
deb https://XXXXXX:443/debian buster-backports main contrib non-free
```

5. Update underlying system packages with `apt-get`
    - `apt-get update && apt-get dist-upgrade`

6. If there were [new system deb packages added](https://github.com/idaholab/Malcolm/tree/main/sensor-iso/config/package-lists) to this release of Hedgehog Linux (you might have to [manually compare](https://github.com/idaholab/Malcolm/commits/main/sensor-iso/config/package-lists) on GitHub), install them. If you're not sure, of course, you could just install everything, like this (although you may have to tweak some version numbers or something if the base distribution of your Hedgehog branch is different than `main`; in this example I'm not jumping between Debian releases, just upgrading within a release):
```
$ for LIST in apps desktopmanager net system; do curl -L -J -O https://raw.github.com/idaholab/Malcolm/main/sensor-iso/config/package-lists/$LIST.list.chroot; done
...
$ apt-get install $(cat *.list.chroot)
```

7. Update underlying python packages with `python3 -m pip`
    * `apt-get install -y build-essential git-core pkg-config python3-dev`
    * `python3 -m pip list --outdated --format=freeze | grep -v '^\-e' | cut -d = -f 1 | xargs -r -n1 python3 -m pip install -U`
        - if this fails for some reason, you may need to reinstall pip first with `python3 -m pip install --force -U pip`
        - some *very* old builds of Hedgehog Linux had separate Python 3.5 and 3.7 installations: in this case, you'd need to do this for both `python3 -m pip` and `python3.7 -m pip` (or whatever `python3.x` you have)
    * If there were [new python packages](https://raw.githubusercontent.com/idaholab/Malcolm/master/sensor-iso/config/hooks/normal/0169-pip-installs.hook.chroot) added to this release of Hedgehog Linux (you might have to [manually compare](https://github.com/idaholab/Malcolm/blame/main/sensor-iso/config/hooks/normal/0169-pip-installs.hook.chroot) on GitHub), install them. If you are using a PyPI mirror, replace `XXXXXX` here with your mirror's IP. The `colorama` package is used here as an example, your package list might vary.
        - `python3 -m pip install --no-compile --no-cache-dir --force-reinstall --upgrade --index-url=https://XXXXXX:443/pypi/simple --trusted-host=XXXXXX:443 colorama`

8. Okay, **now** things start to get a little bit ugly. You're going to need access to the ISO of the release of Hedgehog Linux you're upgrading to, as we're going to grab some packages off of it. On another Linux system, [build it](#ISOBuild).

9. Use a disk image mounter to mount the ISO, **or** if you want to just install the ISO in a VM and grab the files we need off of it, that's fine too. But I'll go through the example as if I've mounted the ISO.

10. Navigate to the `/live/` directory, and mount the `filesystem.squashfs` file
    - `sudo mount filesystem.squashfs /media/squash -t squashfs -o loop`
    - **OR**
    - `squashfuse filesystem.squashfs /home/user/media/squash`

11. Very recent builds of Hedgehog Linux keep some build artifacts in `/opt/hedgehog_install_artifacts/`. You're going to want to grab those files and throw them in a temporary directory on the system you're upgrading, via SSH or whatever means you devise.
```
root@hedgehog:/tmp# scp -r user@otherbox:/media/squash/opt/hedgehog_install_artifacts/ ./
user@otherbox's password: 
auditbeat-tweaked-7.6.2-amd64.deb                                               100%   13MB  49.3MB/s   00:00    
filebeat-tweaked-7.6.2-amd64.deb                                                100%   13MB  65.9MB/s   00:00    
metricbeat-tweaked-7.6.2-amd64.deb                                              100%   18MB  72.0MB/s   00:00    
arkime_2.2.3-1_amd64.deb                                                        100%  113MB  32.2MB/s   00:03    
netsniff-ng_0.6.6-1_amd64.deb                                                   100%  330KB  52.1MB/s   00:00    
packetbeat-tweaked-7.6.2-amd64.deb                                              100%   14MB  59.2MB/s   00:00    
protologbeat                                                                    100%   56MB  38.1MB/s   00:01    
zeek_3.0.20-1_amd64.deb                                                          100%   26MB  63.1MB/s   00:00
```

12. Replace the old `/usr/local/bin/protologbeat` with the new one:
```
root@hedgehog:/tmp# cp -biv hedgehog_install_artifacts/protologbeat /usr/local/bin/protologbeat 
cp: overwrite '/usr/local/bin/protologbeat'? y
'hedgehog_install_artifacts/protologbeat' -> '/usr/local/bin/protologbeat' (backup: '/usr/local/bin/protologbeat~')

root@hedgehog:/tmp# ls -l /usr/local/bin/protologbeat
-rwxr-xr-x 1 root root 58895456 May  8 15:45 /usr/local/bin/protologbeat

root@hedgehog:/tmp# /usr/local/bin/protologbeat version
protologbeat version 7.6.0 (amd64), libbeat 7.6.0 [unknown built unknown]
```

13. Blow away the old `zeek` package, we're going to start clean with that one particularly. The others should be fine to upgrade in place.
```
root@hedgehog:/opt# apt-get --purge remove zeek
Reading package lists... Done
Building dependency tree       
Reading state information... Done
The following packages will be REMOVED:
  zeek*
0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.
After this operation, 160 MB disk space will be freed.
Do you want to continue? [Y/n] y
(Reading database ... 118490 files and directories currently installed.)
Removing zeek (3.0.20-1) ...
dpkg: warning: while removing zeek, directory '/opt/zeek/spool' not empty so not removed
dpkg: warning: while removing zeek, directory '/opt/zeek/share/zeek/site' not empty so not removed
dpkg: warning: while removing zeek, directory '/opt/zeek/lib' not empty so not removed
dpkg: warning: while removing zeek, directory '/opt/zeek/bin' not empty so not removed
root@hedgehog:/opt# rm -rf /opt/zeek*
```

14. Install the new .deb files. You're going to have some warnings, but that's okay.
```
root@hedgehog:/tmp# dpkg -i hedgehog_install_artifacts/*.deb
(Reading database ... 118149 files and directories currently installed.)
Preparing to unpack .../auditbeat-tweaked-7.6.2-amd64.deb ...
Unpacking auditbeat (7.6.2) over (6.8.4) ...
dpkg: warning: unable to delete old directory '/usr/share/auditbeat/kibana/6/dashboard': Directory not empty
dpkg: warning: unable to delete old directory '/usr/share/auditbeat/kibana/6': Directory not empty
Preparing to unpack .../filebeat-tweaked-7.6.2-amd64.deb ...
Unpacking filebeat (7.6.2) over (6.8.4) ...
dpkg: warning: unable to delete old directory '/usr/share/filebeat/kibana/6/dashboard': Directory not empty
dpkg: warning: unable to delete old directory '/usr/share/filebeat/kibana/6': Directory not empty
Preparing to unpack .../metricbeat-tweaked-7.6.2-amd64.deb ...
Unpacking metricbeat (7.6.2) over (6.8.4) ...
Preparing to unpack .../arkime_2.2.3-1_amd64.deb ...
Unpacking arkime (2.2.3-1) over (2.0.1-1) ...
Preparing to unpack .../netsniff-ng_0.6.6-1_amd64.deb ...
Unpacking netsniff-ng (0.6.6-1) over (0.6.6-1) ...
Preparing to unpack .../packetbeat-tweaked-7.6.2-amd64.deb ...
Unpacking packetbeat (7.6.2) over (6.8.4) ...
Preparing to unpack .../zeek_3.0.20-1_amd64.deb ...
Unpacking zeek (3.0.20-1) over (3.0.0-1) ...
Setting up auditbeat (7.6.2) ...
Installing new version of [...]
[...]
Setting up filebeat (7.6.2) ...
Installing new version of [...]
[...]
Setting up metricbeat (7.6.2) ...
Installing new version of [...]
[...]
Setting up arkime (2.2.3-1) ...
READ /opt/arkime/README.txt and RUN /opt/arkime/bin/Configure
Setting up netsniff-ng (0.6.6-1) ...
Setting up packetbeat (7.6.2) ...
Installing new version of [...]
[...]
Setting up zeek (3.0.20-1) ...
Processing triggers for systemd (232-25+deb9u12) ...
Processing triggers for man-db (2.7.6.1-2) ...
```

15. Fix anything that might need fixing as far as the deb package requirements go
    - `apt-get -f install`

16. We just installed a Zeek .deb, but the third-part plugins packages and local config weren't part of that package. So we're going to `rsync` those from the other box where we have the ISO and `filesystem.squashfs` mounted as well:
```
root@hedgehog:/tmp# rsync -a user@otherbox:/media/squash/opt/zeek/ /opt/zeek 
user@otherbox's password: 

root@hedgehog:/tmp# ls -l /opt/zeek/share/zeek/site/
total 52
lrwxrwxrwx  1 root root    13 May  6 21:52 bzar -> packages/bzar
lrwxrwxrwx  1 root root    22 May  6 21:50 cve-2020-0601 -> packages/cve-2020-0601
-rw-r--r--  1 root root  2031 Apr 30 16:02 extractor.zeek
-rw-r--r--  1 root root 39134 May  1 14:20 extractor_params.zeek
lrwxrwxrwx  1 root root    14 May  6 21:52 hassh -> packages/hassh
lrwxrwxrwx  1 root root    12 May  6 21:52 ja3 -> packages/ja3
-rw-rw-r--  1 root root  2005 May  6 21:54 local.zeek
drwxr-xr-x 13 root root  4096 May  6 21:52 packages
lrwxrwxrwx  1 root root    27 May  6 21:52 zeek-EternalSafety -> packages/zeek-EternalSafety
lrwxrwxrwx  1 root root    26 May  6 21:52 zeek-community-id -> packages/zeek-community-id
lrwxrwxrwx  1 root root    27 May  6 21:51 zeek-plugin-bacnet -> packages/zeek-plugin-bacnet
lrwxrwxrwx  1 root root    25 May  6 21:51 zeek-plugin-enip -> packages/zeek-plugin-enip
lrwxrwxrwx  1 root root    29 May  6 21:51 zeek-plugin-profinet -> packages/zeek-plugin-profinet
lrwxrwxrwx  1 root root    27 May  6 21:52 zeek-plugin-s7comm -> packages/zeek-plugin-s7comm
lrwxrwxrwx  1 root root    24 May  6 21:52 zeek-plugin-tds -> packages/zeek-plugin-tds
```

17. The `zeekctl` component of zeek doesn't like being run by an unprivileged user unless the whole directory is owned by that user. As Hedgehog Linux runs everything it can as an unprivileged user, we're going to reset zeek to a "clean" state after each reboot. Zeek's config files will get regenerated when Zeek itself is started. So, now make a complete backup of `/opt/zeek` as it's going to have its ownership changed during runtime:
```
root@hedgehog:/tmp# rsync -a /opt/zeek/ /opt/zeek.orig

root@hedgehog:/tmp# chown -R sensor:sensor /opt/zeek/*

root@hedgehog:/tmp# chown -R root:root /opt/zeek.orig/*

root@hedgehog:/tmp# ls -l /opt/ | grep zeek
drwxr-xr-x  8 root   root    4096 May  8 15:48 zeek
drwxr-xr-x  8 root   root    4096 May  8 15:48 zeek.orig
```

18. Grab other new scripts and stuff from our mount of the ISO using `rsync`:
```
root@hedgehog:/tmp# rsync -a user@otherbox:/media/squash/usr/local/bin/ /usr/local/bin
user@otherbox's password: 

root@hedgehog:/tmp# ls -l /usr/local/bin/ | tail
lrwxrwxrwx 1 root root        18 May  8 14:34 zeek -> /opt/zeek/bin/zeek
-rwxr-xr-x 1 root staff    10349 Oct 29  2019 zeek_carve_logger.py
-rwxr-xr-x 1 root staff    10467 Oct 29  2019 zeek_carve_scanner.py
-rw-r--r-- 1 root staff    25756 Oct 29  2019 zeek_carve_utils.py
-rwxr-xr-x 1 root staff     8787 Oct 29  2019 zeek_carve_watcher.py
-rwxr-xr-x 1 root staff     4883 May  4 17:39 zeek_install_plugins.sh

root@hedgehog:/tmp# rsync -a user@otherbox:/media/squash/opt/yara-rules/ /opt/yara-rules
user@otherbox's password: 

root@hedgehog:/tmp# rsync -a user@otherbox:/media/squash/opt/capa-rules/ /opt/capa-rules
user@otherbox's password: 

root@hedgehog:/tmp# ls -l /opt/ | grep '\-rules'
drwxr-xr-x  8 root   root    4096 May  8 15:48 capa-rules
drwxr-xr-x  8 root   root  24576  May  8 15:48 yara-rules

root@hedgehog:/tmp# for BEAT in auditbeat filebeat metricbeat packetbeat protologbeat; do rsync -a user@otherbox:/media/squash/usr/share/$BEAT/kibana/ /usr/share/$BEAT/kibana; done
user@otherbox's password: 
user@otherbox's password: 
user@otherbox's password: 
user@otherbox's password: 
user@otherbox's password: 

root@hedgehog:/tmp# rsync -avP --delete user@otherbox:/media/squash/etc/audit/rules.d/ /etc/audit/rules.d/
user@otherbox's password: 

root@hedgehog:/tmp# rsync -avP --delete user@otherbox:/media/squash/etc/sudoers.d/ /etc/sudoers.d/
user@otherbox's password: 

root@hedgehog:/tmp# chmod 400 /etc/sudoers.d/*
```

19. Set capabilities and symlinks for network capture programs to be used by the unprivileged user:

commands:

```
chown root:netdev /usr/sbin/netsniff-ng && \
  setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip CAP_SYS_ADMIN+eip' /usr/sbin/netsniff-ng
chown root:netdev /opt/zeek/bin/zeek && \
  setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip' /opt/zeek/bin/zeek
chown root:netdev /sbin/ethtool && \
  setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /sbin/ethtool
chown root:netdev /opt/zeek/bin/capstats && \
  setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /opt/zeek/bin/capstats
chown root:netdev /usr/bin/tcpdump && \
  setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/tcpdump
chown root:netdev /usr/share/auditbeat/bin/auditbeat && \
  setcap 'CAP_AUDIT_READ+eip' /usr/share/auditbeat/bin/auditbeat
chown root:netdev /usr/share/packetbeat/bin/packetbeat && \
  setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/share/packetbeat/bin/packetbeat
chown root:netdev /opt/arkime/bin/capture && \
  setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip' /opt/arkime/bin/capture

ln -s -f /opt/zeek/bin/zeek /usr/local/bin/
ln -s -f /usr/sbin/netsniff-ng /usr/local/bin/
ln -s -f /usr/bin/tcpdump /usr/local/bin/
ln -s -f /opt/arkime/bin/capture /usr/local/bin/
ln -s -f /opt/arkime/bin/npm /usr/local/bin
ln -s -f /opt/arkime/bin/node /usr/local/bin
ln -s -f /opt/arkime/bin/npx /usr/local/bin
```

example:

```
root@hedgehog:/tmp# chown root:netdev /usr/sbin/netsniff-ng && \
>   setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip CAP_SYS_ADMIN+eip' /usr/sbin/netsniff-ng
root@hedgehog:/tmp# chown root:netdev /opt/zeek/bin/zeek && \
>   setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip' /opt/zeek/bin/zeek
root@hedgehog:/tmp# chown root:netdev /sbin/ethtool && \
>   setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /sbin/ethtool
root@hedgehog:/tmp# chown root:netdev /opt/zeek/bin/capstats && \
>   setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /opt/zeek/bin/capstats
root@hedgehog:/tmp# chown root:netdev /usr/bin/tcpdump && \
>   setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/tcpdump
root@hedgehog:/tmp# chown root:netdev /usr/share/auditbeat/bin/auditbeat && \
>   setcap 'CAP_AUDIT_READ+eip' /usr/share/auditbeat/bin/auditbeat
root@hedgehog:/tmp# chown root:netdev /usr/share/packetbeat/bin/packetbeat && \
>   setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/share/packetbeat/bin/packetbeat
root@hedgehog:/tmp# chown root:netdev /opt/arkime/bin/capture && \
>   setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip' /opt/arkime/bin/capture
root@hedgehog:/tmp# ln -s -f /opt/zeek/bin/zeek /usr/local/bin/
root@hedgehog:/tmp# ln -s -f /usr/sbin/netsniff-ng /usr/local/bin/
root@hedgehog:/tmp# ln -s -f /usr/bin/tcpdump /usr/local/bin/
root@hedgehog:/tmp# ln -s -f /opt/arkime/bin/capture /usr/local/bin/
root@hedgehog:/tmp# ln -s -f /opt/arkime/bin/npm /usr/local/bin
root@hedgehog:/tmp# ln -s -f /opt/arkime/bin/node /usr/local/bin
root@hedgehog:/tmp# ln -s -f /opt/arkime/bin/npx /usr/local/bin
```

20. Back up unprivileged user sensor-specific config and scripts:
    - `mv /opt/sensor/ /opt/sensor_upgrade_backup_$(date +%Y-%m-%d)`

21. Grab unprivileged user sensor-specific config and scripts from our mount of the ISO using `rsync` and change its ownership to the unprivileged user:
```
root@hedgehog:/tmp# rsync -av user@otherbox:/media/squash/opt/sensor /opt/
user@otherbox's password: 
receiving incremental file list
created directory ./opt
sensor/
[...]

sent 1,244 bytes  received 1,646,409 bytes  470,758.00 bytes/sec
total size is 1,641,629  speedup is 1.00

root@hedgehog:/tmp# chown -R sensor:sensor /opt/sensor*

root@hedgehog:/tmp# ls -l /opt/ | grep sensor
drwxr-xr-x  4 sensor sensor  4096 May  6 22:00 sensor
drwxr-x---  4 sensor sensor  4096 May  8 14:33 sensor_upgrade_backup_2020-05-08
```

22. Leave the root shell and `cd` to `/opt`
```
root@hedgehog:~# exit
logout

sensor@hedgehog:~$ whoami
sensor

sensor@hedgehog:~$ cd /opt
```

23. Compare the old and new `control_vars.conf` files
```
sensor@hedgehog:opt$ diff sensor_upgrade_backup_2020-05-08/sensor_ctl/control_vars.conf sensor/sensor_ctl/control_vars.conf 
1,2c1,2
< export CAPTURE_INTERFACE=enp0s3
< export CAPTURE_FILTER="not port 5044 and not port 5601 and not port 8005 and not port 9200 and not port 9600"
---
> export CAPTURE_INTERFACE=xxxx
> export CAPTURE_FILTER=""
4c4
[...]
```

Examine the differences. If there aren't any new `export` variables, then you're probably safe to just replace the default version of `control_vars.conf` with the backed-up version:

```
sensor@hedgehog:opt$ cp sensor_upgrade_backup_2020-05-08/sensor_ctl/control_vars.conf sensor/sensor_ctl/control_vars.conf 
cp: overwrite 'sensor/sensor_ctl/control_vars.conf'? y
```

If there are major differences or new variables, continue on to the next step, in a minute you'll need to run `capture-config` to configure from scratch anyway.

24. Restore certificates/keystores for forwarders from the backup `sensor_ctl` path to the new one
```
sensor@hedgehog:opt$ for BEAT in auditbeat filebeat filebeat-syslog heatbeat metricbeat; do cp /opt/sensor_upgrade_backup_2020-05-08/sensor_ctl/$BEAT/data/* /opt/sensor/sensor_ctl/$BEAT/data/; done

sensor@hedgehog:opt$ cp /opt/sensor_upgrade_backup_2020-05-07/sensor_ctl/filebeat/{ca.crt,client.crt,client.key} /opt/sensor/sensor_ctl/filebeat/
```

25. Despite what we just did, you may consider running `capture-config` to re-configure [capture, forwarding, and autostart services](#ConfigUser) from scratch anyway. You can use the backed-up version of `control_vars.conf` to refer back to as a basis for things you might want to restore (e.g., `CAPTURE_INTERFACE`, `CAPTURE_FILTER`, `PCAP_PATH`, `ZEEK_LOG_PATH`, your autostart settings, etc.).

26. Once you feel confident you've completed all of these steps, issue a reboot on the Hedgehog

## Post-upgrade

Once the Hedgehog has come back up, check to make sure everything is working:

* `/opt/sensor/sensor_ctl/status` should return `RUNNING` for the things you set to autorun (no `FATAL` errors)
* `sensorwatch` should show current writes to Zeek log files and PCAP files (depending on your configuration)
* `tail -f /opt/sensor/sensor_ctl/log/*` should show no egregious errors
* `zeek --version`, `zeek -N local` and `capture --version` ought to run and print out version information as expected
* if you are forwarding to a [Malcolm](https://github.com/idaholab/Malcolm) aggregator, you should start seeing data momentarily
    
# <a name="Footer"></a>Copyright

Hedgehog Linux - part of [Malcolm](https://github.com/idaholab/Malcolm) - is Copyright 2022 Battelle Energy Alliance, LLC, and is developed and released through the cooperation of the Cybersecurity and Infrastructure Security Agency of the U.S. Department of Homeland Security.

See [`License.txt`](https://raw.githubusercontent.com/idaholab/Malcolm/main/License.txt) for the terms of its release.

### Contact information of author(s):

[malcolm@inl.gov](mailto:malcolm@inl.gov?subject=Network%20sensor%20development)
