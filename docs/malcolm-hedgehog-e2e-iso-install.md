# <a name="InstallationExample"></a> End-to-end Malcolm and Hedgehog Linux ISO Installation

This document outlines how to install [Malcolm]({{ site.github.repository_url }}) and [Hedgehog Linux](hedgehog.md) using the project's installer ISOs. These instructions apply to installing this software both on a "bare metal" system or in a virtual machine environment using VMware, VirtualBox, QEMU/KVM, etc.

The Malcolm and Hedgehog Linux installers as described in these instructions are intended to be used to **replace** the existing operating system, if any, of the respective systems onto which they are installed, and, as such, are designed to require as little user input as possible. For this reason, there are NO user prompts and confirmations about partitioning and reformatting hard disks for use by the operating system. The installer assumes that all non-removable storage media (eg., SSD, HDD, NVMe, etc.) are available for use and ⛔🆘😭💀 ***will partition and format them without warning*** 💀😭🆘⛔.

In contrast to using the ISO installer, Malcolm can also be installed "natively" on any x86_64 platform that can run Docker. See the [installation example using Ubuntu 22.04 LTS](ubuntu-install-example.md#InstallationExample) for that method of installation and configuration.

### <a name="TableOfContents"></a> Table of Contents

* [Obtaining the Installation ISOs](#ISODownload)
* ["Burning" the Installation ISOs to USB Flash Drive](#ISOBurning)
* [Booting the Installation Media](#BootUSB)
* [Malcolm Installation and Configuration](#MalcolmInstallAndConfig)
    - [ISO Installation](#ISOInstallMalcolm)
    - [System](#MalcolmSystem)
    - [Configuration](#MalcolmConfig)
    - [Setting up Authentication](#MalcolmAuthSetup)
* [Hedgehog Linux Installation and Configuration](#HedgehogInstallAndConfig)
    - [Hedgehog Linux ISO Installation](#ISOInstallHedgehog)

## <a name="ISODownload"></a> Obtaining the Installation ISOs

Malcolm can be [packaged](malcolm-iso.md#ISOBuild) into an [installer ISO](malcolm-iso.md#ISO) based on the current [stable release](https://wiki.debian.org/DebianStable) of [Debian](https://www.debian.org/). This [customized Debian installation](https://wiki.debian.org/DebianLive) is preconfigured with the bare minimum software needed to run Malcolm.

Similar instructions exist for generating the [installer ISO](hedgehog-iso-build.md#HedgehogISOBuild) for [Hedgehog Linux](hedgehog.md), Malcolm's dedicated network sensor appliance OS.

While official downloads of the Malcolm installer ISO are not provided, an **unofficial build** of the ISO installer for the [latest stable release]({{ site.external_download_url }}) is available for download here. If downloading the unofficial builds, be sure to verify the integrity of ISO files against the SHA256 sums provided on the download page.

## <a name="ISOBurning"></a> "Burning" the Installation ISOs to USB Flash Drive

Various methods can be used to write the contents of an installer ISO image to a USB flash drive. One simple free and open source application for doing so [Etcher](https://www.balena.io/etcher), which can be used on Windows, macOS and Linux platforms.

Alternatively, specific instructions may be provided by your operating system (e.g., [Arch Linux](https://wiki.archlinux.org/title/USB_flash_installation_medium), [Debian Linux](https://www.debian.org/releases/stable/amd64/ch04s03.en.html), [Ubuntu Linux](https://ubuntu.com/tutorials/create-a-usb-stick-on-ubuntu#1-overview)). 

Using one of these methods, write the Malcolm and Hedgehog Linux installer ISOs to two 8GB or larger USB flash drives, respectively.

Alternatively, the ISO images could be burned to writable optical media (e.g., DVD±R). For the Malcolm installer you'll likely have to use DVD±R DL ("dual layer" or "double layer") DVD media as the installer ISO exceeds the 4.7 GB storage provided by standard DVDs.

![Etcher on macOS](./images/screenshots/iso_install_etcher_macos.png)

*Using Etcher on macOS*

![dd on Linux](./images/screenshots/iso_install_dd_linux.png)

*Using dd on Linux*

## <a name="BootUSB"></a> Booting the Installation Media

The ISO media boot on systems that support EFI-mode and legacy (BIOS) booting. Configuring your system's firmware to allow booting from USB or optical media will vary from manufacturer to manufacturer. Usually manufacturers will provide a one-time boot options menu upon a specific keypress (e.g., F12 for Dell, F9 for HP, etc.). If needed, consult the documentation provided by the hardware manufacturer on how to access the boot options menu and boot from your newly-burned USB flash media or DVD±R.

![EFI Boot Manager](./images/screenshots/iso_install_boot_menu_efi.png)

*An example of an EFI boot manager in QEMU*

![BIOS Boot Manager](./images/screenshots/iso_install_boot_menu_bios.png)

*An example of a BIOS boot options menu in QEMU*

## <a name="MalcolmInstallAndConfig"></a> Malcolm Installation and Configuration

### <a name="ISOInstallMalcolm"></a> Malcolm ISO Installation

Upon Booting the Malcolm installation ISO, you're presented with the following **Boot menu**. Use the arrow keys to select **Install Malcolm**, and press Enter.

![](./images/screenshots/iso_install_malcolm_iso_menu_1.png)

*The first screen of the installer*

The next screen of the installer presents the following options relevant to installation:

* **Quick Install** - Installs Malcolm without full disk encryption using default partitioning.
* **Encrypted Quick Install** - Installs Malcolm with full disk encryption using default partitioning. You will be prompted for a password for full disk encryption during installation which must be entered each time the system boots.
* **Expert Install** - Allows you to configure the options of the [Debian](https://wiki.debian.org/DebianInstaller)-based installation system. Only recommended when needed for expert Linux users.
* **Virtual Machine Single Partition Quick Install** - The same as **Quick Install** except that all system files are stored in a single partition. Use this option when installing Malcolm onto a virtual machine.

![](./images/screenshots/iso_install_malcolm_iso_menu_2.png)

*The **Install Malcolm** menu*

After making your selection for the type of Malcolm install to perform, the installer will ask for several pieces of information prior to installing the Malcolm base operating system:

* **Hostname** - the name of the Malcolm system used to identify itself on the network
* **Domain name** - (optional) the name of the local network domain
* **Root password** – (optional) a password for the privileged root account which is rarely needed; if unspecified, the non-privileged user account will be added to the `sudo` group
* **User name** the name for the non-privileged service account user account under which the Malcolm runs
* **User password** – a password for the non-privileged user account
* **Encryption password** – (optional) if the encrypted installation option was selected at boot, the encryption password must be entered every time the system boots

![Example of the installer's password prompt](./images/hedgehog/images/users_and_passwords.png)

After the passwords have been entered, the installer will proceed to format the system drive and install Malcolm.

![Installer progress](./images/hedgehog/images/installer_progress.png)

At the end of the installation process, you will be prompted with a few self-explanatory yes/no questions:

* **Disable IPv6?**
* **Automatically login to the GUI session?**
* **Should the GUI session be locked due to inactivity?**
* **Display the [Standard Mandatory DoD Notice and Consent Banner](https://www.stigviewer.com/stig/application_security_and_development/2018-12-24/finding/V-69349)?** *(only applies when installed on U.S. government information systems)*

Following these prompts, the installer will reboot and the Malcolm base operating system will boot.

The Malcolm installer does not require an internet connection to complete successfully. If the installer prompts you to configure network connectivity, you may choose "do not configure the network at this time."

### <a name="MalcolmSystem"></a> Malcolm System

The Malcolm base operating system is a [hardened](hardening.md#Hardening) Linux installation based on the current [stable release](https://wiki.debian.org/DebianStable) of [Debian](https://www.debian.org/) [running](https://wiki.debian.org/Xfce) the [XFCE desktop environment](https://www.xfce.org/). It has been preloaded with all of the [components](components.md#Components) that make up Malcolm.

[NetworkManager](https://wiki.debian.org/NetworkManager) can be used to configure networking for Malcolm. NetworkManager can be configured by clicking the 🖧 (networked computers) icon in the system tray in the upper-right corner of the screen, or right-clicking the icon and selecting **Edit Connections...** to modify the properties of a given connection.

Display resolution should be detected and adjusted automatically. If you need to make changes to display properties, click the **Applications** menu and select **Settings** → **Display**.

The panel bordering the top of the Malcolm desktop is home to a number of useful shortcuts:

![Malcolm Desktop](./images/screenshots/malcolm_desktop.png)


### <a name="MalcolmConfig"></a> Malcolm Configuration

The first time the Malcolm base operating system boots the **Malcolm Configuration** wizard will start automatically. This same configuration script can be run again later by running [`./scripts/install.py --configure`](malcolm-config.md#ConfigAndTuning) from the Malcolm installation directory, or clicking the **Configure Malcolm** 🔳 icon in the top panel.

![Malcolm Configuration on first boot](./images/screenshots/malcolm_first_boot_config.png)

The [configuration and tuning](malcolm-config.md#ConfigAndTuning) wizard's questions proceed as follows. Note that you may not necessarily see every question listed here depending on how you answered earlier questions. Usually the default selection is what you'll want to select unless otherwise indicated below.

* Malcolm processes will run as UID 1000 and GID 1000. Is this OK?
    - Docker runs all of its containers as the privileged `root` user by default. For better security, Malcolm immediately drops to non-privileged user accounts for executing internal processes wherever possible. The `PUID` (**p**rocess **u**ser **ID**) and `PGID` (**p**rocess **g**roup **ID**) environment variables allow Malcolm to map internal non-privileged user accounts to a corresponding [user account](https://en.wikipedia.org/wiki/User_identifier) on the host.
* Should Malcolm use and maintain its own OpenSearch instance?
    - Malcolm's default standalone configuration is to use a local [OpenSearch](https://opensearch.org/) instance in a Docker container to index and search network traffic metadata. See [OpenSearch instances](opensearch-instances.md#OpenSearchInstance) for more information about using a remote OpenSearch cluster instead.
* Forward Logstash logs to a secondary remote OpenSearch instance?
    - Whether the primary OpenSearch instance is a locally maintained single-node instance or is a remote cluster, Malcolm can be configured additionally forward logs to a secondary remote OpenSearch instance. See [OpenSearch instances](opensearch-instances.md#OpenSearchInstance) for more information about forwarding logs to another OpenSearch instance.
* Setting 16g for OpenSearch and 3g for Logstash. Is this OK?
    - Two of Malcolm's main components, OpenSearch and Logstash, require a substantial amount of memory to be set aside for their use. The configuration script will suggest defaults for these values based on the amount of physical memory the system has. The minimum recommended amount of system memory for Malcolm is 16 gigabytes. For a pleasant experience, I would suggest not using a value under 10 gigabytes for OpenSearch and 2500 megabytes for Logstash.
* Setting 3 workers for Logstash pipelines. Is this OK?
    - This setting is used to tune the performance and resource utilization of the the `logstash` container. The default is calculated based on the number of logical CPUs the system has. See [Tuning and Profiling Logstash Performance](https://www.elastic.co/guide/en/logstash/current/tuning-logstash.html), [`logstash.yml`](https://www.elastic.co/guide/en/logstash/current/logstash-settings-file.html) and [Multiple Pipelines](https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html).
* Restart Malcolm upon system or Docker daemon restart?
    - This question allows you to configure Docker's [restart policy](https://docs.docker.com/config/containers/start-containers-automatically/#use-a-restart-policy) for Malcolm (ie., the behavior used to restart Malcolm should the system be shut down or rebooted, or should one of Malcolm's components should crash). Possible options are:
        + no - do not automatically restart the container
        + on-failure - restart the container if it exits due to an error, which manifests as a non-zero exit code
        + always - always restart the container if it stops
        + unless-stopped - similar to always, except that when the container is stopped (manually or otherwise), it is not restarted even after Docker daemon restarts; this is usually a good choice
* Require encrypted HTTPS connections?
    - Malcolm uses [TLS](authsetup.md#TLSCerts) encryption for its web browser-accessible user interfaces. Answering **Y** to this question is almost always what you want. The only situation in which you might want to answer **N** is if you are running Malcolm behind a third-party reverse proxy (e.g., [Traefik](https://doc.traefik.io/traefik/) or [Caddy](https://caddyserver.com/docs/quick-starts/reverse-proxy)) to handle the issuance of the certificates for you and to broker the connections between clients and Malcolm. Reverse proxies such as these often implement the [ACME](https://datatracker.ietf.org/doc/html/rfc8555) protocol for domain name authentication and can be used to request certificates from certificate authorities like [Let's Encrypt](https://letsencrypt.org/how-it-works/). In this configuration, the reverse proxy will be encrypting the connections instead of Malcolm. **Make sure** you understand what you are doing and ensure that external connections cannot reach ports over which Malcolm will be communicating without encryption, including verifying your local firewall configuration, should you choose to answer **N** to this question.
* Will Malcolm be running behind another reverse proxy (Traefik, Caddy, etc.)?
    - See the previous question. If Malcolm is configured behind a remote proxy, Malcolm can prompt you to *Configure labels for Traefik?* to allow it to identify itself to Traefik.
* Specify external Docker network name (or leave blank for default networking)
    - This allows you to configure Malcolm to use [custom Docker networks](https://docs.docker.com/compose/networking/#specify-custom-networks). Leave this blank unless you know you want to do otherwise.
* Authenticate against Lightweight Directory Access Protocol (LDAP) server?
    - Answer **N** to use Malcolm's own built-in [local account management](authsetup.md#AuthBasicAccountManagement), or **Y** to use [Lightweight Directory Access Protocol (LDAP) authentication](authsetup.md#AuthLDAP).
* Select LDAP server compatibility type
    - This question allows you to specify Microsoft Active Directory compatibility (**winldap**) or generic LDAP compatibility (**openldap**, for OpenLDAP, glauth, etc.) when using [LDAP authentication](authsetup.md#AuthLDAP)
* Use StartTLS (rather than LDAPS) for LDAP connection security?
    - When using LDAP authentication, this question allows you to configure [LDAP connection security](authsetup.md#AuthLDAPSecurity)
* Store PCAP, log and index files locally under /home/user/Malcolm?
    - Malcolm generates a number of large file sets during normal operation: PCAP files, Zeek or Suricata logs, OpenSearch indices, etc. By default all of these are stored in subdirectories in the Malcolm installation directory. This question allows you to specify alternative storage location(s) (for example, a separate dedicated drive or RAID volume) for these artifacts.
* Compress OpenSearch index snapshots?
    - Choose whether OpenSearch [index snapshots](https://opensearch.org/docs/2.6/tuning-your-cluster/availability-and-recovery/snapshots/snapshot-management/) should be compressed or not, should you opt to configure them later in [OpenSearch index management](index-management.md#IndexManagement).
* Delete the oldest indices when the database exceeds a certain size?
    - Most of the configuration around OpenSearch [Index State Management](https://opensearch.org/docs/latest/im-plugin/ism/index/) and [Snapshot Management](https://opensearch.org/docs/latest/opensearch/snapshots/sm-dashboards/) can be done in OpenSearch Dashboards. In addition to (or instead of) the OpenSearch index state management operations, Malcolm can also be configured to delete the oldest network session metadata indices when the database exceeds a certain size to prevent filling up all available storage with OpenSearch indices.
* Automatically analyze all PCAP files with Suricata?
    - This option is used to enable [Suricata](https://suricata.io/) (an IDS and threat detection engine) to analyze PCAP files uploaded to Malcolm via its upload web interface.
* Download updated Suricata signatures periodically?
    - This option is used to [enable automatic updates](https://suricata-update.readthedocs.io/en/latest/) of the Suricata rules used by Malcolm.
* Automatically analyze all PCAP files with Zeek?
    - This option is used to enable [Zeek](https://www.zeek.org/index.html) (a network analysis framework and IDS) to analyze PCAP files uploaded to Malcolm via its upload web interface
* Perform reverse DNS lookup locally for source and destination IP addresses in logs?
* Perform hardware vendor OUI lookups for MAC addresses?
* Perform string randomness scoring on some fields?
* Expose OpenSearch port to external hosts?
* Expose Logstash port to external hosts?
* Expose Filebeat TCP port to external hosts?
* Select log format for messages sent to Filebeat TCP listener
* Source field to parse for messages sent to Filebeat TCP listener
* Target field under which to store decoded JSON fields for messages sent to Filebeat TCP listener
* Field to drop from events sent to Filebeat TCP listener
* Tag to apply to messages sent to Filebeat TCP listener
* Expose SFTP server (for PCAP upload) to external hosts?
* Enable file extraction with Zeek?
* Select file extraction behavior
* Select file preservation behavior
* Expose web interface for downloading preserved files?
* Enter AES-256-CBC encryption password for downloaded preserved files (or leave blank for unencrypted)
* Scan extracted files with ClamAV?
* Scan extracted files with Yara?
* Scan extracted PE files with Capa?
* Lookup extracted file hashes with VirusTotal?
* Enter VirusTotal API key
* Download updated file scanner signatures periodically?
* Should Malcolm run and maintain an instance of NetBox, an infrastructure resource modeling tool?
* Should Malcolm enrich network traffic using NetBox?
* Specify default NetBox site name
* Should Malcolm capture live network traffic to PCAP files for analysis with Arkime?
* Capture packets using netsniff-ng?
* Capture packets using tcpdump?
* Should Arkime delete PCAP files based on available storage?
    - OpenSearch index state management and snapshot management only deals with disk space consumed by OpenSearch indices: it does not have anything to do with PCAP file storage. This option can be used to also allow Arkime to prune old PCAP files based on available disk space (see https://arkime.com/faq#pcap-deletion).
* Should Malcolm analyze live network traffic with Suricata?
* Should Malcolm analyze live network traffic with Zeek?
* Should Malcolm use "best guess" to identify potential OT/ICS traffic with Zeek?
* Specify capture interface(s) (comma-separated)
* Capture filter (tcpdump-like filter expression; leave blank to capture all traffic)
    - `not port 5044 and not port * 8005 and not port 9200`
* Disable capture interface hardware offloading and adjust ring buffer sizes?
* Enable dark mode for OpenSearch Dashboards?

### <a name="MalcolmAuthSetup"></a> Setting up Authentication for Malcolm

## <a name="HedgehogInstallAndConfig"></a> Hedgehog Linux Installation and Configuration

## <a name="ISOInstallHedgehog"></a> Hedgehog Linux ISO Installation

The Hedgehog Linux installation ISO follows the same process as the [Malcolm installation](#ISOInstallMalcolm) above.

The installer will ask for a few pieces of information prior to installing Hedgehog Linux:

* **Root password** – a password for the privileged root account which is rarely needed (only during the configuration of the sensors network interfaces and setting the sensor host name)
* **User password** – a password for the non-privileged `sensor` account under which the various sensor capture and forwarding services run
* **Encryption password** – (optional) if the encrypted installation option was selected at boot, the encryption password must be entered every time the sensor boots

At the end of the installation process, you will be prompted with a few self-explanatory yes/no questions:

* **Disable IPv6?**
* **Automatically login to the GUI session?**
* **Should the GUI session be locked due to inactivity?**
* **Display the [Standard Mandatory DoD Notice and Consent Banner](https://www.stigviewer.com/stig/application_security_and_development/2018-12-24/finding/V-69349)?** *(only applies when installed on U.S. government information systems)*

Following these prompts, the installer will reboot and Hedgehog Linux will boot.

