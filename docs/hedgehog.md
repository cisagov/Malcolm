# Hedgehog Linux

**Network Traffic Capture Appliance**

![Hedgehog Linux](./images/hedgehog/logo/hedgehog-color-w-text.png)

Hedgehog Linux is a Debian-based operating system built to

* monitor network interfaces
* capture packets to PCAP files
* detect file transfers in network traffic and extract and scan those files for threats
* generate and forward Zeek logs, Arkime sessions, and other information to [Malcolm]({{ site.github.repository_url }})

<a name="HedgehogTableOfContents"></a>
* [Sensor installation](hedgehog-installation.md#HedgehogInstallation)
    - [Image boot options](hedgehog-installation.md#HedgehogBootOptions)
    - [Installer](hedgehog-installation.md#HedgehogInstaller)
* [Boot](hedgehog-boot.md#HedgehogBoot)
    - [Kiosk mode](hedgehog-boot.md#HedgehogKioskMode)
* [Configuration](malcolm-hedgehog-e2e-iso-install.md#HedgehogInstallAndConfig)
    - [Configure Hostname, Interfaces and Time Sync](malcolm-hedgehog-e2e-iso-install.md#HedgehogInterfaces)
    - [Configure Capture](malcolm-hedgehog-e2e-iso-install.md#HedgehogCapture)
        + [Capture](malcolm-hedgehog-e2e-iso-install.md#HedgehogConfigCapture)
        + [File extraction and scanning](malcolm-hedgehog-e2e-iso-install.md#HedgehogZeekFileExtraction)
    - [Configure Forwarding](malcolm-hedgehog-e2e-iso-install.md#HedgehogConfigForwarding)
        * [arkime-capture](malcolm-hedgehog-e2e-iso-install.md#Hedgehogarkime-capture): Arkime session forwarding
        * [ssl-client-receive](malcolm-hedgehog-e2e-iso-install.md#HedgehogGetCerts): Receive client SSL files for filebeat from Malcolm
        * [filebeat](malcolm-hedgehog-e2e-iso-install.md#Hedgehogfilebeat): Zeek and Suricata log forwarding
        * [miscbeat](malcolm-hedgehog-e2e-iso-install.md#Hedgehogmiscbeat): System metrics forwarding        
        * [acl-configure](malcolm-hedgehog-e2e-iso-install.md#HedgehogACL): Configure ACL for artifact reachback from Malcolm
        * [tags-configure](malcolm-hedgehog-e2e-iso-install.md#HedgehogTags): Specify extra tags for forwarded logs
    - [Autostart services](malcolm-hedgehog-e2e-iso-install.md#HedgehogConfigAutostart)
    - [Managing disk usage](malcolm-hedgehog-e2e-iso-install.md#HedgehogDiskUsage)
    - [Zeek Intelligence Framework](hedgehog-config-zeek-intel.md#HedgehogZeekIntel)
    - [Custom Rules, Scripts and Plugins](hedgehog-custom-rules.md#CustomRulesAndScripts)
    - [Tuning](live-analysis.md#LiveAnalysisTuning)
        + [Zeek](live-analysis.md#LiveAnalysisTuningZeek)
        + [Arkime](live-analysis.md#LiveAnalysisTuningArkime)
        + [Suricata](live-analysis.md#LiveAnalysisTuningSuricata)
* [Appendix A - Generating the ISO](hedgehog-iso-build.md#HedgehogISOBuild)
* [Appendix B - Generating a Raspberry Pi Image](hedgehog-raspi-build.md#HedgehogRaspiBuild)
* [Appendix C - Configuring SSH access](hedgehog-ssh.md#HedgehogConfigSSH)
* [Appendix D - Troubleshooting](hedgehog-troubleshooting.md#HedgehogTroubleshooting)
* [Appendix E - Hardening](hedgehog-hardening.md#HedgehogHardening)
    - [Compliance exceptions](hedgehog-hardening.md#HedgehogComplianceExceptions)
* [Appendix F - Upgrades](hedgehog-upgrade.md#HedgehogUpgradePlan)
