# Hedgehog Linux

**Malcolm's Network Sensor**

* [End-to-end Malcolm and Hedgehog Linux ISO Installation](malcolm-hedgehog-e2e-iso-install.md#InstallationExample)
    - [Hedgehog Linux Installation and Configuration](malcolm-hedgehog-e2e-iso-install.md#HedgehogInstallAndConfig)
        + [Configuring Communication Between Hedgehog and Malcolm](malcolm-hedgehog-e2e-iso-install.md#HedgehogCommConfig)
        + [TCP Ports Required for Malcolm ↔ Hedgehog Communication](malcolm-hedgehog-e2e-iso-install.md#HedgehogMalcolmPorts)
* [Configuring Hedgehog for Standalone Use](hedgehog-standalone.md)
* [Running Hedgehog Linux on Raspberry Pi](hedgehog-raspi.md)

![Hedgehog Linux](./images/hedgehog/logo/hedgehog-color-w-text.png)

Hedgehog Linux is a Debian-based operating system built to

* monitor network interfaces
* capture packets to PCAP files
* detect file transfers in network traffic and extract and scan those files for threats
* generate and forward Zeek logs, Arkime sessions, and other information to [Malcolm]({{ site.github.repository_url }})

As of Malcolm v25.12.0, the Malcolm and Hedgehog Linux base operating systems have been merged into a single code base; in other words, the Hedgehog Linux installer ISO is now simply another "flavor" of the [Malcolm installer ISO](malcolm-iso.md#ISO) preconfigured to use the ["Hedgehog" run profile](live-analysis.md#Profiles). As such, the documentation for Malcolm and Hedgehog Linux has converged, since both platforms use the same procedures for installation and configuration.

The exception to this is the Hedgehog Linux [Raspberry Pi Image](hedgehog-raspi.md#HedgehogRaspiBuild), which is built using a slightly different process from that of the Malcolm and Hedgehog Linux installer ISOs.
