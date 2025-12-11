# Hedgehog Linux

**Network Traffic Capture Appliance**

![Hedgehog Linux](./images/hedgehog/logo/hedgehog-color-w-text.png)

Hedgehog Linux is a Debian-based operating system built to

* monitor network interfaces
* capture packets to PCAP files
* detect file transfers in network traffic and extract and scan those files for threats
* generate and forward Zeek logs, Arkime sessions, and other information to [Malcolm]({{ site.github.repository_url }})

As of Malcolm v25.12.1, the Malcolm and Hedgehog Linux base operating systems have been merged into a single code base; in other words, the Hedgehog Linux installer ISO is now simply another "flavor" of the [Malcolm installer ISO](malcolm-iso.md#ISO) preconfigured to use the ["Hedgehog" run profile](live-analysis.md#Profiles). As such, the documentation for Malcolm and Hedgehog Linux has converged, since both platforms use the same procedures for installation and configuration.

The exception to this is the Hedgehog Linux [Raspberry Pi Image](hedgehog-raspi-build.md#HedgehogRaspiBuild), which is built using a different process from that of the Malcolm and Hedgehog Linux installer ISOs.
