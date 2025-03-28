# <a name="HedgehogHardening"></a>Appendix E - Hardening

Hedgehog Linux uses the [harbian-audit](https://github.com/hardenedlinux/harbian-audit) benchmarks which target the following guidelines for establishing a secure configuration posture:

* [CIS Debian Linux 9/10 Benchmark](https://www.cisecurity.org/cis-benchmarks/cis-benchmarks-faq/)
* [DISA STIG (Security Technical Implementation Guides) for RHEL 7](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/) v2r5 Ubuntu v1r2 [adapted](https://github.com/hardenedlinux/STIG-OS-mirror/blob/master/redhat-STIG-DOCs/U_Red_Hat_Enterprise_Linux_7_V2R5_STIG.zip) for a Debian operating system
* Additional recommendations from [cisecurity.org](https://www.cisecurity.org/)

## <a name="HedgehogComplianceExceptions"></a>Compliance Exceptions

[Currently](https://github.com/hardenedlinux/harbian-audit/tree/master/bin/hardening) there are 274 checks to determine compliance with the [harbian-audit](https://github.com/hardenedlinux/harbian-audit) benchmark.

Hedgehog Linux claims exceptions from the recommendations in this benchmark in the following categories:

**1.1 Install Updates, Patches and Additional Security Software** - When the the Malcolm aggregator appliance software is built, all of the latest applicable security patches and updates are included in it. How future updates are to be handled is still in design.

**1.3 Enable verify the signature of local packages** - As the base distribution is not using embedded signatures, `debsig-verify` would reject all packages (see comment in `/etc/dpkg/dpkg.cfg`). Enabling it after installation would disallow any future updates.

**2.14 Add nodev option to /run/shm Partition**, **2.15 Add nosuid Option to /run/shm Partition**, **2.16 Add noexec Option to /run/shm Partition** - Hedgehog Linux does not mount `/run/shm` as a separate partition, so these recommendations do not apply.

**2.17 Set Sticky Bit on All World-Writable Directories** - The only directory found by [this script](https://github.com/hardenedlinux/harbian-audit/blob/master/bin/hardening/2.17_sticky_bit_world_writable_folder.sh) is `/var/mail`, which is configured as prescribed by the Debian maintainers.

**2.19 Disable Mounting of freevxfs Filesystems**, **2.20 Disable Mounting of jffs2 Filesystems**, **2.21 Disable Mounting of hfs Filesystems**, **2.22 Disable Mounting of hfsplus Filesystems**, **2.23 Disable Mounting of squashfs Filesystems**, **2.24 Disable Mounting of udf Filesystems** - Hedgehog Linux is not compiling a custom Linux kernel, so these filesystems are inherently supported as they are part Debian Linux's default kernel.

**3.3 Set Boot Loader Password** - As maximizing availability is a system requirement, Malcolm should restart automatically without user intervention to ensured uninterrupted service. A boot loader password is not enabled.

**4.8 Disable USB Devices** - The ability to ingest data (such as PCAP files) from a mounted USB mass storage device is a requirement of the system.

**5.2 Install screen** - Hedgehog Linux comes with `tmux`, a modern `screen` alternative. 

**6.1 Ensure the X Window system is not installed**, **6.2 Ensure Avahi Server is not enabled**, **6.3 Ensure print server is not enabled** - An X Windows session is provided for displaying dashboards. The library packages `libavahi-common-data`, `libavahi-common3`, and `libcups2` are dependencies of some of the X components used by Hedgehog Linux, but the `avahi` and `cups` services themselves are disabled.

**6.17 Ensure virus scan Server is enabled**, **6.18 Ensure virus scan Server update is enabled** - As this is a network traffic analysis appliance rather than an end-user device, regular user files will not be created. A virus scan program would impact device performance and would be unnecessary.

**7.1.1 Disable IP Forwarding**, **7.2.4 Log Suspicious Packets**, **7.2.7 Enable RFC-recommended Source Route Validation**, **7.4.1 Install TCP Wrappers** - As Malcolm may operate as a network traffic capture appliance sniffing packets on a network interface configured in promiscuous mode, these recommendations do not apply.

**8.1.1.2 Disable System on Audit Log Full**, **8.1.1.3 Keep All Auditing Information**, **8.1.1.5 Ensure set remote_server for audit service**, **8.1.1.6 Ensure enable_krb5 set to yes for remote audit service**, **8.1.1.7 Ensure set action for audit storage volume is fulled**, **8.1.1.8 Ensure set action for network failure on remote audit service**, **8.1.1.9 Set space left for auditd service**, a few other audit-related items under section **8.1**, **8.2.4 Configure rsyslog to Send Logs to a Remote Log Host** - As maximizing availability is a system requirement, audit processing failures will be logged on the device rather than halting the system. `auditd` is set up to syslog when its local storage capacity is reached.

**8.2.1 Install the rsyslog package**, **8.2.2 Enable rsyslog**, **8.2.3 Create and Set Permissions on rsyslog Log Files by conf file**, **8.3.1 Install the syslog-ng package**, **8.3.2 Ensure the syslog-ng Service is activated**,  - Modern Debian-based Linux systems now use journald instead of rsyslog or syslog-ng. On Malcolm, these logs are available using journalctl and can be configured to be forwarded into the Malcolm data store using Fluent Bit.

**8.4.2 Implement Periodic Execution of File Integrity** - This functionality is not configured by default, but it can be configured post-install by the end user.

**8.5 Ensure permissions on all logfiles are configured** - It is the opinion of the Malcolm development team that the log files found in `/var/log` on the Malcolm base operating system are set with secure file permissions, despite what the [audit script](https://github.com/hardenedlinux/harbian-audit/blob/master/bin/hardening/8.5_ensure_permissions_on_all_logfiles.sh) for this item suggests.

**8.7.1 Ensure journald is configured to compress large log files** - Malcolm does not enable compression for journald logs to ensure that they remain readable by [Fluent Bit](https://docs.fluentbit.io/manual/pipeline/inputs/systemd) (see [this related issue](https://github.com/fluent/fluent-bit/issues/2998)) for forwarding into the Malcolm data store.

**8.7.2  Ensure journald is configured to write logfiles to persistent disk** - Journald's `Storage` setting remains set to the default `auto` value in the Malcolm base operating system. However, these logs can be configured to be forwarded into the Malcolm data store, at which point they are persisted to disk.

Password-related recommendations under **9.2** and **10.1** - The library package `libpam-pwquality` is used in favor of `libpam-cracklib` which is what the [compliance scripts](https://github.com/hardenedlinux/harbian-audit/tree/master/bin/hardening) are looking for. Also, as an appliance running Malcolm is intended to be used as an appliance rather than a general user-facing software platform, some exceptions to password enforcement policies are claimed.

**9.3.13 Limit Access via SSH** - Hedgehog Linux does not create multiple regular user accounts: only `root` and a sensor service account are used. SSH access for `root` is disabled. SSH login with a password is also disallowed: only key-based authentication is accepted. The service account accepts no keys by default. As such, the `AllowUsers`, `AllowGroups`, `DenyUsers`, and `DenyGroups` values in `sshd_config` do not apply.

**9.4 Restrict Access to the su Command** - Hedgehog Linux does not create multiple regular user accounts: only `root` and a sensor service account are used.

**10.1.6 Remove nopasswd option from the sudoers configuration** - A very limited set of operations (a single script used to run the AIDE integrity check as a non-root user) has the NOPASSWD option set to allow it to be run in the background without user intervention.

**10.1.10 Set maxlogins for all accounts** and **10.5 Set Timeout on ttys** - Hedgehog Linux does not create multiple regular user accounts: only `root` and a sensor service account are used.

**12.10 Find SUID System Executables**, **12.11 Find SGID System Executables** - The few files found by [these](https://github.com/hardenedlinux/harbian-audit/blob/master/bin/hardening/12.10_find_suid_files.sh) [scripts](https://github.com/hardenedlinux/harbian-audit/blob/master/bin/hardening/12.11_find_sgid_files.sh) are valid exceptions required by Hedgehog Linux's core requirements.

**14.1  Defense for NAT Slipstreaming** - As Malcolm may operate as a network traffic capture appliance sniffing packets on a network interface configured in promiscuous mode, this recommendation does not apply.

Please review the notes for these additional guidelines. While not claiming an exception, Hedgehog Linux may implement them in a manner different than is described by the [CIS Debian Linux 9/10 Benchmark](https://www.cisecurity.org/cis-benchmarks/cis-benchmarks-faq/) or the [hardenedlinux/harbian-audit](https://github.com/hardenedlinux/harbian-audit) audit scripts.

**4.1 Restrict Core Dumps** - Hedgehog Linux disables core dumps using a configuration file for `ulimit` named `/etc/security/limits.d/limits.conf`. The [audit script](https://github.com/hardenedlinux/harbian-audit/blob/master/bin/hardening/4.1_restrict_core_dumps.sh) checking for this does not check the `limits.d` subdirectory, which is why this is incorrectly flagged as noncompliant.

**5.4 Ensure ctrl-alt-del is disabled** - Hedgehog Linux disables the `ctrl+alt+delete` key sequence by executing `systemctl disable ctrl-alt-del.target` during installation and the command `systemctl mask ctrl-alt-del.target` at boot time.

**6.5 Ensure time sync server is installed**, **6.19 Configure Network Time Protocol (NTP)**, and **6.20 Configure Network Time Protocol (chrony)** - The Malcolm aggregator base operating system [can be configured](malcolm-hedgehog-e2e-iso-install.md#MalcolmTimeSync) to synchronize time using either Network Time Protocol (NTP) or HTP (HTTP Time Protocol). The audit scripts for checking and configuring NTP do not check for binaries provided by the `ntpsec` package Malcolm uses, which is why this is incorrectly flagged as noncompliant.

**7.4.4 Create /etc/hosts.deny**, **7.7.1 Ensure Firewall is active**, **7.7.4.1 Ensure default deny firewall policy**, **7.7.4.2 Ensure loopback traffic is configured**, **7.7.4.3 Ensure default deny firewall policy**, **7.7.4.4 Ensure outbound and established connections are configured** - Hedgehog Linux **is** configured with an appropriately locked-down software firewall (managed by "Uncomplicated Firewall" `ufw`). However, the methods outlined in the CIS benchmark recommendations do not account for this configuration. 

**8.6 Verifies integrity all packages** - The [script](https://github.com/hardenedlinux/harbian-audit/blob/master/bin/hardening/8.7_verify_integrity_packages.sh) which verifies package integrity only "fails" because of missing (status `??5??????` displayed by the utility) language ("locale") files, which are removed as part of Hedgehog Linux's trimming-down process. All non-locale-related system files pass intergrity checks.