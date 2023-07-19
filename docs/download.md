# Downloads

## Malcolm

### Docker images

Malcolm operates as a cluster of Docker containers, isolated sandboxes which each serve a dedicated function of the system. Its Docker images can be pulled from [GitHub](https://github.com/orgs/idaholab/packages?repo_name=Malcolm) or built from source by following the instructions in the [Quick Start](quickstart.md#QuickStart) section of the documentation.

### Installer ISO

Malcolm's Docker-based deployment model makes Malcolm able to run on a variety of platforms. However, in some circumstances (for example, as a long-running appliance as part of a security operations center, or inside of a virtual machine) it may be desirable to install Malcolm as a dedicated standalone installation.

Malcolm can be [packaged](malcolm-iso.md#ISOBuild) into an [installer ISO](malcolm-iso.md#ISO) based on the current [stable release](https://wiki.debian.org/DebianStable) of [Debian](https://www.debian.org/). This [customized Debian installation](https://wiki.debian.org/DebianLive) is preconfigured with the bare minimum software needed to run Malcolm.

While official downloads of the Malcolm installer ISO are not provided, an **unofficial build** of the ISO installer for the [latest stable release]({{ site.github.repository_url }}/releases/latest) is available for download here.

| ISO | SHA256 |
|---|---|
| [malcolm-23.07.0.iso](/iso/malcolm-23.07.0.iso) (4.6GiB) |  [`749f3d3312974bffe1df289192fb331dbed92b292f69dc3d794847442c54c089`](/iso/malcolm-23.07.0.iso.sha256.txt) |

## Hedgehog Linux

### Installer ISO

[Instructions are provided](hedgehog-iso-build.md#HedgehogISOBuild) to generate the Hedgehog Linux ISO from source. While official downloads of the Hedgehog Linux ISO are not provided, an **unofficial build** of the ISO installer for the latest stable release is available for download here.

| ISO | SHA256 |
|---|---|
| [hedgehog-23.07.0.iso](/iso/hedgehog-23.07.0.iso) (2.3GiB) |  [`e28d91ddb9000cdfa470c625f97b8a3917c4f05a06117c0aa959fe705cd2a30a`](/iso/hedgehog-23.07.0.iso.sha256.txt) |

## Warning

Please check any files you may have downloaded from the links on this page against the SHA256 sums provided to verify the integrity of the downloads.

Read carefully the installation documentation for [Malcolm](malcolm-iso.md#ISOInstallation) and/or [Hedgehog Linux](hedgehog-installation.md#HedgehogInstallation). The ISO media boot on systems that support EFI-mode booting. The installer is designed to require as little user input as possible. For this reason, there are NO user prompts and confirmations about partitioning and reformatting hard disks for use by the operating system. The installer assumes that all non-removable storage media (eg., SSD, HDD, NVMe, etc.) are available for use and ⛔🆘😭💀 ***will partition and format them without warning*** 💀😭🆘⛔.

## Disclaimer

The terms of [Malcolm's license]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/LICENSE.txt) and [release notice]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/NOTICE.txt) also apply to these unofficial builds of the Malcolm and Hedgehog Linux installer ISOs: neither the organizations funding Malcolm's development, its developers nor the maintainer of this site makes any warranty, express or implied, or assumes any legal liability or responsibility for the accuracy, completeness or usefulness of any data, apparatus or process disclosed therein.
