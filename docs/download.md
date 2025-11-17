# <a name="DownloadMalcolm"></a> Downloading Malcolm

* [Container images](#DownloadDockerImages)
* [Installer ISOs](#DownloadISOs)
    - [Joining split ISOs](#JoinISOs)
    - [Warning](#ISOsWarning)

## <a name="DownloadDockerImages"></a> Container images

Malcolm operates as a cluster of containers, isolated sandboxes which each serve a dedicated function of the system. These images can be pulled from [GitHub](https://github.com/orgs/idaholab/packages?repo_name=Malcolm) by running `docker compose --profile malcolm pull` from within the Malcolm installation directory, or they can be built from source by following the instructions in the [Quick Start](quickstart.md#QuickStart) section of the documentation.

## <a name="DownloadISOs"></a> Installer ISOs

* [Latest release]({{ site.github.repository_url }}/releases/latest)

Malcolm's container-based deployment model makes Malcolm able to run on a variety of platforms. However, in some circumstances (for example, as a long-running appliance as part of a security operations center, or inside of a virtual machine) it may be desirable to install Malcolm as a dedicated standalone installation.

Malcolm is also packaged into an [installer ISO](malcolm-iso.md#ISO) based on the current [stable release](https://wiki.debian.org/DebianStable) of [Debian](https://www.debian.org/). This [customized Debian installation](https://wiki.debian.org/DebianLive) is preconfigured with the bare minimum software needed to run Malcolm.

### <a name="JoinISOs"></a> Joining split ISOs

ISOs can be downloaded from [Malcolm's releases page]({{ site.github.repository_url }}/releases/latest) on GitHub. Due to [limits on individual files](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases#storage-and-bandwidth-quotas) in GitHub releases, these ISO files have been split into 2GB chunks and can be reassembled with scripts provided for both Bash ([release_cleaver.sh]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/scripts/release_cleaver.sh)) and PowerShell ([release_cleaver.ps1]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/scripts/release_cleaver.ps1)).

For example, having downloaded the following files from Malcolm's releases page on GitHub, the script will join the component files and check the resulting ISOs SHA256 sum:

```bash
$ ls -l
total 5446119424
-rw-r--r-- 1 user user 2000000000 Mar 14 20:03 malcolm-{{ site.malcolm.version }}.iso.01
-rw-r--r-- 1 user user 2000000000 Mar 14 20:03 malcolm-{{ site.malcolm.version }}.iso.02
-rw-r--r-- 1 user user 1446103040 Mar 14 20:03 malcolm-{{ site.malcolm.version }}.iso.03
-rw-r--r-- 1 user user         86 Mar 14 20:03 malcolm-{{ site.malcolm.version }}.iso.sha
-rwxr-xr-x 1 user user       3133 Mar 14 20:02 release_cleaver.sh

$ ./release_cleaver.sh malcolm-{{ site.malcolm.version }}.iso.*
Joining...
malcolm-{{ site.malcolm.version }}.iso: OK

$ ls -l *.iso
-rw-r--r-- 1 user user 5446103040 Mar 14 20:04 malcolm-{{ site.malcolm.version }}.iso
```

Similarly, in Microsoft Windows using PowerShell:

```powershell
PS C:\Download> dir

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         3/14/2024   2:16 PM     2000000000 malcolm-{{ site.malcolm.version }}.iso.01
-a----         3/14/2024   2:16 PM     2000000000 malcolm-{{ site.malcolm.version }}.iso.02
-a----         3/14/2024   2:16 PM     1446103040 malcolm-{{ site.malcolm.version }}.iso.03
-a----         3/14/2024   2:16 PM            176 malcolm-{{ site.malcolm.version }}.iso.sha
-a----         3/14/2024   2:00 PM           6806 release_cleaver.ps1


PS C:\Download> .\release_cleaver.ps1 .\malcolm-{{ site.malcolm.version }}.iso.*
Joining...
"malcolm-{{ site.malcolm.version }}.iso" OK

PS C:\Download> dir *.iso

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         3/14/2024   2:17 PM     5446103040 malcolm-{{ site.malcolm.version }}.iso
```

### <a name="ISOsWarning"></a> Warning

Users should carefully read the [installation documentation](malcolm-iso.md#ISOInstallation). The installer is designed to require as little user input as possible. For this reason, there are NO user prompts and confirmations about partitioning and reformatting hard disks for use by the operating system. The installer assumes that all non-removable storage media (eg., SSD, HDD, NVMe, etc.) are available for use and ⛔🆘😭💀 ***will partition and format them without warning*** 💀😭🆘⛔.
