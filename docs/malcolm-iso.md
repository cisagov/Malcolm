# <a name="ISO"></a>Malcolm installer ISO

* [Malcolm installer ISO](#ISO)
    - [Installation](#ISOInstallation)
    - [Generating the ISO](#ISOBuild)
    - [Setup](#ISOSetup)
        + [Network Interface Configuration](#NetConf)
    - [Time synchronization](time-sync.md#ConfigTime)

Malcolm's container-based deployment model allows Malcolm to run on a variety of platforms. However, in some circumstances (for example, as a long-running appliance as part of a security operations center, or inside a virtual machine) it may be desirable to install Malcolm as a dedicated standalone installation.

Malcolm can be packaged into an installer ISO based on the current [stable release](https://wiki.debian.org/DebianStable) of [Debian](https://www.debian.org/). This [customized Debian installation](https://wiki.debian.org/DebianLive) is preconfigured with the bare minimum software needed to run Malcolm.

## <a name="ISOBuild"></a>Generating the ISO

Official downloads of the Malcolm installer ISO [can be downloaded](download.md#DownloadISOs) from the GitHub releases page. It can also be built easily on an Internet-connected system with Vagrant:

* [Vagrant](https://www.vagrantup.com/)
    - [`bento/debian-13`](https://app.vagrantup.com/bento/boxes/debian-13) Vagrant box

The build should work with a variety of [Vagrant providers](https://developer.hashicorp.com/vagrant/docs/providers):

* [VMware](https://www.vmware.com/) [provider](https://developer.hashicorp.com/vagrant/docs/providers/vmware)
    - [`vagrant-vmware-desktop`](https://github.com/hashicorp/vagrant-vmware-desktop) plugin
* [libvirt](https://libvirt.org/) 
    - [`vagrant-libvirt`](https://github.com/vagrant-libvirt/vagrant-libvirt) provider plugin
    - [`vagrant-mutate`](https://github.com/sciurus/vagrant-mutate) plugin to convert [`bento/debian-13`](https://app.vagrantup.com/bento/boxes/debian-13) Vagrant box to `libvirt` format
* [VirtualBox](https://www.virtualbox.org/) [provider](https://developer.hashicorp.com/vagrant/docs/providers/virtualbox)
    - [`vagrant-vbguest`](https://github.com/dotless-de/vagrant-vbguest) plugin

To perform a clean build of the Malcolm installer ISO, navigate to the local Malcolm working copy and run:

```
$ ./malcolm-iso/build_via_vagrant.sh -f -i malcolm
…
Starting build machine...
Bringing machine 'default' up with 'virtualbox' provider...
…
```

Similarly, to build the [Hedgehog Linux](hedgehog.md) flavor of the ISO:

```
$ ./malcolm-iso/build_via_vagrant.sh -f -i hedgehog
```

Building the ISO may take 30 minutes or more depending on the system. As the build finishes, users will see the following message indicating success:

```
…
Finished, created "/malcolm-build/malcolm-iso/malcolm-{{ site.malcolm.version }}.iso"
…
```

By default, Malcolm's images are not packaged with the installer ISO. Malcolm assumes instead that users will pull the [latest images](https://github.com/orgs/idaholab/packages?repo_name=Malcolm) with a `docker compose --profile malcolm pull` command as described in the [Quick start](quickstart.md#QuickStart) section. To build an ISO with the latest Malcolm images included, follow the directions to create [pre-packaged installation files](development.md#Packager), which include a tarball with a name such as `malcolm_YYYYMMDD_HHNNSS_xxxxxxx_images.tar.xz`. Then, pass that images tarball to the ISO build script with a `-d`, like this:

```
$ ./malcolm-iso/build_via_vagrant.sh -f -i malcolm -d malcolm_YYYYMMDD_HHNNSS_xxxxxxx_images.tar.xz
…
```

A system installed from the resulting ISO will load the Malcolm images upon first boot. This method is desirable when the ISO is to be installed in an "air gapped" environment or for distribution to non-networked machines.

Alternatively, if users have forked Malcolm on GitHub, [workflow files]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/.github/workflows/) are provided that contain instructions for GitHub to build the images and [sensor](live-analysis.md#Hedgehog) and [Malcolm](#ISO) installer ISOs - specifically [`malcolm-iso-build-docker-wrap-push-ghcr.yml`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/.github/workflows/malcolm-iso-build-docker-wrap-push-ghcr.yml) for the Malcolm ISO. Users must run the workflows to build and push the fork's Malcolm images before building the ISO. The resulting ISO file is wrapped in a image that provides an HTTP server from which the ISO may be downloaded.  See [Using GitHub runners to build Malcolm images](contributing-github-runners.md#GitHubRunners) for more information.

## <a name="ISOInstallation"></a>Installation

The installer is designed to require as little user input as possible. For this reason, there are NO user prompts and confirmations about partitioning and reformatting hard disks for use by the operating system. The  installer assumes all non-removable storage media (eg., SSD, HDD, NVMe, etc.) are available for use and ⛔🆘😭💀 ***will partition and format them without warning*** 💀😭🆘⛔.

The installer will ask for several pieces of information prior to installing the Malcolm base operating system:

* Hostname
* Domain name
* Root password – (optional) a password for the privileged root account that is rarely needed
* User name: the name for the non-privileged service account user account under which the Malcolm runs
* User password – a password for the non-privileged sensor account
* Encryption password (optional) – if encrypted installation option was selected at boot time, the encryption password must be entered every time the system boots

At the end of the installation process, users will be prompted with the following self-explanatory yes/no questions:

* **Format non-OS drive(s) for artifact storage?**
* **Disable IPv6?**
* **Automatically login to the GUI session?**
* **Should the GUI session be locked due to inactivity?**
* **Display the [Standard Mandatory DoD Notice and Consent Banner](https://www.stigviewer.com/stig/application_security_and_development/2018-12-24/finding/V-69349)?** *(only applies when installed on U.S. government information systems)*
* **Allow SSH password authentication?** *(Caution: password authentication is less secure than public/private key pairs)*

Following these prompts, the installer will reboot and the Malcolm base operating system will boot.

## <a name="ISOSetup"></a>Setup

When the system boots for the first time, the Malcolm images will load if the installer was built with pre-packaged installation files as described above. Wait for this operation to continue (the progress dialog will disappear when they have finished loading) before continuing the setup.

Open a terminal (click the red terminal 🗔 icon next to the Debian swirl logo 🍥 menu button in the menu bar). At this point, setup is similar to the steps described in the [Quick start](quickstart.md#QuickStart) section. Navigate to the Malcolm directory (`cd ~/Malcolm`) and run [`auth_setup`](authsetup.md#AuthSetup) to configure authentication. If the ISO does not include pre-packaged Malcolm images, or to retrieve the latest updates, run `docker compose --profile malcolm pull`. Finalize the configuration by running `scripts/configure` and follow the prompts as illustrated in the [installation example](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig).

Once Malcolm is configured, users can [start Malcolm](running.md#Starting) via the command line or by clicking the "play" icon (▷) in the menu bar.

### <a name="NetConf"></a>Network Interface Configuration

The Malcolm base operating system does not use Dynamic Host Configuration Protocol (DHCP) to assign IP addresses to any ethernet interfaces by default. To configure DHCP, click the icon for the NetworkManager applet in the system tray and select **Auto Ethernet**:

![Auto Ethernet](./images/screenshots/malcolm-desktop-ethernet-auto.png)

Alternatively, to configure a network interface with a static IP address:

1. Right-click the icon for the NetworkManager applet in the system tray and select **Edit Connections**

![Edit Connections](./images/screenshots/malcolm-desktop-ethernet-manual-1.png)

2. Click the plus ➕ icon on the **Network Connections** dialog

![Add a new connection](./images/screenshots/malcolm-desktop-ethernet-manual-2.png)

3. Select **Ethernet** for the Connection Type

![Connection type](./images/screenshots/malcolm-desktop-ethernet-manual-3.png)

4. On the **Ethernet** tab, select the **Device** (e.g., `eth0`, `enp1s0`, etc.) on

![Device selection](./images/screenshots/malcolm-desktop-ethernet-manual-4.png)

5. On the **IPv4 Settings** tab, set the method **Manual** and add the address/netmask/gateway and specify DNS servers, if applicable

![IPv4 settings](./images/screenshots/malcolm-desktop-ethernet-manual-5.png)

6. Click **Save**