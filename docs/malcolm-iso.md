# <a name="ISO"></a>Malcolm installer ISO

* [Malcolm installer ISO](#ISO)
    - [Installation](#ISOInstallation)
    - [Generating the ISO](#ISOBuild)
    - [Setup](#ISOSetup)
    - [Time synchronization](time-sync.md#ConfigTime)

Malcolm's Docker-based deployment model makes Malcolm able to run on a variety of platforms. However, in some circumstances (for example, as a long-running appliance as part of a security operations center, or inside of a virtual machine) it may be desirable to install Malcolm as a dedicated standalone installation.

Malcolm can be packaged into an installer ISO based on the current [stable release](https://wiki.debian.org/DebianStable) of [Debian](https://www.debian.org/). This [customized Debian installation](https://wiki.debian.org/DebianLive) is preconfigured with the bare minimum software needed to run Malcolm.

## <a name="ISOBuild"></a>Generating the ISO

Official downloads of the Malcolm installer ISO are not provided: however, it can be built easily on an internet-connected Linux host with Vagrant:

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

To perform a clean build the Malcolm installer ISO, navigate to your local Malcolm working copy and run:

```
$ ./malcolm-iso/build_via_vagrant.sh -f
…
Starting build machine...
Bringing machine 'default' up with 'virtualbox' provider...
…
```

Building the ISO may take 30 minutes or more depending on your system. As the build finishes, you will see the following message indicating success:

```
…
Finished, created "/malcolm-build/malcolm-iso/malcolm-23.05.1.iso"
…
```

By default, Malcolm's Docker images are not packaged with the installer ISO, assuming instead that you will pull the [latest images](https://github.com/orgs/idaholab/packages?repo_name=Malcolm) with a `docker-compose pull` command as described in the [Quick start](quickstart.md#QuickStart) section. If you wish to build an ISO with the latest Malcolm images included, follow the directions to create [pre-packaged installation files](development.md#Packager), which include a tarball with a name like `malcolm_YYYYMMDD_HHNNSS_xxxxxxx_images.tar.gz`. Then, pass that images tarball to the ISO build script with a `-d`, like this:

```
$ ./malcolm-iso/build_via_vagrant.sh -f -d malcolm_YYYYMMDD_HHNNSS_xxxxxxx_images.tar.gz
…
```

A system installed from the resulting ISO will load the Malcolm Docker images upon first boot. This method is desirable when the ISO is to be installed in an "air gapped" environment or for distribution to non-networked machines.

Alternately, if you have forked Malcolm on GitHub, [workflow files]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/.github/workflows/) are provided which contain instructions for GitHub to build the docker images and [sensor](live-analysis.md#Hedgehog) and [Malcolm](#ISO) installer ISOs, specifically [`malcolm-iso-build-docker-wrap-push-ghcr.yml`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/.github/workflows/malcolm-iso-build-docker-wrap-push-ghcr.yml) for the Malcolm ISO. You'll need to run the workflows to build and push your fork's Malcolm docker images before building the ISO. The resulting ISO file is wrapped in a Docker image that provides an HTTP server from which the ISO may be downloaded.

## <a name="ISOInstallation"></a>Installation

The installer is designed to require as little user input as possible. For this reason, there are NO user prompts and confirmations about partitioning and reformatting hard disks for use by the operating system. The  installer assumes that all non-removable storage media (eg., SSD, HDD, NVMe, etc.) are available for use and ⛔🆘😭💀 ***will partition and format them without warning*** 💀😭🆘⛔.

The installer will ask for several pieces of information prior to installing the Malcolm base operating system:

* Hostname
* Domain name
* Root password – (optional) a password for the privileged root account which is rarely needed
* User name: the name for the non-privileged service account user account under which the Malcolm runs
* User password – a password for the non-privileged sensor account
* Encryption password (optional) – if the encrypted installation option was selected at boot time, the encryption password must be entered every time the system boots

At the end of the installation process, you will be prompted with a few self-explanatory yes/no questions:

* **Disable IPv6?**
* **Automatically login to the GUI session?**
* **Should the GUI session be locked due to inactivity?**
* **Display the [Standard Mandatory DoD Notice and Consent Banner](https://www.stigviewer.com/stig/application_security_and_development/2018-12-24/finding/V-69349)?** *(only applies when installed on U.S. government information systems)*

Following these prompts, the installer will reboot and the Malcolm base operating system will boot.

## <a name="ISOSetup"></a>Setup

When the system boots for the first time, the Malcolm Docker images will load if the installer was built with pre-packaged installation files as described above. Wait for this operation to continue (the progress dialog will disappear when they have finished loading) before continuing the setup.

Open a terminal (click the red terminal 🗔 icon next to the Debian swirl logo 🍥 menu button in the menu bar). At this point, setup is similar to the steps described in the [Quick start](quickstart.md#QuickStart) section. Navigate to the Malcolm directory (`cd ~/Malcolm`) and run [`auth_setup`](authsetup.md#AuthSetup) to configure authentication. If the ISO didn't have pre-packaged Malcolm images, or if you'd like to retrieve the latest updates, run `docker-compose pull`. Finalize your configuration by running `scripts/configure` and follow the prompts as illustrated in the [installation example](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig).

Once Malcolm is configured, you can [start Malcolm](running.md#Starting) via the command line or by clicking the circular yellow Malcolm icon in the menu bar.