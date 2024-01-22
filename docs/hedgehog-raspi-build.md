# <a name="HedgehogRaspiBuild"></a>Appendix B - Generating a Raspberry Pi Image

Hedgehog Linux can [also be built]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/sensor-raspi) for the Raspberry Pi platform. While these instructions will build an image for various Raspberry Pi models, Hedgehog Linux resource requirements will likely only be satisfied by the 8GB versions of the Raspberry Pi model 4 and higher. The resulting image is still considered experimental.

Official downloads of the Hedgehog Linux Raspberry Pi image are not provided: however, it can be built easily on an internet-connected Linux host with Vagrant:

* [Vagrant](https://www.vagrantup.com/)
    - [`vagrant-sshfs`](https://github.com/dustymabe/vagrant-sshfs) plugin
    - [`bento/debian-12`](https://app.vagrantup.com/bento/boxes/debian-12) Vagrant box

The build should work with either the [VirtualBox](https://www.virtualbox.org/) provider or the [libvirt](https://libvirt.org/) provider:

* [VirtualBox](https://www.virtualbox.org/) [provider](https://www.vagrantup.com/docs/providers/virtualbox)
    - [`vagrant-vbguest`](https://github.com/dotless-de/vagrant-vbguest) plugin
* [libvirt](https://libvirt.org/) 
    - [`vagrant-libvirt`](https://github.com/vagrant-libvirt/vagrant-libvirt) provider plugin
    - [`vagrant-mutate`](https://github.com/sciurus/vagrant-mutate) plugin to convert [`bento/debian-12`](https://app.vagrantup.com/bento/boxes/debian-12) Vagrant box to `libvirt` format

To perform a clean build the Hedgehog Linux Raspberry Pi image, navigate to your local [Malcolm]({{ site.github.repository_url }}/) working copy and run:

```
$ ./sensor-raspi/build_via_vagrant.sh -f -z
…
Starting build machine...
Bringing machine 'vagrant-hedgehog-raspi-build' up with 'virtualbox' provider...
…
```

As this build process is cross-compiling for the ARM64 architecture, building the image is likely to take more than five hours depending on your system. As the build finishes, you will see the following message indicating success:

```
…
2024-01-21 05:11:44 INFO All went fine.
2024-01-21 05:11:44 DEBUG Ending, all OK
…
```

The resulting `.img.xz` file can be written to a microSD card using the [Raspberry Pi Imager](https://www.raspberrypi.com/documentation/computers/getting-started.html#raspberry-pi-imager) or `dd`.

The provided image will allow login (requiring physical access) with the `sensor` account using a default password of `Hedgehog_Linux` or the `root` account with a default password of `Hedgehog_Linux_Root`. It is **highly** recommended for users to use the `passwd` utility to change both of these passwords prior to configuring networking on the device.

Once Hedgehog Linux has booted, [configuration](malcolm-hedgehog-e2e-iso-install.md#HedgehogInstallAndConfig) can proceed as usual using the `configure-interfaces` and `configure-capture` tools.