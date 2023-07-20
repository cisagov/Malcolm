# <a name="HedgehogISOBuild"></a>Appendix A - Generating the ISO

Official downloads of the Hedgehog Linux installer ISO are not provided: however, it can be built easily on an internet-connected Linux host with Vagrant:

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

To perform a clean build the Hedgehog Linux installer ISO, navigate to your local [Malcolm]({{ site.github.repository_url }}/) working copy and run:

```
$ ./sensor-iso/build_via_vagrant.sh -f
…
Starting build machine...
Bringing machine 'default' up with 'virtualbox' provider...
…
```

Building the ISO may take 90 minutes or more depending on your system. As the build finishes, you will see the following message indicating success:

```
…
Finished, created "/sensor-build/hedgehog-23.07.1.iso"
…
```

Alternately, if you have forked Malcolm on GitHub, [workflow files]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/.github/workflows/) are provided which contain instructions for GitHub to build the docker images and Hedgehog and [Malcolm]({{ site.github.repository_url }}) installer ISOs, specifically [`sensor-iso-build-docker-wrap-push-ghcr.yml`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/.github/workflows/sensor-iso-build-docker-wrap-push-ghcr.yml) for the Hedgehog ISO. The resulting ISO file is wrapped in a Docker image that provides an HTTP server from which the ISO may be downloaded.