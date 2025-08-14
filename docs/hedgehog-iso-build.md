# <a name="HedgehogISOBuild"></a>Appendix A - Generating the ISO

Official downloads of the Hedgehog Linux installer ISO [can be downloaded](download.md#DownloadISOs) from the GitHub releases page. It can also be built easily on an Internet-connected system with Vagrant:

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


To perform a clean build the Hedgehog Linux installer ISO, navigate to your local [Malcolm]({{ site.github.repository_url }}/) working copy and run:

```
$ ./hedgehog-iso/build_via_vagrant.sh -f
…
Starting build machine...
Bringing machine 'default' up with 'virtualbox' provider...
…
```

Building the ISO may take 90 minutes or more depending on your system. As the build finishes, you will see the following message indicating success:

```
…
Finished, created "/sensor-build/hedgehog-{{ site.malcolm.version }}.iso"
…
```

Alternately, if you have forked Malcolm on GitHub, [workflow files]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/.github/workflows/) are provided which contain instructions for GitHub to build the images and Hedgehog and [Malcolm]({{ site.github.repository_url }}) installer ISOs, specifically [`hedgehog-iso-build-docker-wrap-push-ghcr.yml`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/.github/workflows/hedgehog-iso-build-docker-wrap-push-ghcr.yml) for the Hedgehog ISO. The resulting ISO file is wrapped in a image that provides an HTTP server from which the ISO may be downloaded. See [Using GitHub runners to build Malcolm images](contributing-github-runners.md#GitHubRunners) for more information.