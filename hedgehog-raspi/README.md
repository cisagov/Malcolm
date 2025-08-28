# Raspberry Pi Hedgehog Sensor Build

This build process builds upon the Debian RPi build process located here:
http://salsa.debian.org/raspi-team/image-specs

## Building an image

Steps to build a Hedgehog Raspberry Pi image.
If you are reading this document online, you should first
clone this repository:

```shell
git clone https://github.com/idaholab/Malcolm.git
cd Malcolm/hedgehog-raspi
```

For this you will first need to install the following packages on a
Debian Bullseye (11), Devuan Daedalus (5), or higher system:

* binfmt-support
* bmap-tools
* debootstrap
* dosfstools
* fakemachine (optional, only available on amd64)
* kpartx
* qemu-utils
* qemu-user-static
* time
* vmdb2 (>= 0.17)
* python3
* zerofree (because of [#1021341](https://bugs.debian.org/1021341))

To install these (as root):
```shell
   apt install -y vmdb2 dosfstools qemu-utils qemu-user-static debootstrap binfmt-support time kpartx bmap-tools python3 zerofree
   apt install -y fakemachine
```

If debootstrap still fails with exec format error, try
running `dpkg-reconfigure qemu-user-static`. This calls
`/var/lib/dpkg/info/qemu-user-static.postinst` which uses binfmt-support
to register the executable format with /usr/bin/qemu-$fmt-static

This repository includes a master YAML recipe (which is basically a
configuration file) for all of the generated images, diverting as
little as possible in a parametrized way. The master recipe is
[raspi_master.yaml](raspi_master.yaml).

A Makefile is supplied to drive the build of the recipes into images.
If `fakemachine` is installed, it can be run as an unprivileged user.
Otherwise, because some steps of building the image require root privileges,
you'll need to execute `make` as root.

The argument to `make` is constructed as follows:
`raspi_<model>_<release>.<result-type>`

Whereby <model\> is one of `4` or `5`; <release\> is `trixie`; and <result-type\> is `img` or `yaml`.

Model `4` for all models of the Raspberry Pi 4, and model `5` for all models of the Raspberry Pi 5.
So if you want to build the default image for a Raspberry Pi 4 with Trixie, you can just issue:

```shell
   make raspi_4_trixie.img
```

At this point; it might be wise to go do something else. The build **WILL** take a while. 

**NOTE:** While this setup will build hedgehog for all raspberry pi variants, it is highly unlikely 
that any variant other than RPI 4 (8GB version) or higher will have adequate resources to function effectively as a sensor.

**NOTE:** Raspberry Pi 5 is **not yet supported** due to missing upstream kernel support. See the following resources:

* [Debian Wiki](https://raspi.debian.net/faq/#faq-rpi5)
* [Debian Mailing list, March 2024](https://lists.debian.org/debian-arm/2024/03/msg00009.html)
* [Debian Mailing list, November 2023](https://lists.debian.org/debian-arm/2023/11/msg00025.html)

## Installing the image onto the Raspberry Pi

If the build completes properly, it can be tested locally before writing to an SD card if desired.
To do so, simply run (as root):

```shell
   mount -o loop,offset=$((1048576*512)) raspi_4_trixie.img /mnt && chroot /mnt
```

If an error is returned by the mount command, there is a chance the image was corrupted during the build.
It is, unfortunately, advised to run `make clean` and rebuild the image. 

Plug an SD card which you would like to **entirely OVERWRITE** into the Build machine's SD card reader.

Assuming your SD card reader provides the device `/dev/mmcblk0`
(**Beware** If you choose the wrong device, you might overwrite
important parts of your system.  Double check it's the correct
device!), copy the image onto the SD card:

```shell
bmaptool copy raspi_3_trixie.img.xz /dev/mmcblk0
```

Alternatively, if you don't have `bmap-tools` installed, you can use
`dd` with the compressed image:

```shell
xzcat raspi_3_trixie.img.xz | dd of=/dev/mmcblk0 bs=64k oflag=dsync status=progress
```

Or with the uncompressed image:

```shell
dd if=raspi_3_trixie.img of=/dev/mmcblk0 bs=64k oflag=dsync status=progress
```

Then, plug the SD card into the Raspberry Pi, and power it up.

The image uses the hostname `Hedgehog-rpi-0w`, `Hedgehog-rpi-2`, `Hedgehog-rpi-3`, `Hedgehog-rpi-4`, `Hedgehog-rpi-5` depending on the
target build. The provided image will allow you to log in with the
`sensor` account with a default password of `Hedgehog_Linux` or 
`root` account with a default password of `Hedgehog_Linux_Root`, but only logging in at the
physical console (be it serial or by USB keyboard and HDMI monitor).
