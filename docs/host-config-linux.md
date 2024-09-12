# <a name="HostSystemConfigLinux"></a>Linux host system configuration

## Docker

### Installing Docker

Docker installation instructions vary slightly by distribution. Please follow the links below to docker.com to find the instructions specific to your distribution:

* [Ubuntu](https://docs.docker.com/install/linux/docker-ce/ubuntu/)
* [Debian](https://docs.docker.com/install/linux/docker-ce/debian/)
* [Fedora](https://docs.docker.com/install/linux/docker-ce/fedora/)
* [CentOS](https://docs.docker.com/install/linux/docker-ce/centos/)
* [Binaries](https://docs.docker.com/install/linux/docker-ce/binaries/)

After installing Docker, because Malcolm should be run as a non-root user, add your user to the `docker` group with something like:
```
$ sudo usermod -aG docker yourusername
```

Following this, either reboot or log out, then log back in.

Docker starts automatically on DEB-based distributions. On RPM-based distributions, users must start Docker manually or enable it using the appropriate `systemctl` or `service` command(s).

You can test Docker by running `docker info`, or (assuming you have internet access), `docker run --rm hello-world`.

### Installing docker compose

Please follow [this link](https://docs.docker.com/compose/install/) on docker.com for instructions on installing the Docker Compose plugin.

## Operating system configuration

The host system (i.e., the one running Docker) must be configured for the [best possible OpenSearch performance](https://www.elastic.co/guide/en/elasticsearch/reference/master/system-config.html). Here are a few suggestions for Linux hosts (these may vary from distribution to distribution):

* Append the following lines to `/etc/sysctl.conf`:

```
# the maximum number of open file handles
fs.file-max=2097152

# increase maximums for inotify watches
fs.inotify.max_user_watches=131072
fs.inotify.max_queued_events=131072
fs.inotify.max_user_instances=512

# the maximum number of memory map areas a process may have
vm.max_map_count=262144

# decrease "swappiness" (swapping out runtime memory vs. dropping pages)
vm.swappiness=1

# the maximum number of incoming connections
net.core.somaxconn=65535

# the % of system memory fillable with "dirty" pages before flushing
vm.dirty_background_ratio=40

# maximum % of dirty system memory before committing everything
vm.dirty_ratio=80
```

* Depending on your distribution, create **either** the file `/etc/security/limits.d/limits.conf` containing:

```
# the maximum number of open file handles
* soft nofile 65535
* hard nofile 65535
# do not limit the size of memory that can be locked
* soft memlock unlimited
* hard memlock unlimited
```

**OR** the file `/etc/systemd/system.conf.d/limits.conf` containing: 

```
[Manager]
# the maximum number of open file handles
DefaultLimitNOFILE=65535:65535
# do not limit the size of memory that can be locked
DefaultLimitMEMLOCK=infinity
```

* Change the readahead value for the disk where the OpenSearch data will be stored. There are a few ways to do this. For example, users could add this line to `/etc/rc.local` (replacing `/dev/sda` with their disk block descriptor):

```
# change disk read-adhead value (# of blocks)
blockdev --setra 512 /dev/sda
```

* Change the I/O scheduler to `deadline` or `noop`. Again, this can be done in a variety of ways. The simplest is to add `elevator=deadline` to the arguments in `GRUB_CMDLINE_LINUX` in `/etc/default/grub`, then running `sudo update-grub2`

* If you are planning on using very large data sets, consider formatting the drive containing the `opensearch` volume as XFS.

After making allthese changes, do a reboot for good measure!

## Podman

Malcolm can run on [Podman](https://podman.io) as a rootless alternative to Docker. When [Running Malcolm](running.md#Running) with Podman, [`podman compose`](https://docs.podman.io/en/latest/markdown/podman-compose.1.html) is used as a wrapper around an external compose provider (such as [`docker-compose`](https://docs.docker.com/compose/) or [`podman-compose`](https://github.com/containers/podman-compose)) which in turn uses the Podman back end to run and orchestrate containers. The same Malcolm runtime scripts (e.g., `./scripts/start`, `./scripts/stop`, etc.) are used whether using Docker or Podman.

Installation and configuration of Podman is not covered in this documentation. Please see the Podman [documentation](https://podman.io/docs/installation#installing-on-linux).

It should be noted that if rootless Podman is used, Malcolm itself cannot perform [traffic capture on local network interfaces](live-analysis.md#LocalPCAP), although it can accept network traffic metadata forwarded from a [a network sensor appliance](live-analysis.md#Hedgehog).