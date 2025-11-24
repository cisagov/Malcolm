# <a name="HostSystemConfigLinux"></a>Linux host system configuration

For most Linux distributions, Malcolm's `install.py` script will perform the steps listed in this document -- installing Docker, configuring the Linux kernel and other OS parameters, etc. -- automatically. See the **Installation example using Ubuntu 24.04 LTS**](ubuntu-install-example.md#UIOpts) for an example. However, this document is provided as a reference for users who would prefer to do it manually

## Operating system configuration

The host system (i.e., the one running Docker or Podman) must be configured for the [best possible OpenSearch performance](https://www.elastic.co/guide/en/elasticsearch/reference/master/system-config.html). Here are a few suggestions for Linux hosts (these may vary from distribution to distribution):

* Append the following lines to `/etc/sysctl.d/99-sysctl-performance.conf`:

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

# virtual memory accounting mode: always overcommit, never check
vm.overcommit_memory=1
```

* In addition, the [some suggest](https://www.elastic.co/guide/en/elasticsearch/reference/current/system-config-tcpretries.html) lowering the TCP retransmission timeout to `5`. However, if your host communicates with other systems over a low-quality network, this low of a setting may be detrimental to those communications. To set this value, add the following to `/etc/sysctl.d/99-sysctl-performance.conf`:

```
# maximum number of TCP retransmissions
net.ipv4.tcp_retries2=5
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

* Change the I/O scheduler to `deadline` or `noop`. Again, this can be done in a variety of ways. The simplest is to add `elevator=deadline` to the arguments in `GRUB_CMDLINE_LINUX` in `/etc/default/grub`, then running `sudo update-grub`.

* Enable cgroup accounting for memory and swap space. This can be done by adding `systemd.unified_cgroup_hierarchy=1 cgroup_enable=memory swapaccount=1 cgroup.memory=nokmem` to the arguments in `GRUB_CMDLINE_LINUX` in `/etc/default/grub`, then running `sudo update-grub`.

* If you are planning on using very large data sets, consider formatting the drive containing the `opensearch` volume as XFS.

After making allthese changes, do a reboot for good measure!

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

## <a name="HostSystemConfigLinuxPodman"></a>Podman

Malcolm can run on [Podman](https://podman.io) as a rootless alternative to Docker. The same Malcolm runtime scripts (e.g., `./scripts/start`, `./scripts/stop`, etc.) are used whether using Docker or Podman. When [running Malcolm](running.md#Running) with Podman, [`podman compose`](https://docs.podman.io/en/latest/markdown/podman-compose.1.html) is used as a wrapper around an external compose provider (such as [`docker-compose`](https://docs.docker.com/compose/)), which in turn uses the Podman back end to run and orchestrate containers. It is recommended to use the `docker-compose` compose provider rather than [`podman-compose`](https://github.com/containers/podman-compose) since it is the original implementation of the Compose specification and is widely used on the supported platforms and because there are known issues with using the `podman-compose` provider to start Malcolm.

It should be noted that if rootless Podman is used, Malcolm itself cannot perform [traffic capture on local network interfaces](live-analysis.md#LocalPCAP), although it can accept network traffic metadata forwarded from a [a network sensor appliance](live-analysis.md#Hedgehog).

### Podman installation example

Although Malcolm can use Podman, Malcolm's [`install.py`](ubuntu-install-example.md#UIOpts) script does not attempt to [install or configure Podman](https://podman.io/docs/installation) because the procedure differs between distributions. In most cases, Podman can be installed from distributions' default package repositories using `apt`/`apt-get`, `yum`, `dnf`, etc.. Podman v5.6.0 or higher is recommended due to fixes relating to user namespace management. Some third-party repositories provide more up-to-date packages for Podman and its dependencies.

The following process of installing and configuring Podman is for example's sake only, and may not represent what's required on each Linux distribution. This example uses a fresh instance of the Ubuntu 24.04 LTS cloud image as its basis and the third-party [alvistack](https://software.opensuse.org/download/package?package=podman&project=home%3Aalvistack) repository as the package source for Podman, but the steps will be similar on other distributions.

* Initial Podman installation and system tweaks

```bash
$ sudo apt-get update
…
Fetched 38.6 MB in 8s (4901 kB/s)

$ apt-cache policy podman
podman:
  Installed: (none)
  Candidate: 4.9.3+ds1-1ubuntu0.2
  …

$ echo 'deb [signed-by=/etc/apt/trusted.gpg.d/home_alvistack.gpg] http://download.opensuse.org/repositories/home:/alvistack/xUbuntu_24.04/ /' \
  | sudo tee /etc/apt/sources.list.d/home:alvistack.list >/dev/null

$ curl -fsSL https://download.opensuse.org/repositories/home:alvistack/xUbuntu_24.04/Release.key \
  | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/home_alvistack.gpg >/dev/null

$ sudo tee /etc/apt/preferences.d/99-home_alvistack >/dev/null <<'EOT'
Package: *
Pin: origin download.opensuse.org
Pin-Priority: 1

Package: buildah catatonit conmon containernetworking containernetworking-plugins containers-common cri-o-runc crun libcharon-standard-plugins libslirp0 passt podman podman-aardvark-dns podman-netavark python3-podman-compose slirp4netns
Pin: origin download.opensuse.org
Pin-Priority: 1001
EOT

$ sudo apt-get update
…
Get:5 http://download.opensuse.org/repositories/home:/alvistack/xUbuntu_24.04  InRelease [1551 B]
Get:6 http://downloadcontentcdn.opensuse.org/repositories/home:/alvistack/xUbuntu_24.04  Packages [170 kB]
Fetched 172 kB in 3s (61.8 kB/s)
Reading package lists... Done

$ apt-cache policy podman
podman:
  Installed: (none)
  Candidate: 100:5.6.2-1
  …

$ sudo apt-get install -y \
    buildah \
    catatonit \
    crun \
    fuse-overlayfs \
    passt \
    podman \
    podman-aardvark-dns \
    podman-netavark \
    slirp4netns \
    uidmap
…
Setting up podman (100:5.6.2-1) ...
…

$ grep -q unprivileged_userns_clone /etc/sysctl.d/* || \
    sudo tee -a /etc/sysctl.d/99-userns.conf >/dev/null <<'EOT'
# allow unprivileged user namespaces
kernel.unprivileged_userns_clone=1
EOT

$ grep -q ip_unprivileged_port_start /etc/sysctl.d/* || \
    sudo tee -a /etc/sysctl.d/99-lowport.conf >/dev/null <<'EOT'
# allow lower unprivileged port bind
net.ipv4.ip_unprivileged_port_start=443
EOT

$ sudo mkdir -p /etc/modprobe.d && \
    echo "options overlay metacopy=off redirect_dir=off" \
    | sudo tee /etc/modprobe.d/podman.conf >/dev/null

$ [[ -d /etc/systemd/system ]] && \
    sudo mkdir -p /etc/systemd/system/user@.service.d && \
    echo -e "[Service]\\nDelegate=cpu cpuset io memory pids" \
    | sudo tee /etc/systemd/system/user@.service.d/delegate.conf >/dev/null

$ sudo touch /etc/subuid && sudo touch /etc/subgid

$ grep --quiet johndoe /etc/subuid || sudo usermod --add-subuids 200000-265535 johndoe

$ grep --quiet johndoe /etc/subgid || sudo usermod --add-subgids 200000-265535 johndoe

$ sudo loginctl enable-linger johndoe

$ sudo usermod -a -G systemd-journal johndoe

$ mkdir -p /run/user/1000/podman

$ systemctl --user enable --now podman.service

$ mkdir -p ~/.docker/cli-plugins && \
    curl -fsSL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64 \
        -o ~/.docker/cli-plugins/docker-compose && \
    chmod 755 ~/.docker/cli-plugins/docker-compose

$ mkdir -p ~/.config/containers && \
    tee -a ~/.config/containers/containers.conf >/dev/null <<'EOT'
[engine]

runtime="crun"
compose_warning_logs=false

[containers]

default_ulimits = [
  "memlock=9223372036854775807:9223372036854775807",
  "nofile=65535:65535",
  "nproc=262143:524287"
]

[network]

default_subnet_pools = [
  {"base" = "172.27.0.0/16", "size" = 24},
]
EOT
```

* Clone Malcolm and run `install.py` for the performance-related system tweaks

```bash
$ git clone https://github.com/idaholab/Malcolm
Cloning into 'Malcolm'...
remote: Enumerating objects: 57191, done.
remote: Counting objects: 100% (872/872), done.
remote: Compressing objects: 100% (96/96), done.
remote: Total 57191 (delta 813), reused 790 (delta 772), pack-reused 56319 (from 2)
Receiving objects: 100% (57191/57191), 237.41 MiB | 4.05 MiB/s, done.
Resolving deltas: 100% (42544/42544), done.

$ sudo apt-get install -y \
    python3-pip \
    python3-ruamel.yaml \
    python3-dotenv \
    python3-dialog \
    dialog
…

$ sudo ./scripts/install.py --skip-splash
```

```
--- Malcolm Configuration Menu ---
Select an item number to configure, or an action:
├── 1. Container Runtime (current: docker)
…
--- Actions ---
  s. Save and Continue Installation
  w. Where Is...? (search for settings)
  x. Exit Installer
---------------------------------

Enter item number or action: 1
Container Runtime (current: docker)
1: docker
2: podman
3: kubernetes
Enter choice number (docker): 2
```

```
--- Malcolm Configuration Menu ---
Select an item number to configure, or an action:
├── 1. Container Runtime (current: podman)
…
--- Actions ---
  s. Save and Continue Installation
  w. Where Is...? (search for settings)
  x. Exit Installer
---------------------------------

Enter item number or action: s
```

```
--- Malcolm Installation Options ---
Select an item number to configure, or an action:
└── 1. Automatically Apply System Tweaks (current: Yes)

--- Actions ---
  s. Save and Continue
  x. Exit Installer

Enter item number or action: s
```

```
============================================================
FINAL CONFIGURATION SUMMARY
============================================================
Configuration Only                                : No
Auto Apply System Tweaks                          : Yes
Configuration Directory                           : /home/johndoe/Malcolm/config
Container Runtime                                 : podman
Run Profile                                       : malcolm
Process UID/GID                                   : 1000/1000
Container Restart Policy                          : No
Container Network                                 : default
Default Storage Locations                         : Yes
HTTPS/SSL                                         : Yes
Node Name                                         : ubuntu-noble-191
============================================================

Proceed with Malcolm installation using the above configuration? (y / N): y
…
[2025-11-05 18:17:34] (SUCCESS) [INSTALLER]: Installation completed successfully
```

* Reboot the system to take new settings into effect, then verify settings and Podman installation

```bash
$ sudo reboot

…

$ cat /proc/cmdline
BOOT_IMAGE=/vmlinuz-6.8.0-85-generic root=UUID=52645fa4-47a3-4335-8817-2637487e1980 ro systemd.unified_cgroup_hierarchy=1 cgroup_enable=memory swapaccount=1 cgroup.memory=nokmem console=tty1 console=ttyS0

$ ulimit -a
real-time non-blocking time  (microseconds, -R) unlimited
core file size              (blocks, -c) 0
data seg size               (kbytes, -d) unlimited
scheduling priority                 (-e) 0
file size                   (blocks, -f) unlimited
pending signals                     (-i) 128240
max locked memory           (kbytes, -l) unlimited
max memory size             (kbytes, -m) unlimited
open files                          (-n) 65535
pipe size                (512 bytes, -p) 8
POSIX message queues         (bytes, -q) 819200
real-time priority                  (-r) 0
stack size                  (kbytes, -s) 8192
cpu time                   (seconds, -t) unlimited
max user processes                  (-u) 262144
virtual memory              (kbytes, -v) unlimited
file locks                          (-x) unlimited

$ cat /etc/sysctl.d/99* | grep -v '^#' | cut -d= -f1 | xargs -r -l sysctl
net.ipv6.conf.all.use_tempaddr = 0
net.ipv6.conf.default.use_tempaddr = 0
fs.file-max = 2097152
fs.inotify.max_user_watches = 131072
fs.inotify.max_queued_events = 131072
fs.inotify.max_user_instances = 512
vm.max_map_count = 262144
vm.swappiness = 1
vm.dirty_background_ratio = 40
vm.dirty_ratio = 80
vm.overcommit_memory = 1
net.core.somaxconn = 65535
net.ipv4.tcp_retries2 = 5
net.ipv4.ip_unprivileged_port_start = 443
kernel.unprivileged_userns_clone = 1

$ podman info
host:
  arch: amd64
  buildahVersion: 1.41.5
  cgroupControllers:
  - cpuset
  - cpu
  - io
  - memory
  - pids
  cgroupManager: systemd
  cgroupVersion: v2
  conmon:
    package: conmon_100:2.1.13-1_amd64
    path: /usr/bin/conmon
    version: 'conmon version 2.1.13, commit: e21e7c85b7637e622f21c57675bf1154fc8b1866'
  cpuUtilization:
    idlePercent: 97.65
    systemPercent: 1.28
    userPercent: 1.07
  cpus: 8
  databaseBackend: sqlite
  distribution:
    codename: noble
    distribution: ubuntu
    version: "24.04"
  eventLogger: journald
  freeLocks: 2048
  hostname: ubuntu-noble-126
  idMappings:
    gidmap:
    - container_id: 0
      host_id: 1000
      size: 1
    - container_id: 1
      host_id: 100000
      size: 65536
    uidmap:
    - container_id: 0
      host_id: 1000
      size: 1
    - container_id: 1
      host_id: 100000
      size: 65536
  kernel: 6.8.0-85-generic
  linkmode: dynamic
  logDriver: journald
  memFree: 33095901184
  memTotal: 33655021568
  networkBackend: netavark
  networkBackendInfo:
    backend: netavark
    dns:
      package: podman-aardvark-dns_100:1.16.0-1_amd64
      path: /usr/libexec/podman/aardvark-dns
      version: aardvark-dns 1.16.0
    package: podman-netavark_100:1.16.1-1_amd64
    path: /usr/libexec/podman/netavark
    version: netavark 1.16.1
  ociRuntime:
    name: crun
    package: crun_100:1.24-1_amd64
    path: /usr/bin/crun
    version: |-
      crun version 1.24
      commit: 54693209039e5e04cbe3c8b1cd5fe2301219f0a1
      rundir: /run/user/1000/crun
      spec: 1.0.0
      +SYSTEMD +SELINUX +APPARMOR +CAP +SECCOMP +EBPF +YAJL
  os: linux
  pasta:
    executable: /usr/bin/pasta
    package: passt_100:0.0+20250919.623dbf6f-1_amd64
    version: |
      pasta 0.0+20250919.623dbf6f
      Copyright Red Hat
      GNU General Public License, version 2 or later
        <https://www.gnu.org/licenses/old-licenses/gpl-2.0.html>
      This is free software: you are free to change and redistribute it.
      There is NO WARRANTY, to the extent permitted by law.
  remoteSocket:
    exists: true
    path: /run/user/1000/podman/podman.sock
  rootlessNetworkCmd: pasta
  security:
    apparmorEnabled: false
    capabilities: CAP_AUDIT_WRITE,CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_FOWNER,CAP_FSETID,CAP_KILL,CAP_MKNOD,CAP_NET_BIND_SERVICE,CAP_NET_RAW,CAP_SETFCAP,CAP_SETGID,CAP_SETPCAP,CAP_SETUID,CAP_SYS_CHROOT
    rootless: true
    seccompEnabled: true
    seccompProfilePath: /usr/share/containers/seccomp.json
    selinuxEnabled: false
  serviceIsRemote: false
  slirp4netns:
    executable: /usr/bin/slirp4netns
    package: slirp4netns_100:1.3.3-1_amd64
    version: |-
      slirp4netns version 1.3.3
      commit: unknown
      libslirp: 4.9.1
      SLIRP_CONFIG_VERSION_MAX: 6
      libseccomp: 2.5.5
  swapFree: 0
  swapTotal: 0
  uptime: 0h 1m 40.00s
  variant: ""
plugins:
  authorization: null
  log:
  - k8s-file
  - none
  - passthrough
  - journald
  network:
  - bridge
  - macvlan
  - ipvlan
  volume:
  - local
registries:
  search:
  - docker.io
store:
  configFile: /home/johndoe/.config/containers/storage.conf
  containerStore:
    number: 0
    paused: 0
    running: 0
    stopped: 0
  graphDriverName: overlay
  graphOptions: {}
  graphRoot: /home/johndoe/.local/share/containers/storage
  graphRootAllocated: 102888095744
  graphRootUsed: 2843721728
  graphStatus:
    Backing Filesystem: extfs
    Native Overlay Diff: "true"
    Supports d_type: "true"
    Supports shifting: "false"
    Supports volatile: "true"
    Using metacopy: "false"
  imageCopyTmpDir: /var/tmp
  imageStore:
    number: 0
  runRoot: /run/user/1000/containers
  transientStore: false
  volumePath: /home/johndoe/.local/share/containers/storage/volumes
version:
  APIVersion: 5.6.2
  Built: 0
  BuiltTime: Thu Jan  1 00:00:00 1970
  GitCommit: ""
  GoVersion: go1.25.1
  Os: linux
  OsArch: linux/amd64
  Version: 5.6.2

$ podman compose version
Docker Compose version v2.40.3
```

At this point, users may:

* re-run the [configuration script](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig) to further adjust any Malcolm runtime settings,
* run [`auth_setup`](authsetup.md#AuthSetup) to configure authentication,
* pull the Malcolm images (`podman compose --profile malcolm pull`), and,
* [start Malcolm](running.md#Running).

Note that the first time Podman Malcolm starts the Malcolm containers it may take a several minutes for Podman to internally remap the user namespaces. This brief penalty is only applicable during startup, not during runtime. During this initial startup process, users monitoring `top` may see high CPU and disk I/O from the `podman`, `exe` or `storage-chown-by-maps` processes.

Once Malcolm has started, the `./scripts/status` and/or `podman ps` commands will show its containers running under Podman:

```bash
$ podman ps -a
CONTAINER ID  IMAGE                                               COMMAND               CREATED         STATUS                   PORTS                                   NAMES
6bd2db077d68  ghcr.io/idaholab/malcolm/htadmin:{{ site.malcolm.version }}            /usr/bin/supervis...  16 minutes ago  Up 3 minutes (healthy)   80/tcp                                  malcolm-htadmin-1
3a4dc9176d1f  ghcr.io/idaholab/malcolm/freq:{{ site.malcolm.version }}               /usr/local/bin/su...  16 minutes ago  Up 3 minutes (healthy)   10004/tcp                               malcolm-freq-1
f2e8ea0dea61  ghcr.io/idaholab/malcolm/pcap-capture:{{ site.malcolm.version }}       /usr/local/bin/su...  16 minutes ago  Up 3 minutes (healthy)                                           malcolm-pcap-capture-1
18b0fda0d0b6  ghcr.io/idaholab/malcolm/redis:{{ site.malcolm.version }}              sh -c redis-serve...  16 minutes ago  Up 3 minutes (healthy)   6379/tcp                                malcolm-redis-1
1c973d038a5a  ghcr.io/idaholab/malcolm/postgresql:{{ site.malcolm.version }}         /usr/bin/docker-e...  16 minutes ago  Up 3 minutes (healthy)   5432/tcp                                malcolm-postgres-1
8b5f0dfddb38  ghcr.io/idaholab/malcolm/redis:{{ site.malcolm.version }}              sh -c redis-serve...  16 minutes ago  Up 3 minutes (healthy)   6379/tcp                                malcolm-redis-cache-1
1554d34dfa81  ghcr.io/idaholab/malcolm/keycloak:{{ site.malcolm.version }}           /opt/keycloak/bin...  16 minutes ago  Up 3 minutes (healthy)   8080/tcp, 8443/tcp, 9000/tcp            malcolm-keycloak-1
9a84d9417554  ghcr.io/idaholab/malcolm/api:{{ site.malcolm.version }}                gunicorn --bind 0...  16 minutes ago  Up 3 minutes (healthy)   5000/tcp                                malcolm-api-1
0b531d4255c4  ghcr.io/idaholab/malcolm/suricata:{{ site.malcolm.version }}           /usr/local/bin/su...  16 minutes ago  Up 3 minutes (healthy)                                           malcolm-suricata-live-1
de2d8b986c95  ghcr.io/idaholab/malcolm/file-upload:{{ site.malcolm.version }}        /usr/local/bin/su...  16 minutes ago  Up 3 minutes (healthy)   22/tcp, 80/tcp                          malcolm-upload-1
e774e99c3364  ghcr.io/idaholab/malcolm/suricata:{{ site.malcolm.version }}           /usr/local/bin/su...  15 minutes ago  Up 3 minutes (healthy)                                           malcolm-suricata-1
e4607af64749  ghcr.io/idaholab/malcolm/opensearch:{{ site.malcolm.version }}         /usr/share/opense...  15 minutes ago  Up 3 minutes (healthy)   9200/tcp, 9300/tcp, 9600/tcp, 9650/tcp  malcolm-opensearch-1
48aa56016aef  ghcr.io/idaholab/malcolm/arkime:{{ site.malcolm.version }}             /usr/local/bin/su...  15 minutes ago  Up 3 minutes (healthy)   8000/tcp, 8005/tcp, 8081/tcp            malcolm-arkime-live-1
f7e7ab1c457b  ghcr.io/idaholab/malcolm/zeek:{{ site.malcolm.version }}               /usr/local/bin/su...  15 minutes ago  Up 3 minutes (healthy)                                           malcolm-zeek-live-1
32790263fd49  ghcr.io/idaholab/malcolm/file-monitor:{{ site.malcolm.version }}       /usr/local/bin/su...  15 minutes ago  Up 3 minutes (healthy)   3310/tcp, 8006/tcp                      malcolm-file-monitor-1
cf7fc1c029a1  ghcr.io/idaholab/malcolm/filebeat-oss:{{ site.malcolm.version }}       /usr/local/bin/su...  14 minutes ago  Up 3 minutes (healthy)                                           malcolm-filebeat-1
f96db0e5bf67  ghcr.io/idaholab/malcolm/zeek:{{ site.malcolm.version }}               /usr/local/bin/su...  13 minutes ago  Up 3 minutes (healthy)                                           malcolm-zeek-1
42f8aab398a9  ghcr.io/idaholab/malcolm/logstash-oss:{{ site.malcolm.version }}       /usr/local/bin/su...  13 minutes ago  Up 3 minutes (starting)  5044/tcp, 9001/tcp, 9600/tcp            malcolm-logstash-1
f9e59777bb96  ghcr.io/idaholab/malcolm/netbox:{{ site.malcolm.version }}             /opt/netbox/docke...  13 minutes ago  Up 3 minutes (healthy)   9001/tcp                                malcolm-netbox-1
f88d6aed3d41  ghcr.io/idaholab/malcolm/arkime:{{ site.malcolm.version }}             /usr/local/bin/su...  13 minutes ago  Up 3 minutes (healthy)   8000/tcp, 8005/tcp, 8081/tcp            malcolm-arkime-1
a10f00dc1618  ghcr.io/idaholab/malcolm/pcap-monitor:{{ site.malcolm.version }}       /usr/local/bin/su...  13 minutes ago  Up 3 minutes (healthy)   30441/tcp                               malcolm-pcap-monitor-1
f9f50b87005e  ghcr.io/idaholab/malcolm/dashboards-helper:{{ site.malcolm.version }}  /usr/local/bin/su...  13 minutes ago  Up 3 minutes (healthy)   28991/tcp                               malcolm-dashboards-helper-1
5d7329c4f689  ghcr.io/idaholab/malcolm/dashboards:{{ site.malcolm.version }}         /usr/share/opense...  10 minutes ago  Up 3 minutes (healthy)   5601/tcp                                malcolm-dashboards-1
be14c59880ef  ghcr.io/idaholab/malcolm/nginx-proxy:{{ site.malcolm.version }}        /usr/bin/supervis...  3 minutes ago   Up 3 minutes (healthy)   0.0.0.0:443->443/tcp                    malcolm-nginx-proxy-1

$ ./scripts/status
NAME                          IMAGE                                                COMMAND                  SERVICE             CREATED          STATUS         PORTS
malcolm-api-1                 ghcr.io/idaholab/malcolm/api:{{ site.malcolm.version }}                 "gunicorn --bind 0:5…"   api                 16 minutes ago   Up 3 minutes   5000/tcp
malcolm-arkime-1              ghcr.io/idaholab/malcolm/arkime:{{ site.malcolm.version }}              "/usr/local/bin/supe…"   arkime              13 minutes ago   Up 3 minutes   8000/tcp, 8005/tcp, 8081/tcp
malcolm-arkime-live-1         ghcr.io/idaholab/malcolm/arkime:{{ site.malcolm.version }}              "/usr/local/bin/supe…"   arkime-live         15 minutes ago   Up 3 minutes
malcolm-dashboards-1          ghcr.io/idaholab/malcolm/dashboards:{{ site.malcolm.version }}          "/usr/share/opensear…"   dashboards          10 minutes ago   Up 3 minutes   5601/tcp
malcolm-dashboards-helper-1   ghcr.io/idaholab/malcolm/dashboards-helper:{{ site.malcolm.version }}   "/usr/local/bin/supe…"   dashboards-helper   13 minutes ago   Up 3 minutes   28991/tcp
malcolm-file-monitor-1        ghcr.io/idaholab/malcolm/file-monitor:{{ site.malcolm.version }}        "/usr/local/bin/supe…"   file-monitor        15 minutes ago   Up 3 minutes   3310/tcp, 8006/tcp
malcolm-filebeat-1            ghcr.io/idaholab/malcolm/filebeat-oss:{{ site.malcolm.version }}        "/usr/local/bin/supe…"   filebeat            14 minutes ago   Up 3 minutes
malcolm-freq-1                ghcr.io/idaholab/malcolm/freq:{{ site.malcolm.version }}                "/usr/local/bin/supe…"   freq                17 minutes ago   Up 3 minutes   10004/tcp
malcolm-htadmin-1             ghcr.io/idaholab/malcolm/htadmin:{{ site.malcolm.version }}             "/usr/bin/supervisor…"   htadmin             17 minutes ago   Up 3 minutes   80/tcp
malcolm-keycloak-1            ghcr.io/idaholab/malcolm/keycloak:{{ site.malcolm.version }}            "/opt/keycloak/bin/k…"   keycloak            16 minutes ago   Up 3 minutes   8080/tcp, 8443/tcp, 9000/tcp
malcolm-logstash-1            ghcr.io/idaholab/malcolm/logstash-oss:{{ site.malcolm.version }}        "/usr/local/bin/supe…"   logstash            13 minutes ago   Up 3 minutes   5044/tcp, 9001/tcp, 9600/tcp
malcolm-netbox-1              ghcr.io/idaholab/malcolm/netbox:{{ site.malcolm.version }}              "/opt/netbox/docker-…"   netbox              13 minutes ago   Up 3 minutes   9001/tcp
malcolm-nginx-proxy-1         ghcr.io/idaholab/malcolm/nginx-proxy:{{ site.malcolm.version }}         "/usr/bin/supervisor…"   nginx-proxy         3 minutes ago    Up 3 minutes   0.0.0.0:443->443/tcp
malcolm-opensearch-1          ghcr.io/idaholab/malcolm/opensearch:{{ site.malcolm.version }}          "/usr/share/opensear…"   opensearch          16 minutes ago   Up 3 minutes   9200/tcp, 9300/tcp, 9600/tcp, 9650/tcp
malcolm-pcap-capture-1        ghcr.io/idaholab/malcolm/pcap-capture:{{ site.malcolm.version }}        "/usr/local/bin/supe…"   pcap-capture        16 minutes ago   Up 3 minutes
malcolm-pcap-monitor-1        ghcr.io/idaholab/malcolm/pcap-monitor:{{ site.malcolm.version }}        "/usr/local/bin/supe…"   pcap-monitor        13 minutes ago   Up 3 minutes   30441/tcp
malcolm-postgres-1            ghcr.io/idaholab/malcolm/postgresql:{{ site.malcolm.version }}          "/usr/bin/docker-ent…"   postgres            16 minutes ago   Up 3 minutes   5432/tcp
malcolm-redis-1               ghcr.io/idaholab/malcolm/redis:{{ site.malcolm.version }}               "sh -c redis-server …"   redis               16 minutes ago   Up 3 minutes   6379/tcp
malcolm-redis-cache-1         ghcr.io/idaholab/malcolm/redis:{{ site.malcolm.version }}               "sh -c redis-server …"   redis-cache         16 minutes ago   Up 3 minutes   6379/tcp
malcolm-suricata-1            ghcr.io/idaholab/malcolm/suricata:{{ site.malcolm.version }}            "/usr/local/bin/supe…"   suricata            16 minutes ago   Up 3 minutes
malcolm-suricata-live-1       ghcr.io/idaholab/malcolm/suricata:{{ site.malcolm.version }}            "/usr/local/bin/supe…"   suricata-live       16 minutes ago   Up 3 minutes
malcolm-upload-1              ghcr.io/idaholab/malcolm/file-upload:{{ site.malcolm.version }}         "/usr/local/bin/supe…"   upload              16 minutes ago   Up 3 minutes   22/tcp, 80/tcp
malcolm-zeek-1                ghcr.io/idaholab/malcolm/zeek:{{ site.malcolm.version }}                "/usr/local/bin/supe…"   zeek                13 minutes ago   Up 3 minutes
malcolm-zeek-live-1           ghcr.io/idaholab/malcolm/zeek:{{ site.malcolm.version }}                "/usr/local/bin/supe…"   zeek-live           15 minutes ago   Up 3 minutes
```
