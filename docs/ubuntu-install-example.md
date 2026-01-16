# <a name="InstallationExample"></a>Installation example using Ubuntu 24.04 LTS

* [Obtaining Malcolm's release artifacts](#FromGit)
* [Using `git` to clone the Malcolm source code](#FromReleaseArtifacts)
* [Software requirements](#SofwareRequirements)
* [Running `install.py`](#UIOpts)
* [The Malcolm configuration menu](#ConfigMenu)
* [The Malcolm installation menu](#InstallMenu)
* [Configuring authentication](#AuthSetup)
* [Pulling the container images](#ContainerPull)
* [Starting Malcolm](#StartMalcolm)

Here's a step-by-step example of getting [Malcolm from GitHub]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}), configuring the local system and the Malcolm instance, and running it on a system running Ubuntu Linux. Installing Malcolm may require some variation depending on individual system configuration, but this should be a good starting point.

For a more in-depth guide convering installing both Malcolm and a [Hedgehog Linux](hedgehog.md) sensor using the [Malcolm installer ISO](malcolm-iso.md#ISO) and Hedgehog Linux installer ISO, see **[End-to-end Malcolm and Hedgehog Linux ISO Installation](malcolm-hedgehog-e2e-iso-install.md#InstallationExample)**.

The commands in this example should be executed as a non-root user except where clearly indicated with the use of `sudo`. Replace `user` in this example with the local account username.

Malcolm can be installed from a git [working copy of the source code](development.md#Build) or the from [pre-packaged installation files](development.md#Packager) downloaded as artifacts from the [latest Malcolm release]({{ site.github.repository_url }}/releases/latest). The instructions for both methods are mostly the same, so both will shown here while indicating where the processes differ.

## <a name="FromReleaseArtifacts"></a>Obtaining Malcolm's release artifacts

To install Malcolm from the latest Malcolm release artifacts, browse to the [Malcolm releases page on GitHub]({{ site.github.repository_url }}/releases/latest) and download the `malcolm-{{ site.malcolm.version }}-docker_install.zip` file, then navigate to the downloads directory and extract it. If your distribution does not have the `unzip` utility, you may need to install it with `sudo apt install unzip`.
```
user@host:~$ cd Downloads/
user@host:~/Downloads$ ls
malcolm-{{ site.malcolm.version }}-docker_install.zip
user@host:~/Downloads$ unzip malcolm-{{ site.malcolm.version }}-docker_install.zip
Archive:  malcolm-{{ site.malcolm.version }}-docker_install.zip
  creating: installer/
  …
 inflating: install.py              
 inflating: malcolm_20251029_140727_d22a504f.README.txt  
 inflating: malcolm_20251029_140727_d22a504f.tar.gz  
 inflating: malcolm_common.py       
 inflating: malcolm_constants.py    
 inflating: malcolm_kubernetes.py   
 inflating: malcolm_utils.py 
```

## <a name="FromGit"></a>Using git to clone the Malcolm source code

If obtaining Malcolm using `git` instead, run the following command to clone Malcolm into a local working copy:
```
user@host:~$ git clone {{ site.github.repository_url }}
Cloning into 'Malcolm'...
remote: Enumerating objects: 45827, done.
remote: Counting objects: 100% (648/648), done.
remote: Compressing objects: 100% (190/190), done.
remote: Total 45827 (delta 538), reused 470 (delta 457), pack-reused 45179 (from 3)
Receiving objects: 100% (45827/45827), 186.07 MiB | 8.59 MiB/s, done.
Resolving deltas: 100% (33914/33914), done.
user@host:~$ cd Malcolm/
```

## <a name="SofwareRequirements"></a>Software requirements

The Malcolm installer requires Python 3.9 or higher and a few Python libraries. On most Linux distributions these libraries (often packaged as `python3-ruamel.yaml` and `python3-dotenv`) can be installed from official repos, using `apt` or `apt-get` (for Ubuntu and other Debian-based distributions), or `yum` or `dnf` (for Redhat-based distributions). Alternatively, [`ruamel.yaml`](https://pypi.org/project/ruamel.yaml/) and [`dotenv`](https://pypi.org/project/dotenv/) can be [installed via `pip`](https://packaging.python.org/en/latest/tutorials/installing-packages/).
```
$ sudo apt-get -y -qq update
$ sudo apt-get -y install python3-ruamel.yaml python3-dotenv
Reading package lists... Done
…
The following NEW packages will be installed:
  python3-dotenv python3-ruamel.yaml python3-ruamel.yaml.clib
…
Setting up python3-dotenv (1.0.1-1) ...
Setting up python3-ruamel.yaml.clib:amd64 (0.2.8-1build1) ...
Setting up python3-ruamel.yaml (0.17.21-1) ...
…
```

Additionally, `install.py` can use a dialog-driven user interface if the `dialog` tool and corresponding Python library [`pythondialog`](https://pypi.org/project/pythondialog/) (packaged as `python3-dialog` by most Linux distributions) are installed:
```
$ sudo apt-get -y install python3-dialog dialog
Reading package lists... Done
…
Setting up dialog (1.3-20240101-1) ...
Setting up python3-dialog (3.5.1-4) ...
…
```

## <a name="UIOpts"></a>Running `install.py`

The dialog- and terminal-based user interfaces provide identical configuration workflows with only slightly different presentations. This document will use the terminal-based ("TUI") interface, which can be forced by running `install.py` with the `--tui` flag, as opposed to the dialog-based ("DUI") interface, which can be forced with the `--dui` flag.

Use `sudo` to run the `install.py` script to configure the system, as elevated privileges are required to install Docker and make performance-related changes to the system configuration. Users will first be presented with a Malcolm logo splash screen unless the `--skip-splash` flag is specified.
```
user@host:~/Malcolm$ sudo ./scripts/install.py

                                                     Welcome To

 ██████   ██████        █████        ████              ██████████████     █████     ████              ██████   ██████
░░██████ ██████       ███░░░███     ░░███             ░░███░░░░░░░░░██   ███  ██   ░░███             ░░██████ ██████ 
 ░███░█████░███      ███   ░░███     ░███              ░███        ░░   █████████   ░███              ░███░█████░███ 
 ░███░░███ ░███     █████████████    ░███              ░███             ████ ████   ░███              ░███░░███ ░███ 
 ░███ ░░░  ░███    ░███░░░░░░░███    ░███              ░███             ████ ████   ░███              ░███ ░░░  ░███ 
 ░███      ░███    ░███      ░███    ░███              ░███             █ ███████   ░███              ░███      ░███ 
 ░███      ░███    ░███      ░███    ░███              ░███         ██  ██████ ██   ░███              ░███      ░███ 
 █████     █████   █████     █████   ██████████████    ██████████████    ███████    ██████████████    █████     █████
░░░░░     ░░░░░   ░░░░░     ░░░░░   ░░░░░░░░░░░░░░    ░░░░░░░░░░░░░░      █████    ░░░░░░░░░░░░░░    ░░░░░     ░░░░░ 

                                       v{{ site.malcolm.version }}. Press any key to continue...
```

If Malcolm is being installed from the downloaded release artifacts, the script will ask whether the user would like to extract the contents of the tarball and to specify the installation directory and Malcolm configuration will continue:
```
Found Malcolm tarball: malcolm_20251029_140727_d22a504f.tar.gz. Use this file? (Y / n):

Enter installation path for Malcolm [/home/user/malcolm] (/home/user/Malcolm):
```

## <a name="UIOpts"></a>User interface options

The user will first be presented with the **Malcolm Configuration Menu** which is used to configure the local Malcolm installation's runtime options. Future runs of `install.py` where only configuration options need to be modified (instead of system-wide package installations or changes) should use the `--configure` flag and be run as the non-`root` user. Running `./scripts/configure` is equivalent to running `./scripts/install.py --configure`.

## <a name="ConfigMenu"></a>The Malcolm configuration menu

The [**Malcolm Configuration Menu**'s options](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfigItems) are described in-depth in the end-to-end installation example. 

Once the desired Malcolm configuration options have been selected, select **s** to save the settings and proceed to the **Malcolm Installation Options**.
```
…
--- Actions ---
  s. Save and Continue
  w. Where Is...? (search for settings)
  x. Exit Installer
---------------------------------

Enter item number or action: s
```

## <a name="InstallMenu"></a>The Malcolm installation menu

The **Malcolm Installation Options** menu is used to configure system-wide package installation or performance-related changes.
```
--- Malcolm Installation Options ---
Select an item number to configure, or an action:
├── 1. Automatically Apply System Tweaks (current: Yes)
├── 2. Docker Compose Installation Method (current: github)
├── 3. Docker Installation Method (current: repository)
├── 4. Docker Users (current: ['ubuntu'])
├── 5. Install Docker if Missing (current: Yes)
├── 6. Pull Malcolm Images (current: No)
├── 7. Try Docker Convenience Script (current: No)
└── 8. Try Docker Repository Installation (current: Yes)

--- Actions ---
  s. Save and Continue
  x. Exit Installer

Enter item number or action: 
```

* **Automatically Apply System Tweaks**
  - Selecting **Y** will apply recommended [system tweaks](host-config-linux.md) automatically without confirmation. Selecting **N** will allow the user to enable or disable these settings individually:
  - [sysctl settings](https://man7.org/linux/man-pages/man8/sysctl.8.html) (see the documentation for [`/proc/sys/vm/`](https://docs.kernel.org/admin-guide/sysctl/vm.html), [`/proc/sys/fs/`](https://docs.kernel.org/admin-guide/sysctl/fs.html), and [`/proc/sys/net/`](https://docs.kernel.org/admin-guide/sysctl/net.html))
  - Enable [cgroup kernel parameters](https://docs.kernel.org/admin-guide/cgroup-v2.html) in the bootloader
  - [Security Limits](https://www.man7.org/linux/man-pages/man5/limits.conf.5.html)
  - [Systemd Limits](https://manpages.debian.org/stable/systemd/systemd-system.conf.5.en.html)
* **Docker Compose Installation Method**
  - If the Docker installation step fails to install Docker Compose, the Malcolm installer can attempt to [download it directly from GitHub](https://docs.docker.com/compose/install/linux/#install-the-plugin-manually) as a fallback.
* **Install Docker if Missing**, **Docker Installation Method**, **Try Docker Convenience Script**, and **Try Docker Repository Installation**
  - If the system does not already have Docker (or Podman, if it was selected during configuration) installed, the Malcolm installer will attempt to install it for you. The installation options include:
    + `repository` - Install Docker [using its `apt` repository](https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository)
    + `convenience_script` - Install Docker [using covenience script](https://docs.docker.com/engine/install/ubuntu/#install-using-the-convenience-script)
* **Docker Users**
  - When using the Docker runtime, because Malcolm's containers' processes should run without superuser permissions, the username of the non-root user under which Malcolm will be run should be specified here to be added to the `docker` group.
  - Select **Y** to attempt to install Docker using the installation method specified above.
* **Pull Malcolm Images**
  - Select **Y** for the installer to attempt to pull the Malcolm container images after installation. This can always be done later by running `docker compose --profile malcolm pull` or the [`./scripts/github_image_helper.sh`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/scripts/github_image_helper.sh) convenience script.

Once the installation options have been selected, select **s** to save the settings and proceed to the final configuration summary for confirmation. Then, select **y** to write the changed configuration to the corresponding [environment variable](malcolm-config.md#MalcolmConfigEnvVars) files and to proceed any the system-wide changes selected.
```
…
--- Actions ---
  s. Save and Continue
  w. Where Is...? (search for settings)
  x. Exit Installer
---------------------------------

Enter item number or action: s
```

```
============================================================
FINAL CONFIGURATION SUMMARY
============================================================
Configuration Only                                : No
Auto Apply System Tweaks                          : Yes
Configuration Directory                           : /home/user/Malcolm/config
Container Runtime                                 : docker
Run Profile                                       : malcolm
Process UID/GID                                   : 1000/1000
Container Restart Policy                          : unless-stopped
Container Network                                 : default
Default Storage Locations                         : Yes
HTTPS/SSL                                         : Yes
Node Name                                         : host
============================================================

Proceed with Malcolm installation using the above configuration? (y / N):  y
```

After the installation has completed, it is recommended to **reboot the system** so that the new system settings can be applied. After rebooting, log back in and return to the directory to which Malcolm was installed (or where the git working copy was cloned).

## <a name="AuthSetup"></a>Configuring authentication

The next step is to [set up authentication](authsetup.md#AuthSetup) and generate some unique self-signed TLS certificates. Users may choose another username instead of `analyst` to log in to the Malcolm web interface.
```
user@host:~/Malcolm$ ./scripts/auth_setup 

1: all - Configure all authentication-related settings
2: method - Select authentication method (currently "basic")
3: admin - Store administrator username/password for basic HTTP authentication
4: webcerts - (Re)generate self-signed certificates for HTTPS access
5: fwcerts - (Re)generate self-signed certificates for a remote log forwarder
6: keycloak - Configure Keycloak
7: remoteos - Configure remote primary or secondary OpenSearch/Elasticsearch instance
8: email - Store username/password for OpenSearch Alerting email sender account
9: netbox - (Re)generate internal passwords for NetBox
10: keycloakdb - (Re)generate internal passwords for Keycloak's PostgreSQL database
11: postgres - (Re)generate internal superuser passwords for PostgreSQL
12: redis - (Re)generate internal passwords for Redis
13: arkime - Store password hash secret for Arkime viewer cluster
14: txfwcerts - Transfer self-signed client certificates to a remote log forwarder
Configure Authentication (all): 1

Select authentication method (currently "basic")? (Y / n): y
1: basic - Use basic HTTP authentication
2: ldap - Use Lightweight Directory Access Protocol (LDAP) for authentication
3: keycloak - Use embedded Keycloak for authentication
4: keycloak_remote - Use remote Keycloak for authentication
5: no_authentication - Disable authentication
Select authentication method (basic): 1

Store administrator username/password for basic HTTP authentication? (Y / n): y

Administrator username (between 4 and 32 characters; alphanumeric, _, -, and . allowed) (): analyst
analyst password  (between 8 and 128 characters): :
analyst password (again): :

Additional local accounts can be created at https://localhost/auth/ when Malcolm is running

(Re)generate self-signed certificates for HTTPS access? (Y / n): y

(Re)generate self-signed certificates for a remote log forwarder? (Y / n): y

Configure Keycloak? (Y / n): n

Configure remote primary or secondary OpenSearch/Elasticsearch instance? (y / N): n

Store username/password for OpenSearch Alerting email sender account? (y / N): n

(Re)generate internal passwords for NetBox? (Y / n): y

(Re)generate internal passwords for Keycloak's PostgreSQL database? (Y / n): y

(Re)generate internal superuser passwords for PostgreSQL? (Y / n): y

(Re)generate internal passwords for Redis? (Y / n): y

Store password hash secret for Arkime viewer cluster? (y / N): n

Transfer self-signed client certificates to a remote log forwarder? (y / N): n

```

Users planning to install and configure sensor devices running [Hedgehog Linux](hedgehog.md) must perform an additional step to allow communication between a Malcolm instance and an installation of Hedgehog Linux. In order for a sensor running Hedgehog Linux to securely communicate with Malcolm, it needs a copy of the client certificates generated when "(Re)generate self-signed certificates for a remote log forwarder" was selected above. The certificate authority, certificate, and key files to be copied to and used by the remote log forwarder are located in Malcolm's `filebeat/certs/` directory; these certificates should be copied to the `/opt/sensor/sensor_ctl/logstash-client-certificates` directory on the Hedgehog Linux sensor.

As an alternative to manually copying the files to the sensor, Malcolm can facilitate the secure transfer of these certificates using [`croc`](https://github.com/schollz/croc), an open-source tool for secure file transfer between two computers. Malcolm does not automatically download and install `croc`, but it may be downloaded from its [releases page on GitHub](https://github.com/schollz/croc/releases) or [installed from the command line](https://github.com/schollz/croc#install). If `croc` exists in the `PATH` on the Malcolm system, the `auth_setup` script will prompt to "Transfer self-signed client certificates to a remote log forwarder." Users can follow the steps outlined in the **[End-to-end Malcolm and Hedgehog Linux ISO Installation](malcolm-hedgehog-e2e-iso-install.md#InstallationExample)** (see [the Malcolm portion](malcolm-hedgehog-e2e-iso-install.md#MalcolmAuthSetup) and [the sensor portion](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfigItems) of those instructions) to copy the certificates to the sensor.

## <a name="ContainerPull"></a>Pulling the container images

In this example, rather than [building Malcolm from scratch](development.md#Build), images may be pulled from [GitHub](https://github.com/orgs/idaholab/packages?repo_name=Malcolm) by running `docker compose --profile malcolm pull` or the [`./scripts/github_image_helper.sh`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/scripts/github_image_helper.sh) convenience script.
```
user@host:~/Malcolm$ docker compose --profile malcolm pull
[+] Pulling 27/27
 ✔ api Pulled
 ✔ arkime Pulled
 ✔ arkime-live Pulled
 ✔ dashboards Pulled
 ✔ dashboards-helper Pulled
 ✔ filebeat Pulled
 ✔ filescan Pulled
 ✔ freq Pulled
 ✔ htadmin Pulled
 ✔ keycloak Pulled
 ✔ logstash Pulled
 ✔ netbox Pulled
 ✔ nginx-proxy Pulled
 ✔ opensearch Pulled
 ✔ pcap-capture Pulled
 ✔ pcap-monitor Pulled
 ✔ postgres Pulled
 ✔ redis Pulled
 ✔ redis-cache Pulled
 ✔ strelka-backend Pulled
 ✔ strelka-frontend Pulled
 ✔ strelka-manager Pulled
 ✔ suricata Pulled
 ✔ suricata-live Pulled
 ✔ upload Pulled
 ✔ zeek Pulled
 ✔ zeek-live Pulled


user@host:~/Malcolm$ docker images
IMAGE                                                       ID             DISK USAGE   CONTENT SIZE   EXTRA
ghcr.io/idaholab/malcolm/api:{{ site.malcolm.version }}                        0ba697568f70        201MB             0B   U
ghcr.io/idaholab/malcolm/arkime:{{ site.malcolm.version }}                     54a12ceafb40        861MB             0B   U
ghcr.io/idaholab/malcolm/dashboards-helper:{{ site.malcolm.version }}          0bef31d3d258        233MB             0B   U
ghcr.io/idaholab/malcolm/dashboards:{{ site.malcolm.version }}                 1cdc4634a78a        1.8GB             0B   U
ghcr.io/idaholab/malcolm/file-upload:{{ site.malcolm.version }}                8f0cf3fbb34e        309MB             0B   U
ghcr.io/idaholab/malcolm/filebeat-oss:{{ site.malcolm.version }}               681c3b86c47b        470MB             0B   U
ghcr.io/idaholab/malcolm/filescan:{{ site.malcolm.version }}                   f7d43d90d09a        363MB             0B   U
ghcr.io/idaholab/malcolm/freq:{{ site.malcolm.version }}                       12cb29c77aae        167MB             0B   U
ghcr.io/idaholab/malcolm/htadmin:{{ site.malcolm.version }}                    7fabfc1d8671        247MB             0B   U
ghcr.io/idaholab/malcolm/keycloak:{{ site.malcolm.version }}                   9e61d35dcec9        549MB             0B   U
ghcr.io/idaholab/malcolm/logstash-oss:{{ site.malcolm.version }}               687504dbda6d       1.54GB             0B   U
ghcr.io/idaholab/malcolm/netbox:{{ site.malcolm.version }}                     9486029468ec       2.18GB             0B   U
ghcr.io/idaholab/malcolm/nginx-proxy:{{ site.malcolm.version }}                a9835ddbc2a5        180MB             0B   U
ghcr.io/idaholab/malcolm/opensearch:{{ site.malcolm.version }}                 75f2c09f0447       1.91GB             0B   U
ghcr.io/idaholab/malcolm/pcap-capture:{{ site.malcolm.version }}               672a7e07d8b7        174MB             0B   U
ghcr.io/idaholab/malcolm/pcap-monitor:{{ site.malcolm.version }}               2bf4908adc58        198MB             0B   U
ghcr.io/idaholab/malcolm/postgresql:{{ site.malcolm.version }}                 a65a70c670d7        336MB             0B   U
ghcr.io/idaholab/malcolm/redis:{{ site.malcolm.version }}                      5f6dcf55d0d2       52.5MB             0B   U
ghcr.io/idaholab/malcolm/strelka-backend:{{ site.malcolm.version }}            17087ff5ee30       3.63GB             0B   U
ghcr.io/idaholab/malcolm/strelka-frontend:{{ site.malcolm.version }}           0f871f660102       81.8MB             0B   U
ghcr.io/idaholab/malcolm/strelka-manager:{{ site.malcolm.version }}            a582a74cdb87       54.8MB             0B   U
ghcr.io/idaholab/malcolm/suricata:{{ site.malcolm.version }}                   11f1f4b74f1d        362MB             0B   U
ghcr.io/idaholab/malcolm/zeek:{{ site.malcolm.version }}                       ccbcc3bb894d       1.56GB             0B   U
```

## <a name="StartMalcolm"></a>Starting Malcolm

Finally, [start Malcolm](running.md#Starting). When Malcolm starts it will stream informational and debug messages to the console until it has completed initializing. It will take several minutes for all of Malcolm's components to start up. Logstash will take the longest, probably 3 to 5 minutes.

Users will know Logstash is fully ready when you see Logstash spit out a bunch of starting up messages, ending with this, after which the `start` will return to the command line prompt.
```
user@host:~/Malcolm$ ./scripts/start
…
logstash | [2026-01-16T17:58:33,274][INFO ][logstash.agent           ] Pipelines running {:count=>7, :running_pipelines=>[:"malcolm-output", :"malcolm-input", :"malcolm-filescan", :"malcolm-suricata", :"malcolm-enrichment", :"malcolm-beats", :"malcolm-zeek"], :non_running_pipelines=>[]}

Started Malcolm


Malcolm services can be accessed at https://#.#.#.#/
------------------------------------------------------------------------------

user@host:~/Malcolm$
```

The [Malcolm user interfaces](quickstart.md#UserInterfaceURLs) may be accessed via a web browser.

![Malcolm Landing Page](./images/screenshots/malcolm_landing_page.png)