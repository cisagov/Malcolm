# <a name="Development"></a>Development

* [Development](#Development)
    - [Building from source](#Build)
    - [Pre-Packaged installation files](#Packager)

Checking out the [Malcolm source code]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}) results in the following subdirectories in your `malcolm/` working copy:

* `api` - code and configuration for the `api` container, which provides a REST API to query Malcolm
* `arkime` - code and configuration for the `arkime` container that processes PCAP files using `capture`, which serves the Viewer application
* `config` - a directory containing the environment variable files that define Malcolm's configuration
* `container-health-scripts` - scripts included in Malcolm's images for [Docker health checks](https://docs.docker.com/reference/dockerfile/#healthcheck) and [Kubernetes liveness checks](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/#define-a-liveness-command)
* `dashboards` - code and configuration for the `dashboards` container for creating additional ad-hoc visualizations and dashboards beyond that which is provided by Arkime Viewer
* `Dockerfiles` - a directory containing build instructions for Malcolm's images
* `docs` - a directory containing instructions and documentation
* `filebeat` - code and configuration for the `filebeat` container that ingests Zeek logs and forwards them to the `logstash` container
* `file-monitor` - code and configuration for the `file-monitor` container that can scan files extracted by Zeek
* `file-upload` - code and configuration for the `upload` container that serves a web browser-based upload form for uploading PCAP files and Zeek logs, and serves an SFTP share as an alternate upload
* `freq-server` - code and configuration for the `freq` container used for calculating entropy of strings
* `hedgehog-raspi` - code and configuration for building a [Hedgehog Linux](live-analysis.md#Hedgehog) [Raspberry Pi image](hedgehog-raspi-build.md#HedgehogRaspiBuild)
* `htadmin` - configuration for the `htadmin` user account management container
* `logstash` - code and configuration for the `logstash` container that parses Zeek logs and forwards them to the `opensearch` container
* `malcolm-iso` - code and configuration for building an [installer ISO](malcolm-iso.md#ISO) for a minimal Debian-based Linux installation for running Malcolm
* `netbox` - code and configuration for the `netbox` container which provides asset management capabilities
* `nginx` - configuration for the `nginx` reverse-proxy container
* `opensearch` - an initially empty directory where the OpenSearch database instance will reside
* `opensearch-backup` - an initially empty directory for storing OpenSearch [index snapshots](index-management.md#IndexManagement) 
* `pcap` - an initially empty directory for PCAP files to be uploaded, processed, and stored
* `pcap-capture` - code and configuration for the `pcap-capture` container that can capture network traffic
* `pcap-monitor` - code and configuration for the `pcap-monitor` container that watches for new or uploaded PCAP files and notifies the other services to process them
* `postgres-scripts` - code used in the `postgres` container for database initialization
* `redis` - an initially empty directory where the Redis database runtime files will reside
* `scripts` - control scripts for starting, stopping, restarting, etc., Malcolm
* `shared` - miscellaneous code used by various Malcolm components 
* `suricata` - code and configuration for the `suricata` container that handles PCAP processing using Suricata
* `suricata-logs` - an initially empty directory for Suricata logs to be uploaded, processed, and stored
* `yara` - a directory for custom user-provided YARA rules
* `zeek` - code and configuration for the `Zeek` container that handles PCAP processing using Zeek
* `zeek-logs` - an initially empty directory for Zeek logs to be uploaded, processed, and stored
* `_includes` and `_layouts` - templates for the HTML version of the documentation
* `.github` - GitHub workflow actions used to build [Malcolm using GitHub runners](contributing-github-runners.md#GitHubRunners)

and the following files of special note:

* `docker-compose-dev.yml` - the configuration file used by `docker compose` to build, start, and stop an instance of the Malcolm appliance
* `docker-compose.yml` - similar to `docker-compose-dev.yml`, only used for the ["packaged"](#Packager) installation of Malcolm

## <a name="Build"></a>Building from source

Building the Malcolm images from scratch requires Internet access to pull source files for its components. Once Internet access is available, execute the following command to build all the images used by the Malcolm appliance:

```
$ ./scripts/build.sh
```

Then, go take a walk or something since it will be a while. When you are done, you can run `docker images` and see if you have fresh images for:

* `ghcr.io/idaholab/malcolm/api` (based on `python:3-slim`)
* `ghcr.io/idaholab/malcolm/arkime` (based on `debian:13-slim`)
* `ghcr.io/idaholab/malcolm/dashboards-helper` (based on `debian:13-slim`)
* `ghcr.io/idaholab/malcolm/dashboards` (based on `opensearchproject/opensearch-dashboards`)
* `ghcr.io/idaholab/malcolm/file-monitor` (based on `debian:13-slim`)
* `ghcr.io/idaholab/malcolm/file-upload` (based on `debian:13-slim`)
* `ghcr.io/idaholab/malcolm/filebeat-oss` (based on `docker.elastic.co/beats/filebeat-oss`)
* `ghcr.io/idaholab/malcolm/freq` (based on `debian:13-slim`)
* `ghcr.io/idaholab/malcolm/htadmin` (based on `debian:11-slim`)
* `ghcr.io/idaholab/malcolm/keycloak` (based on `quay.io/keycloak/keycloak:26.1`)
* `ghcr.io/idaholab/malcolm/logstash-oss` (based on `docker.elastic.co/logstash/logstash-oss`)
* `ghcr.io/idaholab/malcolm/netbox` (based on `netboxcommunity/netbox:latest`)
* `ghcr.io/idaholab/malcolm/nginx-proxy` (based on `alpine:3.23`)
* `ghcr.io/idaholab/malcolm/opensearch` (based on `opensearchproject/opensearch`)
* `ghcr.io/idaholab/malcolm/pcap-capture` (based on `debian:13-slim`)
* `ghcr.io/idaholab/malcolm/pcap-monitor` (based on `debian:13-slim`)
* `ghcr.io/idaholab/malcolm/postgresql` (based on `postgres:16-alpine`)
* `ghcr.io/idaholab/malcolm/redis` (based on `redis:7-alpine`)
* `ghcr.io/idaholab/malcolm/suricata` (based on `debian:13-slim`)
* `ghcr.io/idaholab/malcolm/zeek` (based on `debian:13-slim`)

Alternately, if you have forked Malcolm on GitHub, [workflow files]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/.github/workflows/) are provided that contain instructions for GitHub to build the images, as well as [sensor](live-analysis.md#Hedgehog) and [Malcolm](malcolm-iso.md#ISO) installer ISOs. The resulting images are named according to the pattern `ghcr.io/owner/malcolm/image:branch` (e.g., if you have forked Malcolm with the GitHub user `romeogdetlevjr`, the `Arkime` container built for the `main` branch would be named `ghcr.io/romeogdetlevjr/malcolm/arkime:main`). To run your local instance of Malcolm using these images instead of the official ones, you will need to edit your `docker-compose.yml` file(s) and replace the `image:` tags according to this new pattern, or use the bash helper script `./shared/bin/github_image_helper.sh` to pull and re-tag the images.

# <a name="Packager"></a>Pre-Packaged installation files

## Creating pre-packaged installation files

`scripts/malcolm_appliance_packager.sh` can be run to package up the configuration files (and, if necessary, the images), which can be copied to a network share or USB drive for distribution to non-networked machines. For example:

```
$ ./scripts/malcolm_appliance_packager.sh 
...
Packaged Malcolm to "/home/user/Downloads/malcolm_20251029_140727_d22a504f.tar.gz"

Do you need to package container images also [y/N]? y
This might take a few minutes...

Packaged Malcolm images to "/home/user/Downloads/malcolm_20251029_140727_d22a504f_images.tar.xz"

To install and configure Malcolm, run install.py

To start, stop, restart, etc. Malcolm:
  Use the control scripts in the "scripts/" directory:
   - start       (start Malcolm)
   - stop        (stop Malcolm)
   - restart     (restart Malcolm)
   - logs        (monitor Malcolm logs)
   - wipe        (stop Malcolm and clear its database)
   - auth_setup  (change authentication-related settings)

Malcolm services can be accessed at https://<IP or hostname>/
```

The above example will result in the following artifacts for distribution as explained in the script's output:

```
$ ls -lh
total 4.0G
drwxrwxr-x 10 user user  156 Oct 29 17:22 installer
-rwxrwxr-x  1 user user  44K Oct 29 17:22 install.py
-rw-rw-r--  1 user user  460 Oct 29 17:22 malcolm_20251029_140727_d22a504f.README.txt
-rw-rw-r--  1 user user 270K Oct 29 17:22 malcolm_20251029_140727_d22a504f.tar.gz
-rw-rw-r--  1 user user   4G Oct 29 17:22 malcolm_20251029_140727_d22a504f_images.tar.xz
-rw-rw-r--  1 user user  74K Oct 29 17:22 malcolm_common.py
-rw-rw-r--  1 user user 5.6K Oct 29 17:22 malcolm_constants.py
-rw-rw-r--  1 user user  50K Oct 29 17:22 malcolm_kubernetes.py
-rw-rw-r--  1 user user  37K Oct 29 17:22 malcolm_utils.py
```

## Installing from pre-packaged installation files

If you have obtained pre-packaged installation files to install Malcolm on a non-networked machine via an internal network share or on a USB key, you likely have the following files:

* `malcolm_YYYYMMDD_HHNNSS_xxxxxxx.README.txt` - This readme file contains minimal setup instructions for extracting the contents of the other tarballs and running the Malcolm appliance.
* `malcolm_YYYYMMDD_HHNNSS_xxxxxxx.tar.gz` - This tarball contains the configuration files and directory configuration used by an instance of Malcolm. It can be extracted via `tar -xf malcolm_YYYYMMDD_HHNNSS_xxxxxxx.tar.gz` upon which a directory will be created (named similarly to the tarball) containing the directories and configuration files. Alternatively, `install.py` can accept this filename as an argument and handle its extraction and initial configuration for you.
* `malcolm_YYYYMMDD_HHNNSS_xxxxxxx_images.tar.xz` - This tarball contains the images used by Malcolm. It can be imported manually via `docker load -i malcolm_YYYYMMDD_HHNNSS_xxxxxxx_images.tar.xz`
* `install.py` - This install script can load the images and extract Malcolm configuration files from the aforementioned tarballs and do some initial configuration for you (see [Running `install.py`](ubuntu-install-example.md#UIOpts)).

Run `install.py malcolm_XXXXXXXX_XXXXXX_XXXXXXX.tar.gz` and follow the prompts. If you do not already have Docker and Docker Compose installed, the `install.py` script will help you install them.