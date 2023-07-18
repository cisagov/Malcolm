# <a name="Development"></a>Development

* [Development](#Development)
    - [Building from source](#Build)
    - [Pre-Packaged installation files](#Packager)

Checking out the [Malcolm source code]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}) results in the following subdirectories in your `malcolm/` working copy:

* `api` - code and configuration for the `api` container, which provides a REST API to query Malcolm
* `arkime` - code and configuration for the `arkime` container that processes PCAP files using `capture`, which serves the Viewer application
* `arkime-logs` - an initially empty directory to which the `arkime` container will write some debug log files
* `config` - a directory containing the environment variable files that define Malcolm's configuration
* `dashboards` - code and configuration for the `dashboards` container for creating additional ad-hoc visualizations and dashboards beyond that which is provided by Arkime Viewer
* `Dockerfiles` - a directory containing build instructions for Malcolm's docker images
* `docs` - a directory containing instructions and documentation
* `filebeat` - code and configuration for the `filebeat` container that ingests Zeek logs and forwards them to the `logstash` container
* `file-monitor` - code and configuration for the `file-monitor` container that can scan files extracted by Zeek
* `file-upload` - code and configuration for the `upload` container that serves a web browser-based upload form for uploading PCAP files and Zeek logs, and serves an SFTP share as an alternate upload
* `freq-server` - code and configuration for the `freq` container used for calculating entropy of strings
* `htadmin` - configuration for the `htadmin` user account management container
* `logstash` - code and configuration for the `logstash` container that parses Zeek logs and forwards them to the `opensearch` container
* `malcolm-iso` - code and configuration for building an [installer ISO](malcolm-iso.md#ISO) for a minimal Debian-based Linux installation for running Malcolm
* `netbox` - code and configuration for the `netbox`, `netbox-postgres`, `netbox-redis`, and `netbox-redis-cache` containers which provide asset management capabilities
* `nginx` - configuration for the `nginx` reverse-proxy container
* `opensearch` - an initially empty directory where the OpenSearch database instance will reside
* `opensearch-backup` - an initially empty directory for storing OpenSearch [index snapshots](index-management.md#IndexManagement) 
* `pcap` - an initially empty directory for PCAP files to be uploaded, processed, and stored
* `pcap-capture` - code and configuration for the `pcap-capture` container that can capture network traffic
* `pcap-monitor` - code and configuration for the `pcap-monitor` container that watches for new or uploaded PCAP files and notifies the other services to process them
* `scripts` - control scripts for starting, stopping, restarting, etc., Malcolm
* `sensor-iso` - code and configuration for building a [Hedgehog Linux](live-analysis.md#Hedgehog) ISO
* `shared` - miscellaneous code used by various Malcolm components 
* `suricata` - code and configuration for the `suricata` container that handles PCAP processing using Suricata
* `suricata-logs` - an initially empty directory for Suricata logs to be uploaded, processed, and stored
* `zeek` - code and configuration for the `Zeek` container that handles PCAP processing using Zeek
* `zeek-logs` - an initially empty directory for Zeek logs to be uploaded, processed, and stored
* `_includes` and `_layouts` - templates for the HTML version of the documentation

and the following files of special note:

* `docker-compose.yml` - the configuration file used by `docker-compose` to build, start, and stop an instance of the Malcolm appliance
* `docker-compose-standalone.yml` - similar to `docker-compose.yml`, only used for the ["packaged"](#Packager) installation of Malcolm

## <a name="Build"></a>Building from source

Building the Malcolm docker images from scratch requires Internet access to pull source files for its components. Once Internet access is available, execute the following command to build all the Docker images used by the Malcolm appliance:

```
$ ./scripts/build.sh
```

Then, go take a walk or something since it will be a while. When you are done, you can run `docker images` and see if you have fresh images for:

* `ghcr.io/idaholab/malcolm/api` (based on `python:3-slim`)
* `ghcr.io/idaholab/malcolm/arkime` (based on `debian:11-slim`)
* `ghcr.io/idaholab/malcolm/dashboards-helper` (based on `alpine:3.18`)
* `ghcr.io/idaholab/malcolm/dashboards` (based on `opensearchproject/opensearch-dashboards`)
* `ghcr.io/idaholab/malcolm/file-monitor` (based on `debian:11-slim`)
* `ghcr.io/idaholab/malcolm/file-upload` (based on `debian:11-slim`)
* `ghcr.io/idaholab/malcolm/filebeat-oss` (based on `docker.elastic.co/beats/filebeat-oss`)
* `ghcr.io/idaholab/malcolm/freq` (based on `debian:11-slim`)
* `ghcr.io/idaholab/malcolm/htadmin` (based on `debian:11-slim`)
* `ghcr.io/idaholab/malcolm/logstash-oss` (based on `opensearchproject/logstash-oss-with-opensearch-output-plugin`)
* `ghcr.io/idaholab/malcolm/netbox` (based on `netboxcommunity/netbox:latest`)
* `ghcr.io/idaholab/malcolm/nginx-proxy` (based on `alpine:3.18`)
* `ghcr.io/idaholab/malcolm/opensearch` (based on `opensearchproject/opensearch`)
* `ghcr.io/idaholab/malcolm/pcap-capture` (based on `debian:11-slim`)
* `ghcr.io/idaholab/malcolm/pcap-monitor` (based on `debian:11-slim`)
* `ghcr.io/idaholab/malcolm/postgresql` (based on `postgres:14-alpine`)
* `ghcr.io/idaholab/malcolm/redis` (based on `redis:7-alpine`)
* `ghcr.io/idaholab/malcolm/suricata` (based on `debian:11-slim`)
* `ghcr.io/idaholab/malcolm/zeek` (based on `debian:11-slim`)

Alternately, if you have forked Malcolm on GitHub, [workflow files]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/.github/workflows/) are provided that contain instructions for GitHub to build the docker images, as well as [sensor](live-analysis.md#Hedgehog) and [Malcolm](malcolm-iso.md#ISO) installer ISOs. The resulting images are named according to the pattern `ghcr.io/owner/malcolm/image:branch` (e.g., if you have forked Malcolm with the GitHub user `romeogdetlevjr`, the `Arkime` container built for the `main` would be named `ghcr.io/romeogdetlevjr/malcolm/arkime:main`). To run your local instance of Malcolm using these images instead of the official ones, you willll need to edit your `docker-compose.yml` file(s) and replace the `image:` tags according to this new pattern, or use the bash helper script `./shared/bin/github_image_helper.sh` to pull and re-tag the images.

# <a name="Packager"></a>Pre-Packaged installation files

## Creating pre-packaged installation files

`scripts/malcolm_appliance_packager.sh` can be run to package up the configuration files (and, if necessary, the Docker images), which can be copied to a network share or USB drive for distribution to non-networked machines. For example:

```
$ ./scripts/malcolm_appliance_packager.sh 
You must set a username and password for Malcolm, and self-signed X.509 certificates will be generated

Store administrator username/password for local Malcolm access? (Y/n): y

Administrator username: analyst
analyst password:
analyst password (again):

Additional local accounts can be created at https://localhost/auth/ when Malcolm is running

(Re)generate self-signed certificates for HTTPS access (Y/n): y 

(Re)generate self-signed certificates for a remote log forwarder (Y/n): y

Will Malcolm be using an existing remote primary or secondary OpenSearch instance? (y/N): n

Store username/password for email alert sender account? (y/N): n

(Re)generate internal passwords for NetBox (Y/n): y

Packaged Malcolm to "/home/user/tmp/malcolm_20190513_101117_f0d052c.tar.gz"

Do you need to package docker images also [y/N]? y
This might take a few minutes...

Packaged Malcolm docker images to "/home/user/tmp/malcolm_20190513_101117_f0d052c_images.tar.xz"


To install Malcolm:
  1. Run install.py
  2. Follow the prompts

To start, stop, restart, etc. Malcolm:
  Use the control scripts in the "scripts/" directory:
   - start         (start Malcolm)
   - stop          (stop Malcolm)
   - restart       (restart Malcolm)
   - logs          (monitor Malcolm logs)
   - wipe          (stop Malcolm and clear its database)
   - auth_setup    (change authentication-related settings)

A minute or so after starting Malcolm, the following services will be accessible:
  - Arkime: https://localhost/
  - OpenSearch Dashboards: https://localhost/dashboards/
  - PCAP upload (web): https://localhost/upload/
  - PCAP upload (sftp): sftp://USERNAME@127.0.0.1:8022/files/
  - NetBox: https://localhost/netbox/
  - Account management: https://localhost/auth/
  - Documentation: https://localhost/readme/
```

The above example will result in the following artifacts for distribution as explained in the script's output:

```
$ ls -lh
total 2.0G
-rwxr-xr-x 1 user user  61k May 13 11:32 install.py
-rw-r--r-- 1 user user 2.0G May 13 11:37 malcolm_20190513_101117_f0d052c_images.tar.xz
-rw-r--r-- 1 user user  683 May 13 11:37 malcolm_20190513_101117_f0d052c.README.txt
-rw-r--r-- 1 user user 183k May 13 11:32 malcolm_20190513_101117_f0d052c.tar.gz
```

## Installing from pre-packaged installation files

If you have obtained pre-packaged installation files to install Malcolm on a non-networked machine via an internal network share or on a USB key, you likely have the following files:

* `malcolm_YYYYMMDD_HHNNSS_xxxxxxx.README.txt` - This readme file contains minimal setup instructions for extracting the contents of the other tarballs and running the Malcolm appliance.
* `malcolm_YYYYMMDD_HHNNSS_xxxxxxx.tar.gz` - This tarball contains the configuration files and directory configuration used by an instance of Malcolm. It can be extracted via `tar -xf malcolm_YYYYMMDD_HHNNSS_xxxxxxx.tar.gz` upon which a directory will be created (named similarly to the tarball) containing the directories and configuration files. Alternatively, `install.py` can accept this filename as an argument and handle its extraction and initial configuration for you.
* `malcolm_YYYYMMDD_HHNNSS_xxxxxxx_images.tar.xz` - This tarball contains the Docker images used by Malcolm. It can be imported manually via `docker load -i malcolm_YYYYMMDD_HHNNSS_xxxxxxx_images.tar.xz`
* `install.py` - This install script can load the Docker images and extract Malcolm configuration files from the aforementioned tarballs and do some initial configuration for you.

Run `install.py malcolm_XXXXXXXX_XXXXXX_XXXXXXX.tar.gz` and follow the prompts. If you do not already have Docker and Docker Compose installed, the `install.py` script will help you install them.