# <a name="HostSystemConfigMac"></a>macOS host system configuration

## Automatic installation using `install.py`

The `install.py` script will attempt to guide you through the installation of Docker and Docker Compose if they are not present, similar to how it's illustrated in the [**Installation example using Ubuntu 24.04 LTS**](ubuntu-install-example.md#InstallationExample). If that works, skip ahead to **Configure docker daemon option** in this section.

## Install Homebrew

The easiest way to install and maintain docker on Mac is using the [Homebrew cask](https://brew.sh). Execute the following in a terminal.

```
$ /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
$ brew install cask
```

## Install Docker Desktop and Docker Compose

```
$ brew install --cask docker-desktop
```
This will install the latest version of `docker`. It can be upgraded later using `brew` as well:
```
$ brew upgrade --cask --no-quarantine docker
```
You can now run Docker from the Applications folder. Docker Desktop on macOS also includes the Docker Compose plugin.

## Configure docker daemon option

Some changes should be made for performance. See the following (unaffiliated) posts/articles for more information:

* [What Are the Latest Docker Desktop Enterprise-Grade Performance Optimizations?](https://www.docker.com/blog/what-are-the-latest-docker-desktop-enterprise-grade-performance-optimizations/)
* [Docker on MacOS is still slow?](https://www.paolomainardi.com/posts/docker-performance-macos-2025)
* [Docker on MacOS is slow and how to fix it](https://www.cncf.io/blog/2023/02/02/docker-on-macos-is-slow-and-how-to-fix-it)
* [The most performant Docker setup on macOS](https://medium.com/%40guillem.riera/the-most-performant-docker-setup-on-macos-apple-silicon-m1-m2-m3-for-x64-amd64-compatibility-da5100e2557d)
* [Why Docker Compose Is Actually Killing Your M1 Mac](https://medium.com/%40sohail_saifi/why-docker-compose-is-actually-killing-your-m1-mac-the-performance-truth-no-one-talks-about-4357678c8584)

* **Resource allocation** - For best results, Mac users should be running recent system with at least 32GB RAM and an SSD. In the system tray, select **Docker** → **Preferences** → **Advanced**. Set the resources available to Docker to at least 6 CPUs and at least 24GB RAM (even more is preferable).

* **Volume mount performance** - Users can speed up performance of volume mounts by removing unused paths from **Docker** → **Preferences** → **File Sharing**. For example, if volumes are mounted under the home directory only, users could share /Users but remove other paths.

After making these changes, right-click on the Docker 🐋 icon in the system tray and select **Restart**.

## Podman

Malcolm can run on [Podman](https://podman.io) as a rootless alternative to Docker. See the Linux instructions for [Installing and configuring Podman](host-config-linux.md#HostSystemConfigLinuxPodman) for more information.