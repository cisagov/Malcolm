# <a name="HostSystemConfigMac"></a>macOS host system configuration

## Automatic installation using `install.py`

The `install.py` script will attempt to guide you through the installation of Docker and Docker Compose if they are not present. If that works, skip ahead to **Configure docker daemon option** in this section.

## Install Homebrew

The easiest way to install and maintain docker on Mac is using the [Homebrew cask](https://brew.sh). Execute the following in a terminal.

```
$ /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
$ brew install cask
$ brew tap homebrew/cask-versions
```

## Install docker

```
$ brew install --cask docker
```
This will install the latest version of `docker`. It can be upgraded later using `brew` as well:
```
$ brew upgrade --cask --no-quarantine docker
```
You can now run Docker from the Applications folder.

## Install docker compose

```
$ brew install docker-compose
```

This will install the latest version of the Docker Compose plugin. It can be upgraded later using [`brew`] as well:

```
$ brew upgrade --no-quarantine docker-compose
```

The [brew formula for docker-compose notes](https://formulae.brew.sh/formula/docker-compose) has the following note about needing to symlink for Docker to find the compose plugin:

```
Compose is now a Docker plugin. For Docker to find this plugin, symlink it:
    mkdir -p ~/.docker/cli-plugins
    ln -sfn $HOMEBREW_PREFIX/opt/docker-compose/bin/docker-compose ~/.docker/cli-plugins/docker-compose
```

## Configure docker daemon option

Some changes should be made for performance ([this link](http://markshust.com/2018/01/30/performance-tuning-docker-mac) gives a good succinct overview).

* **Resource allocation** - For best results, Mac users should be running recent system with at least 32GB RAM and an SSD. In the system tray, select **Docker** → **Preferences** → **Advanced**. Set the resources available to Docker to at least 6 CPUs and at least 24GB RAM (even more is preferable).

* **Volume mount performance** - Users can speed up performance of volume mounts by removing unused paths from **Docker** → **Preferences** → **File Sharing**. For example, if volumes are mounted under the home directory only, users could share /Users but remove other paths.

After making these changes, right-click on the Docker 🐋 icon in the system tray and select **Restart**.

## Podman

See [Docker vs. Podman](quickstart.md#DockerVPodman).