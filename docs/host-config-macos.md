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

## Install docker-edge

```
$ brew install --cask docker-edge
```
This will install the latest version of `docker`. It can be upgraded later using `brew` as well:
```
$ brew upgrade --cask --no-quarantine docker-edge
```
You can now run Docker from the Applications folder.

## Install docker-compose

```
$ brew install docker-compose
```
This will install the latest version of the `docker-compose` plugin. It can be upgraded later using `brew` as well:
```
$ brew upgrade --no-quarantine docker-compose
```
You can now run `docker-compose` (at `/usr/local/opt/docker-compose/bin/docker-compose`) from the command-line

## Configure docker daemon option

Some changes should be made for performance ([this link](http://markshust.com/2018/01/30/performance-tuning-docker-mac) gives a good succinct overview).

* **Resource allocation** - For best results, Mac users should be running a quad-core MacBook Pro with 16GB RAM and an SSD, or desktop equivalent. Malcolm can run on older  MacBook Pro machines (e.g., 2013 with 8GB RAM), but users are encouraged to bring a higher level of processing power. In the system tray, select **Docker** → **Preferences** → **Advanced**. Set the resources available to Docker to at least 4 CPUs and 8GB of RAM (>= 16GB is preferable).

* **Volume mount performance** - Users can speed up performance of volume mounts by removing unused paths from **Docker** → **Preferences** → **File Sharing**. For example, if volumes are mounted under the home directory only, users could share /Users but remove other paths.

After making these changes, right-click on the Docker 🐋 icon in the system tray and select **Restart**.