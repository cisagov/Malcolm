# <a name="HostSystemConfigMac"></a>macOS host system configuration

## Automatic installation using `install.py`

The `install.py` script will attempt to guide you through the installation of Docker and Docker Compose if they are not present. If that works for you, you can skip ahead to **Configure docker daemon option** in this section.

## Install Homebrew

The easiest way to install and maintain docker on Mac is using the [Homebrew cask](https://brew.sh). Execute the following in a terminal.

```
$ /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
$ brew install cask
$ brew tap homebrew/cask-versions
```

## Install docker-edge

```
$ brew cask install docker-edge
```
This will install the latest version of docker and docker-compose. It can be upgraded later using `brew` as well:
```
$ brew cask upgrade --no-quarantine docker-edge
```
You can now run docker from the Applications folder.

## Configure docker daemon option

Some changes should be made for performance ([this link](http://markshust.com/2018/01/30/performance-tuning-docker-mac) gives a good succinct overview).

* **Resource allocation** - For a good experience, you likely need at least a quad-core MacBook Pro with 16GB RAM and an SSD. I have run Malcolm on an older 2013 MacBook Pro with 8GB of RAM, but the more the better. Go in your system tray and select **Docker** → **Preferences** → **Advanced**. Set the resources available to docker to at least 4 CPUs and 8GB of RAM (>= 16GB is preferable).

* **Volume mount performance** - You can speed up performance of volume mounts by removing unused paths from **Docker** → **Preferences** → **File Sharing**. For example, if you're only going to be mounting volumes under your home directory, you could share `/Users` but remove other paths.

After making these changes, right click on the Docker 🐋 icon in the system tray and select **Restart**.