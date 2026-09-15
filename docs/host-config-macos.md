# <a name="HostSystemConfigMac"></a>macOS host system configuration

## Automatic installation using `install.py`

The `install.py` script will attempt to guide you through the installation of Docker and Docker Compose if they are not present, similar to how it's illustrated in the [**Installation example using Ubuntu 24.04 LTS**](ubuntu-install-example.md#InstallationExample). If that works, skip ahead to **Configure Docker Desktop resources** in this section.

Malcolm can run on both Intel (`x86_64`/`amd64`) and Apple silicon (`AArch64`/`arm64`) Macs using Docker Desktop. Malcolm publishes ARM64 container images, so Apple silicon systems do not need to run the full Malcolm stack through x86 emulation. See [Recommended system requirements](system-requirements.md) for Malcolm's hardware requirements and [Docker's macOS installation documentation](https://docs.docker.com/desktop/setup/install/mac-install/) for the macOS versions currently supported by Docker Desktop.

## Install Homebrew

Homebrew is optional, but it provides a convenient way to install and update Docker Desktop. To install Homebrew, execute the following in a terminal:

```
$ /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Follow any post-installation instructions printed by Homebrew so the `brew` command is available in your shell.

## Install Docker Desktop and Docker Compose

Docker Desktop can be installed with Homebrew's Docker Desktop cask:

```
$ brew install --cask docker-desktop
```

Start Docker Desktop from the Applications folder and complete its first-run setup. Docker Desktop on macOS includes the Docker Compose plugin, so a separate Compose installation is not required.

Docker Desktop can later be upgraded with:

```
$ brew upgrade --cask docker-desktop
```

On Apple silicon, Docker recommends installing Rosetta 2 for the best compatibility with optional tools that still require `amd64` emulation. Malcolm itself has ARM64 container images, so Rosetta is not required merely to run Malcolm's native ARM64 images.

## Configure Docker Desktop resources

Malcolm is resource intensive. Review [Recommended system requirements](system-requirements.md) before configuring Docker Desktop. Malcolm requires at least 8 CPU cores and 24 GB of RAM for a dedicated system, while 16 or more CPU cores and 32 GB or more of RAM are recommended for an optimal experience.

Open Docker Desktop **Settings** → **Resources** → **Advanced** and allocate enough CPU, memory, and disk space to the Docker Linux VM for the Malcolm workload while leaving sufficient resources for macOS itself. Docker Desktop defaults to using 50% of the host's memory, which may be too low for Malcolm on some systems.

For file sharing performance, Docker Desktop currently uses VirtioFS by default on macOS. Keep Malcolm under a directory that Docker Desktop is allowed to share. If needed, manage shared paths under **Settings** → **Resources** → **File sharing**. Sharing only the directories required by Malcolm can reduce unnecessary file-system overhead.

After changing Docker Desktop resource or file-sharing settings, restart Docker Desktop before starting Malcolm.

## Podman

Malcolm can run on [Podman](https://podman.io) as a rootless alternative to Docker. See the Linux instructions for [Installing and configuring Podman](host-config-linux.md#HostSystemConfigLinuxPodman) for more information.
