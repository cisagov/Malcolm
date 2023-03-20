# <a name="HostSystemConfigWindows"></a>Windows host system configuration

## <a name="HostSystemConfigWindowsDocker"></a>Installing and configuring Docker Desktop for Windows

Installing and configuring [Docker to run under Windows](https://docs.docker.com/desktop/windows/wsl/) must be done manually, rather than through the `install.py` script as is done for Linux and macOS.

1. Be running Windows 10, version 1903 or higher
1. Prepare your system and [install WSL](https://docs.microsoft.com/en-us/windows/wsl/install) and a Linux distribution by running `wsl --install -d Debian` in PowerShell as Administrator (these instructions are tested with Debian, but may work with other distributions)
1. Install Docker Desktop for Windows either by downloading the installer from the [official Docker site](https://docs.docker.com/desktop/install/windows-install/) or installing it through [chocolatey](https://chocolatey.org/packages/docker-desktop).
1. Follow the [Docker Desktop WSL 2 backend](https://docs.docker.com/desktop/windows/wsl/) instructions to finish configuration and review best practices
1. Reboot
1. Open the WSL distribution's terminal and run run `docker info` to make sure Docker is running

## <a name="HostSystemConfigWindowsMalcolm"></a>Finish Malcolm's configuration

Once Docker is installed, configured and running as described in the previous section, run [`./scripts/install.py --configure`](malcolm-config.md#ConfigAndTuning) to finish configuration of the local Malcolm installation. Malcolm will be controlled and run from within your WSL distribution's terminal environment.