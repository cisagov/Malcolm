# <a name="HostSystemConfigWindows"></a>Windows host system configuration

Installing and configuring Docker to run under the Windows Subsystem for Linux (WSL) must be done manually, rather than through the `install.py` script as with Linux and macOS.

1. Make sure your Windows 10 or Windows 11 system is up-to-date with the current Windows cummulative update.
1. Open PowerShell or Windows Command Prompt in administrator mode by right-clicking the icon in the Start Menu and selecting **Run as administrator**.
1. Enter the command [`wsl --install`](https://learn.microsoft.com/en-us/windows/wsl/install) and wait for the installation to finish.
1. Reboot the system.
1. Upon rebooting, the Linux terminal will open automatically with **Installing, this may take a few minutes...**. Wait for this process to complete.
1. As prompted, create a default UNIX user account by providing a username and password.
1. Install Docker by running `curl -fsSL https://get.docker.com -o get-docker.sh` followed by `sudo sh get-docker.sh`.
1. Add the user account you just created to the `docker` group by running `sudo usermod -a -G docker username`, replacing `username` with the username you created before.
1. Verify Docker and Docker Compose are correctly installed by running `docker --version` and `docker compose version`.
1. If running Ubuntu 22.04 LTS, to ensure container networking works correctly, run `sudo update-alternatives --config iptables` and select the option for `iptables-legacy`.
1. Restart WSL by rebooting the system.
1. Upon rebooting, open the Start Menu and select the name of the Linux distribution you installed (**Ubuntu** is the default).
1. Continue with the Malcolm installation and configuration as described in the [**Quick start**](quickstart.md#QuickStart) documentation or illustrated with the **[Installation example using Ubuntu 24.04 LTS](ubuntu-install-example.md#InstallationExample)**.

Once the configuration is complete, Malcolm will be started and stopped from within your WSL distribution's terminal environment as described in [**Running Malcolm**](running.md).

## Podman

Malcolm can run on [Podman](https://podman.io) as a rootless alternative to Docker. See the Linux instructions for [Installing and configuring Podman](host-config-linux.md#HostSystemConfigLinuxPodman) for more information.