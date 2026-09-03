# <a name="UpgradePlan"></a>Upgrading Malcolm

* [Upgrading Malcolm](#UpgradePlan)
    - [Scenario 1: Malcolm was installed from the ISO installer or a prepackaged or release tarball](#UpgradeISOEnv)
    - [Scenario 2: Malcolm was installed from a GitHub clone](#UpgradeGitEnv)
    - [Final Steps](#UpgradeFinalSteps)

At this time there is not an "official" version upgrade procedure for Malcolm, as such procedures vary from platform to platform. However, the process is fairly simple and can be done by following the guidelines outlined in this document.

The Malcolm project uses [calendar versioning](https://calver.org/) for its [releases]({{ site.github.repository_url }}/releases/latest). A careful reading of the release notes between the source and target version before upgrading Malcolm is highly recommended.

## <a name="UpgradeISOEnv"></a> Scenario 1: Malcolm was installed from the [ISO installer](malcolm-hedgehog-e2e-iso-install.md#ISOInstallMalcolm) or a [prepackaged or release tarball](development.md#Packager)

This section walks through upgrading a Malcolm system (installed via the [ISO Installation](malcolm-hedgehog-e2e-iso-install.md#ISOInstallMalcolm)) to the [latest release]({{ site.github.repository_url }}/releases/latest) of Malcolm (`v{{ site.malcolm.version }}` at the time of this writing), including the underlying Linux system upgrade, Docker image refresh, Malcolm application file replacement, configuration review, and startup.

As of Malcolm v25.12.0, the Malcolm and Hedgehog Linux base operating systems have been merged into a single code base; in other words, the Hedgehog Linux installer ISO is now simply another "flavor" of the [Malcolm installer ISO](malcolm-iso.md#ISO) preconfigured to use the ["Hedgehog" run profile](live-analysis.md#Profiles). As such, the process for updating Malcolm and Hedgehog Linux are the same, since both platforms use the same procedures for installation and configuration.

This example makes the following assumptions. Commands may need to be adjusted according to individual circumstances.

- The Malcolm user is `analyst`
- Malcolm is installed in `/home/analyst/Malcolm`
- The original Malcolm version is `25.02.0` (based on Debian 12, "Bookworm")
- The target Malcolm version is `{{ site.malcolm.version }}` (based on Debian 13, "Trixie")
- Console or SSH access to the Malcolm instance is available
- Sufficient free disk space for OS packages, Docker images, and backups

> **Note:** Steps involving `apt`, `usrmerge`, and changing Debian package sources from Bookworm to Trixie apply to Malcolm ISO-based systems using the Malcolm-provided Debian base operating system. If Malcolm was installed from a release tarball on [another Linux distribution](ubuntu-install-example.md#InstallationExample), follow that operating system's normal upgrade procedure instead, then continue with the Malcolm application and Docker image upgrade steps below as applicable.

---

### 1. Stop Malcolm before upgrading the operating system

Before upgrading system packages, [stop Malcolm](running.md#StopAndRestart)
 so containers are not running while packages, Docker components, or system libraries are being upgraded.

Run this as the normal Malcolm user:

```bash
~/Malcolm/scripts/stop
```

---

### 2. Become root

The operating system upgrade requires root privileges.

Depending on how your system is configured, use either `su -` or `sudo su -`.

```bash
su -
```

Enter the root password (or the user's password, if using `sudo`) when prompted.

You should now have a root shell:

```bash
root@malcolmvm:~#
```

---

### 3. Set a safe default file creation mask

Set the root shell's `umask` to `0022`.

Due to the Malcolm base operating system's [hardened](hardening.md#Hardening) configuration, this ensures files created during the upgrade are generally readable by other users where appropriate, which is the normal default for system administration tasks.

```bash
umask 0022
```

---

### 4. Prepare for `/usr` merge conversion

Debian systems moving forward expect the `/usr` merge layout. Remove the file that tells the system to skip that conversion.

```bash
rm -f /etc/unsupported-skip-usrmerge-conversion
```

Then update the current package index:

```bash
apt update
```

Install the `usrmerge` package:

```bash
apt -y install --no-install-recommends usrmerge
```

This converts the system to the merged `/usr` layout if it has not already been converted.

---

### 5. Change Debian package sources from Bookworm to Trixie

Next, update your APT sources so they point to Debian Trixie instead of Debian Bookworm.

The following commands replace occurrences of `bookworm` with `trixie` in the main APT sources file and any files under `/etc/apt/sources.list.d/`.

```bash
sed -i "s/bookworm/trixie/g" /etc/apt/sources.list
find /etc/apt/sources.list.d -type f -exec sed -i "s/bookworm/trixie/g" {} +
```

After changing the repositories, refresh the package lists:

```bash
apt update
```

---

### 6. Perform the full Debian upgrade

Run the full distribution upgrade:

```bash
apt full-upgrade
```

APT will calculate the changes and show a summary similar to:

```
1030 upgraded, 285 newly installed, 83 to remove and 0 not upgraded.
Need to get 1,136 MB of archives.
After this operation, 1,248 MB of additional disk space will be used.
Do you want to continue? [Y/n]
```

When prompted, enter `Y`.

During the upgrade, you may be asked whether to replace locally modified configuration files. When asked whether to override or replace local changes, choose:

```
No
```

or:

```
Keep the local version currently installed
```

This helps preserve system-specific configuration that may have been customized for your Malcolm installation.

Wait for the upgrade to complete.

---

### 7. Install new packages required by the Malcolm v{{ site.malcolm.version }} ISO configuration

After the Debian upgrade completes, install the new packages used by the Malcolm `v{{ site.malcolm.version }}` base operating system.

This command fetches Malcolm's package list definitions from GitHub, filters out package lists that are not relevant, combines and deduplicates them, removes comments and blank lines, and installs the resulting package list.

```bash
curl -s "https://api.github.com/repos/idaholab/Malcolm/contents/malcolm-iso/config/package-lists?ref=v{{ site.malcolm.version }}" \
| grep "download_url" \
| cut -d '"' -f 4 \
| grep -Ev "\.binary$|live\.|virtualguest\." \
| while read -r url; do curl -sSL "$url"; echo; done \
| sort -u \
| grep -Ev "^\s*#|^\s*$" \
| xargs -r apt install -y
```

This ensures the upgraded operating system has the expected supporting packages for this Malcolm release.

---

### 8. Reboot the system

Once the OS upgrade and package installation are complete, reboot the system.

```bash
reboot
```

Your SSH or console session will disconnect:

```
Connection to 192.168.122.13 closed by remote host.
Connection to 192.168.122.13 closed.
```

Wait for the system to come back online, then reconnect.

---

### 9. Stop Malcolm again after reboot

After logging back in as the normal Malcolm user, stop Malcolm again to make sure no services are running before continuing with the application upgrade.

```bash
~/Malcolm/scripts/stop
```

This is safe to run even if Malcolm is not currently running.

---

### 10. Become root and remove unused packages

Become root again:

```bash
su -
```

Set the `umask` again:

```bash
umask 0022
```

Remove packages that were automatically installed but are no longer required after the OS upgrade:

```bash
apt -y autoremove
```

When that completes, exit the root shell:

```bash
exit
```

You should now be back as the normal Malcolm user.

---

### 11. Remove old Malcolm Docker images

Remove existing Docker images from the `idaholab/malcolm` repository.

This clears out old Malcolm container images so the new release images can be loaded cleanly.

```bash
docker images --format=table | grep idaholab/malcolm | \
    awk '{print $3}' | xargs -r -l docker rmi -f
```

This command:

1. Lists Docker images
2. Filters for images matching `idaholab/malcolm`
3. Extracts the image IDs
4. Removes those images forcibly

---

### 12. Download the Malcolm v{{ site.malcolm.version }} release artifacts

Create a `Downloads` directory and move into it:

```bash
mkdir -p ~/Downloads
cd ~/Downloads
```

Download the required release files from the Malcolm `v{{ site.malcolm.version }}` GitHub release:

```bash
curl -s https://api.github.com/repos/idaholab/Malcolm/releases/tags/v{{ site.malcolm.version }} \
  | grep "browser_download_url" \
  | grep -E "(docker_install\.zip|release_cleaver\.sh|malcolm.*_images\.tar\.xz)" \
  | cut -d '"' -f 4 \
  | xargs -r -I {} curl -L -O {}
```

This downloads files such as:

- `malcolm-{{ site.malcolm.version }}-docker_install.zip`
- `release_cleaver.sh`
- Split Docker image archive files named similar to:
  - `malcolm-{{ site.malcolm.version }}_images.tar.xz.01`
  - `malcolm-{{ site.malcolm.version }}_images.tar.xz.02`
  - `malcolm-{{ site.malcolm.version }}_images.tar.xz.03`
  - `malcolm-{{ site.malcolm.version }}_images.tar.xz.04`
  - `malcolm-{{ site.malcolm.version }}_images.tar.xz.sha`

For users who want to download only the Docker install ZIP and skip the image tarballs, preferring to pull the new images from GitHub's [ghcr.io container registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry) later using `docker compose`:

```bash
curl -s https://api.github.com/repos/idaholab/Malcolm/releases/tags/v{{ site.malcolm.version }} \
  | grep "browser_download_url" \
  | grep -E "docker_install\.zip" \
  | cut -d '"' -f 4 \
  | xargs -r -I {} curl -L -O {}
```

In that case, skip ahead to **Extract the Malcolm application archive**.

---

### 13. Reassemble the split Docker image archive

Users opting to pull the new Malcolm container images later using `docker compose` should skip this step.

Make the release helper script executable:

```bash
chmod +x release_cleaver.sh
```

Use it to join the split Docker image archive:

```bash
./release_cleaver.sh malcolm-{{ site.malcolm.version }}_images.tar.xz.*
```

You should see output similar to:

```
Joining...
malcolm-{{ site.malcolm.version }}_images.tar.xz: OK
```

After the full archive has been successfully reassembled and verified, remove the split parts:

```bash
rm -f malcolm-{{ site.malcolm.version }}_images.tar.xz.*
```

---

### 14. Load the Malcolm Docker images

Users opting to pull the new Malcolm container images later using `docker compose` should skip this step.

Load the new Malcolm Docker images into the local Docker image cache:

```bash
docker load -i malcolm-{{ site.malcolm.version }}_images.tar.xz
```

This may take some time.

After the images are loaded, remove the large archive to reclaim disk space:

```bash
rm -f malcolm-{{ site.malcolm.version }}_images.tar.xz
```

---

### 15. Extract the Malcolm application archive

The Docker install ZIP contains a `.tar.gz` archive with the Malcolm application files.

Extract only the `.tar.gz` file from the ZIP:

```bash
unzip malcolm-{{ site.malcolm.version }}-docker_install.zip "*.tar.gz"
```

You should see output similar to:

```
Archive:  malcolm-{{ site.malcolm.version }}-docker_install.zip
  inflating: malcolm_########_######_########.tar.gz
```

Extract the `.tar.gz` archive:

```bash
tar xf malcolm_########_######_########.tar.gz
```

This creates a directory similar to:

```
malcolm_########_######_########/
```

Return to your home directory:

```bash
cd ~
```

---

### 16. Back up the existing Malcolm application directory

Before replacing the existing Malcolm application files, create a backup.

This backup intentionally excludes large runtime data directories such as OpenSearch data, packet captures, Zeek logs, Suricata logs, and filescan logs.

```bash
rsync -av \
  --exclude='opensearch/*' \
  --exclude='pcap/*' \
  --exclude='suricata-logs/*' \
  --exclude='zeek-logs/*' \
  --exclude='filescan-logs/*' \
  /home/analyst/Malcolm/ \
  /home/analyst/Malcolm-25.02.0-bak/
```

This creates a backup at:

```
/home/analyst/Malcolm-25.02.0-bak/
```

The trailing slashes are important:

- `/home/analyst/Malcolm/` means "copy the contents of this directory"
- `/home/analyst/Malcolm-25.02.0-bak/` is the backup destination

---

### 17. Preview the Malcolm application file update

Before copying the new Malcolm files into place, perform a dry run.

```bash
rsync -av --dry-run --exclude='.opensearch.*.curlrc' \
  /home/analyst/Downloads/malcolm_########_######_########/ \
  /home/analyst/Malcolm/
```

This shows what would be copied, updated, or removed without actually changing anything.

The command excludes files matching:

```
.opensearch.*.curlrc
```

Those files may contain local OpenSearch authentication or connection settings that should not be overwritten with their empty default files.

Review the output before continuing.

---

### 18. Apply the Malcolm application file update

If the dry run looks correct, run the same `rsync` command without `--dry-run`:

```bash
rsync -av --exclude='.opensearch.*.curlrc' \
  /home/analyst/Downloads/malcolm_########_######_########/ \
  /home/analyst/Malcolm/
```

This updates the existing Malcolm directory with the `v{{ site.malcolm.version }}` application files.

> **Note:** This `rsync` command updates and adds files but does not delete files from the existing Malcolm directory that are not present in the new release. This is intentional to avoid removing local files unexpectedly. If you choose to add `--delete` to the command, review the exclusions carefully and ensure you have a complete backup first.

---

### 19. Update `.os-info` for the new Malcolm version

Change into the Malcolm directory:

```bash
cd ~/Malcolm
```

Update `.os-info` so it reflects the new Malcolm variant and version information:

```bash
ver="{{ site.malcolm.version }}"; sed -i -E \
  -e 's/^(VARIANT_ID=")hedgehog-malcolm(")$/\1malcolm\2/' \
  -e 's/^(VARIANT_ID=")hedgehog-sensor(")$/\1hedgehog\2/' \
  -e "s/^(VARIANT=\".*)v[0-9]+\\.[0-9]+\\.[0-9]+(.*\")$/\1v${ver}\2/" \
  -e "s/^(BUILD_ID=\").*(\")$/\1$(date +%F)-${ver}\2/" \
  .os-info
```

This command:

- Normalizes older `VARIANT_ID` values if needed
- Updates the displayed Malcolm version to `v{{ site.malcolm.version }}`
- Updates the `BUILD_ID` to include the current date and version

---

Proceed to [**Final Steps**](#UpgradeFinalSteps) below to finish the upgrade and start Malcolm.

## <a name="UpgradeGitEnv"></a> Scenario 2: Malcolm was installed from a GitHub clone

This section explains how to upgrade Malcolm when your installation was originally created using `git clone`.

This scenario is different from upgrading a release archive installation because the Malcolm directory is a Git working tree rather than a directory replaced from a release archive. Instead of replacing the entire application directory with files from a downloaded archive, the application files are updated from a Git repository, then local configuration changes are reapplied or reconciled.

The examples below assume:

- The Malcolm source repository is checked out at `/home/user/Malcolm`
- The target Malcolm version is `{{ site.malcolm.version }}`

Adjust paths and version numbers as needed for your environment.

---

### 1. Change into the Malcolm directory

Start by changing into your Malcolm Git working tree.

```bash
cd /home/user/Malcolm
```

If your Malcolm clone is in a different location, use that path instead.

---

### 2. Stop Malcolm

Stop the currently running Malcolm containers before making changes.

```bash
./scripts/stop
```

Stopping Malcolm first helps prevent configuration or data inconsistencies while the repository, Docker images, and configuration files are being updated.

---

### 3. Stash local Git changes

If you have modified files such as `docker-compose.yml`, configuration files, or other tracked files, stash those changes before switching versions or pulling updates.

```bash
git stash save "pre-upgrade Malcolm configuration changes"
```

This saves your local modifications in Git's stash so the working tree can be cleanly updated.

You can optionally confirm the stash was created:

```bash
git stash list
```

You should see an entry similar to:

```text
stash@{0}: On main: pre-upgrade Malcolm configuration changes
```

> **Note:** `git stash` only saves changes to files tracked by Git by default. If you have important untracked files, back them up separately as described in the next step.

---

### 4. Back up the existing Malcolm directory

Before changing versions, create a backup of the current Malcolm directory.

This backup excludes large runtime data directories, including OpenSearch data, packet captures, and sensor logs.

```bash
rsync -av \
  --exclude='opensearch/*' \
  --exclude='pcap/*' \
  --exclude='suricata-logs/*' \
  --exclude='zeek-logs/*' \
  --exclude='filescan-logs/*' \
  /home/user/Malcolm/ \
  /home/user/Malcolm-git-bak/
```

This creates a backup at:

```text
/home/user/Malcolm-git-bak/
```

The trailing slashes are important:

- `/home/user/Malcolm/` means "copy the contents of this directory"
- `/home/user/Malcolm-git-bak/` is the backup destination

This backup can be useful if you need to manually restore previous configuration settings after the upgrade.

---

### 5. Update the Malcolm Git repository

How you update the repository depends on whether you want to move to a specific release tag or continue tracking a branch such as `main`.

#### Option A: Check out the latest release tag

To upgrade to Malcolm `v{{ site.malcolm.version }}`, fetch the latest tags and check out the release tag:

```bash
git fetch --all --tags --prune
git checkout v{{ site.malcolm.version }}
```

This places your working tree at the exact tagged release.

Use this option if you want a stable, versioned release.

#### Option B: Pull the latest changes from your current branch

If your clone is tracking a branch such as `main`, you can pull the latest changes from GitHub instead:

```bash
git pull --rebase
```

This updates your current branch and reapplies any local commits on top of the latest upstream changes.

Use this option if you intentionally track a branch instead of a release tag.

---

### 6. Reapply the stashed local changes

Now apply the local changes you saved earlier with `git stash`.

```bash
git stash pop
```

This attempts to reapply your saved local changes to the upgraded Malcolm files.

If Git can apply the changes cleanly, the stash entry is removed automatically.

If conflicts occur, Git will report them.

---

### 7. Resolve any merge conflicts

If `git stash pop` reports merge conflicts, you must resolve them before continuing.

You may see messages involving files such as:

```text
Auto-merging docker-compose.yml
CONFLICT (content): Merge conflict in docker-compose.yml
Recorded preimage for 'docker-compose.yml'
HEAD detached at v26.05.0
Unmerged paths:
  (use "git restore --staged <file>..." to unstage)
  (use "git add <file>..." to mark resolution)
    both modified:   docker-compose.yml
```

This is common because `docker-compose.yml` changes between Malcolm releases and is also a file customized by the configuration script.

You can resolve conflicts manually with a text editor. Git's documentation on [merge conflicts](https://git-scm.com/book/en/v2/Git-Branching-Basic-Branching-and-Merging#_basic_merge_conflicts) explains the conflict markers and resolution process.

Conflict markers look similar to this:

```text
<<<<<<< Updated upstream
new version content
=======
your stashed local content
>>>>>>> Stashed changes
```

Edit the file so it contains the correct final configuration, then mark it resolved:

```bash
git add docker-compose.yml
```

Repeat this process for each conflicted file.

Because the Malcolm configuration script will be run later, it may be easier to keep the new release's `docker-compose.yml` rather than manually resolving every conflict in that file.

The new version of `docker-compose.yml` is available here:

[New `docker-compose.yml`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/docker-compose.yml)

To keep the new version of `docker-compose.yml` from the upgraded Malcolm release, run:

```bash
git checkout --ours docker-compose.yml
```

Then mark the conflict resolved:

```bash
git add docker-compose.yml
```

> **Note:** In this conflict context, `--ours` keeps the version from the currently checked-out upgraded Malcolm tree. The stashed changes are considered the other side of the merge.

If you choose this approach, you can manually restore any needed settings from the backup created earlier (`/home/user/Malcolm-git-bak/docker-compose.yml`) after running the configuration script.

> **Note:** If `git stash pop` results in conflicts, Git may keep the stash entry instead of dropping it. After resolving conflicts and confirming the upgrade is correct, you can review remaining stashes with `git stash list` and remove the old upgrade stash with `git stash drop` if it is no longer needed.

---

### 8. Check Git status

After resolving conflicts, check the repository status.

```bash
git status
```

Make sure there are no unresolved paths.

If conflicts remain, Git will list them. Resolve each conflicted file before continuing.

---

Proceed to [**Final Steps**](#UpgradeFinalSteps) below to finish the upgrade and start Malcolm.

## <a name="UpgradeFinalSteps"></a> Final Steps

### 1. Run `status` to migrate configuration and prepopulate new settings' defaults

Run the `status` script to migrate some of the [configuration values]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/config) from the previous Malcolm version and populate new values with their defaults.

```bash
./scripts/status
```

Since Malcolm is not running, you will see output similar to:

```
NAME      IMAGE     COMMAND   SERVICE   CREATED   STATUS    PORTS
```

---

### 2. Run Malcolm configuration

Run the Malcolm [configuration](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig) script:

```bash
./scripts/configure
```

Review the [configuration menu items](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfigItems) carefully.

This step allows you to confirm or update Malcolm's configuration for the new version.

---

### 3. Run authentication setup

Run the [authentication setup](malcolm-hedgehog-e2e-iso-install.md#MalcolmAuthSetup) script:

```bash
./scripts/auth_setup
```

During this step:

- Verify the authentication method
- Do **not** regenerate self-signed certificates unless you intentionally want to replace them (including on any sensors previously communicating with this Malcolm instance)
- Do **not** overwrite existing passwords unless you intentionally want to reset them

The goal is to preserve your existing authentication material while ensuring the upgraded installation is configured correctly.

---

### 4. Pull Docker images

If you already loaded the Docker images using `docker load`, you can skip this step.

If you did not load the release image archive, pull the required images instead:

```bash
docker compose --profile=malcolm pull
```

This downloads the Malcolm images from the GitHub container registry.

---

### 5. Start Malcolm

[Start Malcolm](running.md#Running):

```bash
./scripts/start
```

The startup process may take several minutes.

---

### 6. Verify Malcolm is running

Check container status:

```bash
./scripts/status
```

Confirm that the expected Malcolm services are running and healthy.

---

### 7. Post-upgrade checks

After Malcolm starts successfully, perform the following checks:

1. Log into the Malcolm [web interface](quickstart.md#UserInterfaceURLs).
2. Confirm authentication still works.
3. Verify OpenSearch dashboards load.
4. Confirm previously collected data is present if expected.

Technically minded users may wish to follow the debug output provided by `./scripts/start` (use `./scripts/logs` to re-open the log stream after it's been closed), although there is a lot there and it may be hard to distinguish whether or not something is okay.

```bash
./scripts/logs
```

If a specific service has issues, inspect that service's logs, for example:

```bash
./scripts/logs -s opensearch
./scripts/logs -s arkime
./scripts/logs -s dashboards
```
