# <a name="UpgradePlan"></a>Upgrading Malcolm

At this time there is not an "official" upgrade procedure to get from one version of Malcolm to the next, as it may vary from platform to platform. However, the process is fairly simple can be done by following these steps:

## Update the underlying system

You may wish to get the official updates for the underlying system's software packages before you proceed. Consult the documentation of your operating system for how to do this.

If you are upgrading an Malcolm instance installed from [Malcolm installation ISO](malcolm-iso.md#ISOInstallation), follow scenario 2 below. Due to the Malcolm base operating system's [hardened](hardening.md#Hardening) configuration, when updating the underlying system, temporarily set the umask value to Debian default (`umask 0022` in the root shell in which updates are being performed) instead of the more restrictive Malcolm default. This will allow updates to be applied with the right permissions.

## Scenario 1: Malcolm is a GitHub clone

If you checked out a working copy of the Malcolm repository from GitHub with a `git clone` command, here are the basic steps to performing an upgrade:

1. stop Malcolm
    * `./scripts/stop`
2. stash changes to `docker-compose.yml` and other files
    * `git stash save "pre-upgrade Malcolm configuration changes"`
3. pull changes from GitHub repository
    * `git pull --rebase`
4. pull new Docker images (this will take a while)
    * `docker-compose pull`
5. apply saved configuration change stashed earlier
    * `git stash pop`
6. if you see `Merge conflict` messages, resolve the [conflicts](https://git-scm.com/book/en/v2/Git-Branching-Basic-Branching-and-Merging#_basic_merge_conflicts) with your favorite text editor
7. you may wish to re-run `install.py --configure` as described in [System configuration and tuning](malcolm-config.md#ConfigAndTuning) in case there are any new `docker-compose.yml` parameters for Malcolm that need to be set up
8. start Malcolm
    * `./scripts/start`
9. you may be prompted to [configure authentication](authsetup.md#AuthSetup) if there are new authentication-related files that need to be generated
    * you probably do not need to re-generate self-signed certificates

## Scenario 2: Malcolm was installed from a packaged tarball

If you installed Malcolm from [pre-packaged installation files]({{ site.github.repository_url }}#Packager), here are the basic steps to perform an upgrade:

1. stop Malcolm
    * `./scripts/stop`
2. uncompress the new pre-packaged installation files (using `malcolm_YYYYMMDD_HHNNSS_xxxxxxx.tar.gz` as an example, the file and/or directory names will be different depending on the release)
    * `tar xf malcolm_YYYYMMDD_HHNNSS_xxxxxxx.tar.gz`
3. backup current Malcolm scripts, configuration files and certificates
    * `mkdir -p ./upgrade_backup_$(date +%Y-%m-%d)`
    * `cp -r filebeat/ htadmin/ logstash/ nginx/ auth.env docker-compose.yml net-map.json ./scripts ./README.md ./upgrade_backup_$(date +%Y-%m-%d)/`
3. replace scripts and local documentation in your existing installation with the new ones
    * `rm -rf ./scripts ./README.md`
    * `cp -r ./malcolm_YYYYMMDD_HHNNSS_xxxxxxx/scripts ./malcolm_YYYYMMDD_HHNNSS_xxxxxxx/README.md ./`
4. replace (overwrite) `docker-compose.yml` file with new version
    * `cp ./malcolm_YYYYMMDD_HHNNSS_xxxxxxx/docker-compose.yml ./docker-compose.yml`
5. re-run `./scripts/install.py --configure` as described in [System configuration and tuning](malcolm-config.md#ConfigAndTuning)
6. using a file comparison tool (e.g., `diff`, `meld`, `Beyond Compare`, etc.), compare `docker-compose.yml` and the `docker-compare.yml` file you backed up in step 3, and manually migrate over any customizations you wish to preserve from that file (e.g., `PCAP_FILTER`, `MAXMIND_GEOIP_DB_LICENSE_KEY`, `MANAGE_PCAP_FILES`; [anything else](malcolm-config.md#DockerComposeYml) you may have edited by hand in `docker-compose.yml` that's not prompted for in `install.py --configure`)
7. pull the new docker images (this will take a while)
    * `docker-compose pull` to pull them from [GitHub](https://github.com/orgs/idaholab/packages?repo_name=Malcolm) or `docker-compose load -i malcolm_YYYYMMDD_HHNNSS_xxxxxxx_images.tar.gz` if you have an offline tarball of the Malcolm docker images
8. start Malcolm
    * `./scripts/start`
9. you may be prompted to [configure authentication](authsetup.md#AuthSetup) if there are new authentication-related files that need to be generated
    * you probably do not need to re-generate self-signed certificates

## Post-upgrade

### Monitoring Malcolm

If you are technically-minded, you may wish to follow the debug output provided by `./scripts/start` (or `./scripts/logs` if you need to re-open the log stream after you've closed it), although there is a lot there and it may be hard to distinguish whether or not something is okay.

Running `docker-compose ps -a` should give you a good idea if all of Malcolm's Docker containers started up and, in some cases, may be able to indicate if the containers are "healthy" or not.

After upgrading following one of the previous outlines, give Malcolm several minutes to get started. Once things are up and running, open one of Malcolm's [web interfaces](quickstart.md#UserInterfaceURLs) to verify that things are working.

### Loading new OpenSearch Dashboards visualizations

Once the upgraded instance Malcolm has started up, you'll probably want to import the new dashboards and visualizations for OpenSearch Dashboards. You can signal Malcolm to load the new visualizations by opening OpenSearch Dashboards, clicking **Management** → **Index Patterns**, then selecting the `arkime_sessions3-*` index pattern and clicking the delete **🗑** button near the upper-right of the window. Confirm the **Delete index pattern?** prompt by clicking **Delete**. Close the OpenSearch Dashboards browser window. After a few minutes the missing index pattern will be detected and OpenSearch Dashboards will be signalled to load its new dashboards and visualizations.

## Major releases

The Malcolm project uses [semantic versioning](https://semver.org/) when choosing version numbers. If you are moving between major releases (e.g., from v4.0.1 to v5.0.0), you're likely to find that there are enough major backwards compatibility-breaking changes that upgrading may not be worth the time and trouble. A fresh install is strongly recommended between major releases.