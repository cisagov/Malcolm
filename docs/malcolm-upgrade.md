# <a name="UpgradePlan"></a>Upgrading Malcolm

At this time there is not an "official" version upgrade procedure for Malcolm, as such procedures vary from platform to platform. However, the process is fairly simple and can be done by following these steps:

## Update the underlying system

Users may wish to apply official updates for the underlying system's software packages before proceededing. Consult operating system documentation for instructions on applying system updates.

If upgrading a Malcolm instance installed from [Malcolm installation ISO](malcolm-iso.md#ISOInstallation), follow Scenario 2 below. Due to the Malcolm base operating system's [hardened](hardening.md#Hardening) configuration, users updating the underlying system must temporarily set the umask value to Debian default (`umask 0022` in the root shell in which updates are being performed) instead of the more restrictive Malcolm default. This will allow updates to be applied with the correct permissions.

## Scenario 1: Malcolm is a GitHub clone

Here are the basic steps to perform an upgrade if Malcolm was checked with a `git clone` command:

1. stop Malcolm
    * `./scripts/stop`
1. stash changes to `docker-compose.yml` and other files
    * `git stash save "pre-upgrade Malcolm configuration changes"`
1. save a backup of the [environment variable files](malcolm-config.md#MalcolmConfigEnvVars) in the Malcolm `./config/` directory
1. pull changes from GitHub repository
    * `git pull --rebase`
1. pull new Docker images (this will take a while)
    * `docker-compose pull`
1. apply saved configuration change stashed earlier
    * `git stash pop`
1. if `Merge conflict` messages appear, resolve the [conflicts](https://git-scm.com/book/en/v2/Git-Branching-Basic-Branching-and-Merging#_basic_merge_conflicts) with a text editor
1. re-run `./scripts/configure` as described in [Malcolm Configuration](malcolm-config.md#ConfigAndTuning) in case there are any new configuration parameters for Malcolm that need to be set up
1. start Malcolm
    * `./scripts/start`
1. users may be prompted to [configure authentication](authsetup.md#AuthSetup) if there are new authentication-related files that need to be generated
    * users probably do not need to re-generate self-signed certificates

## Scenario 2: Malcolm was installed from a packaged tarball

If Malcolm was installed from [pre-packaged installation files]({{ site.github.repository_url }}#Packager), here are the basic steps to perform an upgrade:

1. stop Malcolm
    * `./scripts/stop`
1. uncompress the new pre-packaged installation files (using `malcolm_YYYYMMDD_HHNNSS_xxxxxxx.tar.gz` as an example, the file and/or directory names will be different depending on the release)
    * `tar xf malcolm_YYYYMMDD_HHNNSS_xxxxxxx.tar.gz`
1. backup current Malcolm scripts, configuration files and certificates
    * `mkdir -p ./upgrade_backup_$(date +%Y-%m-%d)`
    * `cp -r filebeat/ htadmin/ logstash/ nginx/ config/ docker-compose.yml ./scripts ./README.md ./upgrade_backup_$(date +%Y-%m-%d)/`
1. replace scripts and local documentation in the existing installation with the new ones
    * `rm -rf ./scripts ./README.md`
    * `cp -r ./malcolm_YYYYMMDD_HHNNSS_xxxxxxx/scripts ./malcolm_YYYYMMDD_HHNNSS_xxxxxxx/README.md ./`
1. replace (overwrite) `docker-compose.yml` file with new version
    * `cp ./malcolm_YYYYMMDD_HHNNSS_xxxxxxx/docker-compose.yml ./docker-compose.yml`
1. re-run `./scripts/configure` as described in [Malcolm Configuration](malcolm-config.md#ConfigAndTuning)
    * to do an in-depth comparison of the previous version's settings with the new setings:
        + using a file comparison tool (e.g., `diff`, `meld`, `Beyond Compare`, etc.), compare `docker-compose.yml` and the `docker-compare.yml` file backed up in Step 3, and manually migrate over any customizations in file
        + compare the contents of each  `.env` file  Malcolm's `./config/` directory with its corresponding `.env.example` file
1. pull the new docker images (this will take a while)
    * `docker-compose pull` to pull them from [GitHub](https://github.com/orgs/idaholab/packages?repo_name=Malcolm) or `docker-compose load -i malcolm_YYYYMMDD_HHNNSS_xxxxxxx_images.tar.xz` if an offline tarball of the Malcolm docker images is available
1. start Malcolm
    * `./scripts/start`
1. users may be prompted to [configure authentication](authsetup.md#AuthSetup) if there are new authentication-related files that need to be generated
    * users probably do not need to re-generate self-signed certificates

## Post-upgrade

### Monitoring Malcolm

Technically minded users may wish to follow the debug output provided by `./scripts/start` (use `./scripts/logs` to re-open the log stream after it's been closed), although there is a lot there and it may be hard to distinguish whether or not something is okay.

Running `docker-compose ps -a` should provide a good indication that all Malcolm's Docker containers started up and, in some cases, may be able to indicate if the containers are "healthy" or not.

After upgrading following one of the previous outlines, give Malcolm several minutes to get started. Once things are up and running, open one of Malcolm's [web interfaces](quickstart.md#UserInterfaceURLs) to verify that things are working.

### Loading new OpenSearch Dashboards visualizations

Once the upgraded instance Malcolm has started up, users will want to import the new dashboards and visualizations for OpenSearch Dashboards. Users can signal Malcolm to load the new visualizations by opening OpenSearch Dashboards, clicking **Management** → **Index Patterns**, then selecting the `arkime_sessions3-*` index pattern and clicking the delete **🗑** button near the upper-right of the window. Confirm the **Delete index pattern?** prompt by clicking **Delete**. Close the OpenSearch Dashboards browser window. After a few minutes the missing index pattern will be detected and OpenSearch Dashboards will be signalled to load its new dashboards and visualizations.

## Major releases

The Malcolm project uses [semantic versioning](https://semver.org/) when choosing version numbers. When moving between major releases (e.g., from v4.0.1 to v5.0.0), users are likely to find there are enough major backwards compatibility-breaking changes that upgrading may not be worth the time and trouble. A fresh install is strongly recommended between major releases.