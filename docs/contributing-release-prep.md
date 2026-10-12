# <a name="ReleasePrep"></a>Preparing a Malcolm Release

This document outlines the steps a Malcolm developer goes through to publish a release of Malcolm. This guide assumes the developer has been doing their work downstream in a fork of the main [Malcolm repository upstream]({{ site.github.repository_url }}), forked at `romeogdetlevjr/Malcolm` by the fictitious Malcolm developer Romeo G Detlev Jr. concocted for this example.

## 1. Review the project milestone and the branch from which the release will be staged

Malcolm tracks issues (whether they be bugs, new features, enhancements, etc.) for release milestones using a [GitHub project](https://github.com/orgs/cisagov/projects/98). Before building release candidate images, Romeo reviews the items for the upcoming release in the corresponding project milestone and ensures that all items assigned to it have their status set to **Done**, each item having been completed and tested locally by the developer to which the issue was assigned.

Romeo also ensures that all work towards this release has been pulled into the branch on his fork from which the release will be cut. If [pull requests]({{ site.github.repository_url }}/pulls) have been submitted upstream which resolve the issues assigned to this release, those pull requests should be merged into the branch at `romeogdetlevjr/Malcolm`, whether they were submitted initially against that fork or pulled in manually by Romeo as part of this release process. Pull requests are not accepted directly into the `main` branch of the official [upstream fork]({{ site.github.repository_url }}). In other words, the branch of Malcolm in Romeo's development fork should contain **everything** that is going to comprise this release of Malcolm.

There are several places in the Malcolm source code where the release version itself (e.g., `{{ site.malcolm.version }}`) needs to be present. Most of these places are in the documentation, consisting of markdown files, but others include [docker-compose.yml]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/docker-compose.yml), [docker-compose-dev.yml]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/docker-compose-dev.yml), and the [Kubernetes manifests]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/kubernetes). Most likely Romeo's first commit into his branch as he worked on this release was to bump those version strings ([like this](https://github.com/romeogdetlevjr/Malcolm/commit/cc7d0d8855b5cc4f04cd38ae22d1421c627444cc)), but he should verify now that he did so.

## 2. Build Malcolm container images using GitHub runners

Images and artifacts for release should not be built on Romeo's own development workstation. Instead, carefully reviews the documentation for [using GitHub runners to build Malcolm images](contributing-github-runners.md#GitHubRunners) (including setting up his [GitHub repository actions secrets and variables](contributing-github-runners.md#secrets-and-variables)) and starts builds of the GitHub container images [with a workflow or repository dispatch API trigger](contributing-github-runners.md#triggers). He monitors the [progress of the workflow actions]({{ site.github.repository_url }}/actions) and ensures that they complete successfully, including jobs for both `docker (linux/amd64)` and `docker (linux/arm64)` where applicable.

## 3. Build Malcolm ISO images using GitHub runners

The [workflow for building the Malcolm installer ISO]({{ site.github.repository_url }}/actions/workflows/malcolm-iso-build-docker-wrap-push-ghcr.yml) and [Hedgehog Linux installer ISO]({{ site.github.repository_url }}/actions/workflows/hedgehog-iso-build-docker-wrap-push-ghcr.yml) need to be run **after** all of the container image "build-and-push" actions have completed successfully, as those images are pulled and archived inside of the ISO itself. Once Romeo is sure that all of the actions for building the container images from the previous step have completed successfully, he initiates a run of the [`malcolm-iso-build-docker-wrap-push-ghcr`]({{ site.github.repository_url }}/actions/workflows/malcolm-iso-build-docker-wrap-push-ghcr.yml) and [`hedgehog-iso-build-docker-wrap-push-ghcr`]({{ site.github.repository_url }}/actions/workflows/hedgehog-iso-build-docker-wrap-push-ghcr.yml) actions.

## 4. Pull the container images from ghcr.io

Once all of the release candidate images have been built by their respective GitHub actions, Romeo can use the [convenience helper script](contributing-github-runners.md#convenience-scripts-for-development) (found at [`./scripts/github_image_helper.sh`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/scripts/github_image_helper.sh) in the Malcolm source code) which has the following purposes:

1. To pull the freshly-built container images from ghcr.io named with his fork's tags (e.g., `ghcr.io/romeogdetlevjr/malcolm/zeek:main`)
2. To tag these images with their "official" tags (e.g., `ghcr.io/idaholab/malcolm/zeek:{{ site.malcolm.version }}`)
3. To extract the ISO 9660-formatted ISO files for the Malcolm and Hedgehog Linux installer ISOs

Romeo carefully reviews the documentation on this [convenience helper script](contributing-github-runners.md#convenience-scripts-for-development), then runs it. When it has completed, he verifies with `docker images` that he pulled the new container images (checking the containers' ages with the `CREATED` column) and that he has the `.iso` files he expects to have.

## 5. Extract, install, and test ISO images

Now that he's got the `.iso` files for Malcolm and Hedgehog Linux, Romeo fires up some virtualization software ([VMware Workstation](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion), [VirtualBox](https://www.virtualbox.org/), or, his personal favorite, [virt-manager](https://virt-manager.org/)) and installs the ISOs into their respective VMs. He makes sure his VMs are configured to meet the [recommended system requirements](system-requirements.md#SystemRequirements). He follows the [end-to-end Malcolm and Hedgehog Linux ISO Installation](malcolm-hedgehog-e2e-iso-install.md#InstallationExample) example in the documentation to install and configure Malcolm and Hedgehog Linux, resulting in a configuration where the VMs are successfully communicating with each other.

Romeo knows that verifying live traffic capture is an important part of testing both [Hedgehog Linux](live-analysis.md#Hedgehog) and [Malcolm](live-analysis.md#LocalPCAP). He has used a few open-source tools to generate "real" live Internet traffic in his VMs, including [PartyLoud](https://github.com/mmguero-dev/PartyLoud), [alphasoc/flightsim](https://github.com/alphasoc/flightsim), and [3CORESec/testmynids.org](https://github.com/3CORESec/testmynids.org). He downloads these utilities into both VMs and configures both Malcolm and Hedgehog Linux to capture the live traffic generated, and validates the resulting traffic metadata generated by Zeek, Suricata, and Arkime looks correct in both [OpenSearch Dashboards](dashboards.md#Dashboards) and [Arkime](arkime.md#Arkime). He makes a special note to use [Arkime's sessions interface](arkime.md#ArkimeSessions) to retrieve a PCAP payload for an Arkime session captured on each VM.

### `malcolm-test`: Malcolm System Tests

In addition to the `.iso` spot checks described above, Romeo uses [`malcolm-test`](contributing-malcolm-test.md#MalcolmTest) to ensure that the release candidate does not introduce any regressions. He also carefully reviews each issue assigned to this milestone on the [GitHub project board](https://github.com/orgs/cisagov/projects/98) and verifies that new [tests](https://github.com/idaholab/Malcolm-Test/tree/main/src/maltest/tests) were [created](https://github.com/idaholab/Malcolm-test?tab=readme-ov-file#TestCreation) to cover new features and bug fixes wherever possible.

## 6. Extract Hedgehog Linux Raspberry Pi image

The Hedgehog Linux [Raspberry Pi Image](hedgehog-raspi.md#HedgehogRaspiBuild) is also built on GitHub. As that image targets an ARM64 architecture, it can be pulled and extracted on an ARM64-based machine using the [convenience helper script](contributing-github-runners.md#convenience-scripts-for-development) mentioned earlier in step 4.

## 7. Submit and merge a pull request

Now that he's satisfied that everything looks ship-shape for the release, Romeo drafts and submits a pull request from his development fork to the [Malcolm repository upstream]({{ site.github.repository_url }}), where it should be carefully reviewed, preferably by Romeo and another Malcolm developer together.

Once the PR has been carefully reviewed by the necessary parties to everyone's satisfaction, it can be merged info the `main` branch upstream.

## 8. Push official images to ghcr.io

Earlier Romeo used the [convenience helper script](contributing-github-runners.md#convenience-scripts-for-development) to pull and tag the container images that would become the official images for this release. He now pushes those images to ghcr.io, making them available to the public in the official upstream namespace with their final release tags. He uses some script-fu to do this, listing the container images, filtering for the newly-tagged `idaholab` images for this release, and using `xargs` to execute a `docker push` command for each:

```bash
$ docker images \
    | grep -P "ghcr\.io/idaholab/malcolm/.+24\.10\.1" \
    | awk '{print $1 ":" $2}' \
    | xargs -r -l docker push

Getting image source signatures
Copying blob f944ed4242ed skipped: already exists
…
Copying config 2c88f94597 done   |
Writing manifest to image destination
…
Writing manifest to image destination
Getting image source signatures
Copying blob 43c4264eed91 skipped: already exists
…
Copying config caff12e3c5 done   |
Writing manifest to image destination
```

The push should actually go very quickly, because the container registry is smart enough to realize that the images already exist (with the `romeogdetlevjr` tags), so there will be a lot of "Copying blob … skipped: already exists" messages in the output.

## 9. Pulling and pushing the arm64 images

Romeo's primary development workstation is a Linux system running on the x86_64/amd64 architecture. He realizes that Malcolm has had [arm64 support](https://github.com/idaholab/Malcolm/issues/389) for some time. However, the convenience script he used to pull and tag the Malcolm images as described above is only doing so for the `amd64` container images.

Romeo switches over to an arm64-based machine (in his case, his Apple M2 Max MacBook Pro) and repeats the steps from **Pull the container images from ghcr.io** and **Push official images to ghcr.io** above, only this time for the Malcolm images with the `-arm64` suffixed tags.

## 10. Prepare release artifacts

Romeo appreciates it when open source projects include detailed release notes, so he carefully goes writes some to accompany this release of Malcolm. Using the pattern followed in [previous Malcolm releases]({{ site.github.repository_url }}/releases), he uses Markdown to draft release notes including:

* New features and enhancements
* Version bumps for any components or libraries used by Malcolm
* Bugs fixed
* Changes to [environment variable files](malcolm-config.md#MalcolmConfigEnvVars)
* Breaking changes (things that aren't backwards compatible, things requiring a re-run of the `configure` script, etc.)

There are two general categories of files that need to be generated to be included with the Malcolm release as assets, broken down thusly:

* Images
    - Malcolm installer ISO
    - Hedgehog Linux installer ISO
    - Hedgehog Linux Raspberry Pi image
* Scripts and tarball for a standalone Docker installation

Romeo checks out and switches his GitHub repository's working copy so that it's tracking the [upstream branch]({{ site.github.repository_url }}) (e.g., `git checkout main` and `git branch --set-upstream-to idaholab/main`). Running `git log -1` should show that the latest commit to this branch is the merge of the pull request performed earlier.

Romeo creates a local directory to contain the release artifacts and runs `./scripts/malcolm_appliance_packager.sh` to package up the scripts and tarball for a standalone Docker installation (the output of that script is somewhat verbose, so it's been summarized for display here):

```bash
$ mkdir releases

$ cd releases

$ ~/Malcolm/scripts/malcolm_appliance_packager.sh
…
mkdir: created directory …

Package Kubernetes manifests in addition to docker-compose.yml [y/N]? y
…
Packaged Malcolm to "/home/romeogdetlevjr/Malcolm/releases/malcolm_20241008_215936_deadbeef.tar.gz"

Do you need to package container images also [y/N]? n

To install and configure Malcolm, run install.py

To start, stop, restart, etc. Malcolm:
  Use the control scripts in the "scripts/" directory:
   - start       (start Malcolm)
   - stop        (stop Malcolm)
   - restart     (restart Malcolm)
   - logs        (monitor Malcolm logs)
   - wipe        (stop Malcolm and clear its database)
   - auth_setup  (change authentication-related settings)

Malcolm services can be accessed at https://<IP or hostname>/

$ ls -l
total 749,568
drwxrwxr-x 10 romeogdetlevjr romeogdetlevjr     156 Oct 29 14:15 installer
-rwxrwxr-x  1 romeogdetlevjr romeogdetlevjr  44,201 Oct 29 14:15 install.py
-rw-rw-r--  1 romeogdetlevjr romeogdetlevjr     460 Oct 29 14:15 malcolm_20251029_140727_d22a504f.README.txt
-rw-rw-r--  1 romeogdetlevjr romeogdetlevjr 275,657 Oct 29 14:15 malcolm_20251029_140727_d22a504f.tar.gz
-rw-rw-r--  1 romeogdetlevjr romeogdetlevjr  75,769 Oct 29 14:15 malcolm_common.py
-rw-rw-r--  1 romeogdetlevjr romeogdetlevjr   5,685 Oct 29 14:15 malcolm_constants.py
-rw-rw-r--  1 romeogdetlevjr romeogdetlevjr  50,329 Oct 29 14:15 malcolm_kubernetes.py
-rw-rw-r--  1 romeogdetlevjr romeogdetlevjr  36,952 Oct 29 14:15 malcolm_utils.py
```

The resultant `.py`, `.tar.gz,` and `.txt` files are ready to be included as assets in the Malcolm release on GitHub.

As described in the documentation for [downloading Malcolm](download.md#JoinISOs), due to [limits on individual files](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases#storage-and-bandwidth-quotas) in GitHub releases, the binary image files have been split into 2GB chunks. The same scripts (for Bash ([release_cleaver.sh]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/scripts/release_cleaver.sh)) and PowerShell ([release_cleaver.ps1]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/scripts/release_cleaver.ps1))) used to join the files can be used to split them up:

```bash
$ ls -l
total 8,502,263,808
-rw-r--r-- 1 romeogdetlevjr romeogdetlevjr     1,209,240 Oct 22 09:50 hedgehog-{{ site.malcolm.version }}-build.log
-rw-r--r-- 1 romeogdetlevjr romeogdetlevjr 2,664,972,288 Oct 22 09:50 hedgehog-{{ site.malcolm.version }}.iso
-rw-r--r-- 1 romeogdetlevjr romeogdetlevjr       963,775 Oct 22 09:49 malcolm-{{ site.malcolm.version }}-build.log
-rw-r--r-- 1 romeogdetlevjr romeogdetlevjr 5,835,110,400 Oct 22 09:49 malcolm-{{ site.malcolm.version }}.iso

$ for ISO in *.iso; do ~/Malcolm/scripts/release_cleaver.sh "$ISO"; done
Splitting...
bf6e71385046b39d265af3dfc5b77677a0ac5eeac86bdc5be48791d0900715df  hedgehog-{{ site.malcolm.version }}.iso
Splitting...
b4957741420ec06988d975cdb7f71eaa201918245f6fcb7ee2641d7d0ad97c52  malcolm-{{ site.malcolm.version }}.iso

$ ls -l
total 17,002,364,928
-rw-r--r-- 1 romeogdetlevjr romeogdetlevjr     1,209,240 Oct 22 09:50 hedgehog-{{ site.malcolm.version }}-build.log
-rw-r--r-- 1 romeogdetlevjr romeogdetlevjr 2,664,972,288 Oct 22 09:50 hedgehog-{{ site.malcolm.version }}.iso
-rw-r--r-- 1 romeogdetlevjr romeogdetlevjr 2,000,000,000 Oct 22 10:40 hedgehog-{{ site.malcolm.version }}.iso.01
-rw-r--r-- 1 romeogdetlevjr romeogdetlevjr   664,972,288 Oct 22 10:40 hedgehog-{{ site.malcolm.version }}.iso.02
-rw-r--r-- 1 romeogdetlevjr romeogdetlevjr            87 Oct 22 10:40 hedgehog-{{ site.malcolm.version }}.iso.sha
-rw-r--r-- 1 romeogdetlevjr romeogdetlevjr       963,775 Oct 22 09:49 malcolm-{{ site.malcolm.version }}-build.log
-rw-r--r-- 1 romeogdetlevjr romeogdetlevjr 5,835,110,400 Oct 22 09:49 malcolm-{{ site.malcolm.version }}.iso
-rw-r--r-- 1 romeogdetlevjr romeogdetlevjr 2,000,000,000 Oct 22 10:41 malcolm-{{ site.malcolm.version }}.iso.01
-rw-r--r-- 1 romeogdetlevjr romeogdetlevjr 2,000,000,000 Oct 22 10:41 malcolm-{{ site.malcolm.version }}.iso.02
-rw-r--r-- 1 romeogdetlevjr romeogdetlevjr 1,835,110,400 Oct 22 10:41 malcolm-{{ site.malcolm.version }}.iso.03
-rw-r--r-- 1 romeogdetlevjr romeogdetlevjr            86 Oct 22 10:41 malcolm-{{ site.malcolm.version }}.iso.sha
```

The resultant files (with the `.iso.##` and `.iso.sha` extensions) are the files ready to be included as assets in the Malcolm release on GitHub.

## 11. Publish the release

Romeo goes to the [releases]({{ site.github.repository_url }}/releases) page of the upstream repository. He clicks **Draft a new release**. On the new release page, he enters the release tag under **Choose a tag** (e.g., `v{{ site.malcolm.version }}`) with `main` as the target. He puts **Malcolm v{{ site.malcolm.version }}** as the release title, and pastes the content of the markdown release notes he wrote into the **Write** input where it prompts him to **Describe this release**.

Romeo attaches the asset files from the previous step where it says "↓ Attach binaries by dropping them here or selecting them." He ensures that **Set as the latest release** is checked.

After reviewing the contents of this page, Romeo pushes the green **Publish release** button, making this the latest official Malcolm release.

## 12. Close project milestone

Finally, Romeo navigates back to the [GitHub project](https://github.com/orgs/idaholab/projects/1) and changes the status of each issue under the now-released milestone from **Done** to **Released**. He then navigates to the [milestones]({{ site.github.repository_url }}/milestones) page on GitHub and clicks **Close** for that milestone.

# <a name="IronBankRelease"></a>Updating Malcolm Iron Bank Images

Malcolm publishes hardened container images to the DoD's Iron Bank (IB), the centralized repository of vetted, continuously rescanned images maintained under Platform One ([official documentation](https://p1docs.dso.mil/iron-bank/faq)). The images themselves are available at [repo1.dso.mil/dsop/afdco/malcolm](https://repo1.dso.mil/dsop/afdco/malcolm). These builds exist because government and defense teams often cannot pull from public container registries at all, and even when they can, an Authority to Operate (ATO) usually requires proof that a container has passed vulnerability scanning, STIG checks, and supply-chain validation. Iron Bank handles much of that work up front, so anyone deploying Malcolm inside a DoD network, on an Impact Level 2 system, or as part of an accreditation package already has the scan history and documentation available alongside the image. Users outside that environment, running Malcolm in a non-U.S. government setting, will generally find the official upstream `ghcr.io/idaholab` images simpler and faster to update. But for systems integrators, ISSOs pursuing an ATO, or anyone who needs to answer "where did this container come from" during an audit, the Iron Bank builds may be worth using.

This section describes how Malcolm developers update the Iron Bank images after a [Malcolm release](#ReleasePrep).

## 1. Clone the git repositories for the Malcolm Iron Bank images

If working copies for the Malcolm IB image repositories don't yet exist locally, clone them:

```bash
IRON_BANK_PARENT_PATH=/path/to/iron-bank
mkdir -p "$IRON_BANK_PARENT_PATH"

for REPO in \
    api \
    arkime \
    dashboards \
    dashboards-helper \
    dirinit \
    filebeat \
    filescan \
    file-upload \
    freq \
    htadmin \
    keycloak \
    logstash-oss \
    netbox \
    nginx \
    opensearch \
    pcap-capture \
    pcap-monitor \
    postgresql \
    redis \
    strelka-backend \
    strelka-frontend \
    strelka-manager \
    suricata \
    zeek \
; do
    git clone https://repo1.dso.mil/dsop/afdco/malcolm/"$REPO".git
    pushd "$REPO" >/dev/null 2>&1
    for BRANCH in master development inl-26.x; do
        git checkout "$BRANCH"
    done
    popd >/dev/null 2>&1
done
```

As illustrated above, users will likely want the `master` and `development` branches, as well as whatever "working" or "update" branch is going to be used to stage the changes.

## 2. Perform automated version bumps in the hardening manifests

Run [`./scripts/iron-bank/bump-iron-bank-hardening-manifest.sh`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/scripts/iron-bank/bump-iron-bank-hardening-manifest.sh) for each image's `hardening_manifest.yaml`:

```bash
IRON_BANK_PARENT_PATH=/path/to/iron-bank
MALCOLM_TAG={{ site.malcolm.version }}

for REPO_DIR in $(find "$IRON_BANK_PARENT_PATH" -mindepth 1 -maxdepth 1 -type d | sed "s@\./@@") \
; do
    pushd "$REPO_DIR" >/dev/null 2>&1
    REPO_NAME="$(basename `git config --get remote.origin.url` | sed 's/\.git$//')"
    GITHUB_TOKEN=ghp_xxxxxxxxxxxx bump-iron-bank-hardening-manifest.sh "$MALCOLM_TAG"
    popd >/dev/null 2>&1
done
```

This script bumps the version tag in a `hardening_manifest.yaml`, resolves the new upstream container digest via `docker buildx imagetools`, re-downloads the Malcolm source tarball (if necessary) to compute its new sha512 sum, and pulls the commit sha and commit date for the corresponding git tag into `VCS_REVISION` and `BUILD_DATE`. A GitHub personal access token can be picked up from `$GITHUB_TOKEN` to authenticate the GitHub API call and avoid the unauthenticated rate limit (60 req/hr per IP).

For each image working copy, this script will output something like:

```
Using GitHub token for API authentication
Old version: 26.08.0
New version: 26.09.0
Updated tags: entry
Updated org.opencontainers.image.version label
Inspecting ghcr.io/idaholab/malcolm/api:26.09.0 ...
New digest: sha256:d2d1d6f2df02bbb895e3b2e9c69e47915185e4b3bc79b74797952eee6a312944
Downloading https://github.com/idaholab/Malcolm/archive/refs/tags/v26.09.0.tar.gz ...
New sha512: 4b856ba57893c76ed28fd936c25dd4bd9caef4b3c774402afd0d9842f64d15ea08dba235d2f9381b08fa471a32b46453f3a79dc597f563014d5e634e1d1ec832
Resolving commit for tag v26.09.0 on https://github.com/idaholab/Malcolm ...
New VCS_REVISION: b09a0ad
Fetching commit date for b09a0adaee18421bcc24f3c5608d2135a6ee84bb ...
New BUILD_DATE: 2026-09-29T20:47:52Z
Done. Updated ./hardening_manifest.yaml from 26.08.0 to 26.09.0.
```

## 3. Perform manual updates to the hardening manifests and Dockerfiles

Review the [`./Dockerfiles`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/Dockerfiles) of the [latest Malcolm release]({{ site.github.repository_url }}/releases/latest) and make note of all other changes not covered by the automatic version bumps in the previous step. These may include:

* Changes to base Docker images (`BASE_IMAGE` and `BASE_TAG`)
* Version updates of included tools like [`supercronic`](github.com/aptible/supercronic) or [`yq`](https://github.com/mikefarah/yq)
* Changed build logic or references to moved or new files or directories

Upstream changes will need to be reflected in `Dockerfile` and `hardening_manifest.yaml` in each Iron Bank Malcolm image repository. One-off changes will likely need to be made by hand, while other things may be able to be done in bulk.

For example, if the `yq` utility had been updated from v4.53.6 to v4.54.1, that update could be done across all hardening manifests at once:

```bash
$ grep -A 3 yq_linux_amd64 */hardening_manifest.yaml
dashboards-helper/hardening_manifest.yaml:  - filename: yq_linux_amd64
dashboards-helper/hardening_manifest.yaml:    url: https://github.com/mikefarah/yq/releases/download/v4.53.6/yq_linux_amd64
dashboards-helper/hardening_manifest.yaml-    validation:
dashboards-helper/hardening_manifest.yaml-      type: sha512
dashboards-helper/hardening_manifest.yaml-      value: 508f4ee34c6d093d136ff3c1b36db4105e686c3d68d435c064448ba16e2616d528efafb2cb0a1890b7724890373a226a38b7da27e6796396ee759bed39a8c671
--
filebeat/hardening_manifest.yaml:  - filename: yq_linux_amd64
filebeat/hardening_manifest.yaml:    url: https://github.com/mikefarah/yq/releases/download/v4.53.6/yq_linux_amd64
filebeat/hardening_manifest.yaml-    validation:
filebeat/hardening_manifest.yaml-      type: sha512
filebeat/hardening_manifest.yaml-      value: 508f4ee34c6d093d136ff3c1b36db4105e686c3d68d435c064448ba16e2616d528efafb2cb0a1890b7724890373a226a38b7da27e6796396ee759bed39a8c671
--
...
```

Both the version number and sha sum for the updated version would need to be changed. For the version number:

```bash
OLD_VERSION=4.53.6

NEW_VERSION=4.54.1

sed -i "s@\(yq/releases/download/\)v$OLD_VERSION@\1v$NEW_VERSION@" */hardening_manifest.yaml
```

For the sha sum, the new binary will need to be downloaded and the new checksum calculated:

```bash
OLD_SUM=508f4ee34c6d093d136ff3c1b36db4105e686c3d68d435c064448ba16e2616d528efafb2cb0a1890b7724890373a226a38b7da27e6796396ee759bed39a8c671

curl -fsSLOJ 'https://github.com/mikefarah/yq/releases/download/v4.54.1/yq_linux_amd64'

NEW_SUM=$(sha512sum yq_linux_amd64 | awk '{print $1}')

sed -i "s@$OLD_SUM@$NEW_SUM@" */hardening_manifest.yaml

rm -f yq_linux_amd64
```

Verify the updated version and sha sum was written:

```bash
$ grep -A 3 yq_linux_amd64 */hardening_manifest.yaml
dashboards-helper/hardening_manifest.yaml:  - filename: yq_linux_amd64
dashboards-helper/hardening_manifest.yaml:    url: https://github.com/mikefarah/yq/releases/download/v4.54.1/yq_linux_amd64
dashboards-helper/hardening_manifest.yaml-    validation:
dashboards-helper/hardening_manifest.yaml-      type: sha512
dashboards-helper/hardening_manifest.yaml-      value: 57a5e74afd5aafb63c373be84c37fb778957051af3f2d1f563ae77df27b16f0e221cd64a6b7d7729f087fccbfe7d5b4aa1b42e9004d6c2df478f160b17392ead
--
filebeat/hardening_manifest.yaml:  - filename: yq_linux_amd64
filebeat/hardening_manifest.yaml:    url: https://github.com/mikefarah/yq/releases/download/v4.54.1/yq_linux_amd64
filebeat/hardening_manifest.yaml-    validation:
filebeat/hardening_manifest.yaml-      type: sha512
filebeat/hardening_manifest.yaml-      value: 57a5e74afd5aafb63c373be84c37fb778957051af3f2d1f563ae77df27b16f0e221cd64a6b7d7729f087fccbfe7d5b4aa1b42e9004d6c2df478f160b17392ead
--
...
```

## 4. Commit and push the updates to the repositories

```bash
IRON_BANK_PARENT_PATH=/path/to/iron-bank
MALCOLM_TAG={{ site.malcolm.version }}

for REPO_DIR in $(find "$IRON_BANK_PARENT_PATH" -mindepth 1 -maxdepth 1 -type d | sed "s@\./@@") \
; do
    pushd "$REPO_DIR" >/dev/null 2>&1
    REPO_NAME="$(basename `git config --get remote.origin.url` | sed 's/\.git$//')"
    git add ./Dockerfile ./hardening_manifest.yaml && \
        git commit -m "Updates to the $REPO_NAME image for Malcolm v$MALCOLM_TAG" && \
        git push
    popd >/dev/null 2>&1
done
```

## 5. Monitor the image builds for failures

Open the Iron Bank pipeline page for each repository (this example requires xdg-open from xdg-utils) and monitor each pipeline build for failures.

```bash
IRON_BANK_PARENT_PATH=/path/to/iron-bank

for REPO_DIR in $(find "$IRON_BANK_PARENT_PATH" -mindepth 1 -maxdepth 1 -type d | sed "s@\./@@") \
; do
    pushd "$REPO_DIR" >/dev/null 2>&1
    REPO_NAME="$(basename `git config --get remote.origin.url` | sed 's/\.git$//')"
    xdg-open "https://repo1.dso.mil/dsop/afdco/malcolm/$REPO_NAME/-/pipelines"
    popd >/dev/null 2>&1
done
```

Investigate and fix any failed builds.

## 6. Test Malcolm Iron Bank images

Pull and tag the Iron Bank images:

```bash
IRON_BANK_PARENT_PATH=/path/to/iron-bank
BRANCH=inl-26.x
TAG=26.08.0-ib
CONTAINER_ENGINE=docker

for REPO_DIR in $(find "$IRON_BANK_PARENT_PATH" -mindepth 1 -maxdepth 1 -type d | sed "s@\./@@") \
; do
    pushd "$REPO_DIR" >/dev/null 2>&1
    REPO_NAME="$(basename `git config --get remote.origin.url` | sed 's/\.git$//')"
    gitlab-artifacts-download.py \
        -p "$REPO_NAME" \
        -b "$BRANCH" \
        -j create-tar \
        -t ghcr.io/idaholab/malcolm/"$REPO_NAME":"$TAG"
    popd >/dev/null 2>&1
done

for PAIR in filebeat:filebeat-oss \
            nginx:nginx-proxy \
            redis:valkey; do \
    "$CONTAINER_ENGINE" tag ghcr.io/idaholab/malcolm/${PAIR%:*}:$TAG ghcr.io/idaholab/malcolm/${PAIR#*:}:$TAG
done
```

You'll need to modify your local Malcolm installation's `docker-compose.yml` file:

* `yq -i '.services[] |= . + {"user": "0:0"}' docker-compose.yml`
* Add `-ib` (or whatever else you used as  tag suffix in the commands above, if any, to the `image:` line of each service)

Start Malcolm and verify that all containers are running as expected.

## 7. Submit pull requests to Iron Bank

The script [`./scripts/iron-bank/malcolm-iron-bank-merge-requests.sh`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/scripts/iron-bank/malcolm-iron-bank-merge-requests.sh) can help get these started in bulk. Verify the variables at the top of that script before running it. The pull requests should be from your working branch (e.g., `inl-26.x`) to `development`. Follow the instructions in Iron Bank for applying labels, etc., to make sure these PRs are flagged to be reviewed by Iron Bank staff.

# <a name="ReleaseHelmChart"></a>Updating the Malcolm Helm Chart

This section outlines updating the [Malcolm-Helm chart](https://github.com/idaholab/Malcolm-Helm) corresponding with a Malcolm release.

These changes should be done in a fork or branch of the Malcolm-Helm git repository then submitted as a pull request.

## 1. Update `Chart.yaml`

Update `version` and `appVersion` in `chart/Chart.yaml`. Note that `version` does not use leading zeroes (`26.8.0`) while `appVersion` does (`26.08.0`).

## 2. Update `values.yaml` and templates

Examine the [latest Malcolm release]({{ site.github.repository_url }}/releases/latest) for changes that may need to be reflected in the helm chart. Likely areas where you will find these changes include, but are not limited to, the following:

* [`docker-compose.yml`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/docker-compose.yml)
    * Most changes to `docker-compose.yml` will have an analogue in the helm chart service templates. These might include changes to services' `env_file` sections, volume bind mounts, capabilities, etc.
[`config/`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/config)
    * Changes in the `*.env.example` files will need to be reflected in their corresponding `ConfigMap`/`configMapRef` sections.
* [`kubernetes/`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes)
    * Malcolm's non-helm [Kubernetes manifests](kubernetes.md) can be found here and will likely have some matching parts in Malcolm-Helm.

## 3. Test updates

Test all changes from the previous version, minimally with the [Vagrant example](https://github.com/idaholab/Malcolm-Helm#VagrantDemo) but also preferrably on a real cluster.

## 4. Submit pull request to idaholab/Malcolm-Helm

Submit a pull request to [idaholab/Malcolm-Helm](https://github.com/idaholab/Malcolm-Helm/pulls) with the changes. This should be reviewed, approved, and merged by a maintainer of that project.

## 4. Update Malcolm-Helm repository with new release

Follow [these instructions](https://github.com/idaholab/Malcolm-Helm/blob/helm-repo/README.md) to package and publish the Malcolm-Helm release.
