# <a name="ReleasePrep"></a>Preparing a Malcolm Release

This document outlines the steps a Malcolm developer goes through to publish a release of Malcolm. This guide assumes the developer has been doing their work downstream in a fork of the main [Malcolm repository upstream]({{ site.github.repository_url }}), forked at `romeogdetlevjr/Malcolm` by the fictitious Malcolm developer Romeo G Detlev Jr. concocted for this example.

## 1. Review the project milestone and the branch from which the release will be staged

Malcolm tracks issues (whether they be bugs, new features, enhancements, etc.) for release milestones using a [GitHub project](https://github.com/orgs/cisagov/projects/98). Before building release candidate images, Romeo reviews the items for the upcoming release in the corresponding project milestone and ensures that all items assigned to it have their status set to **Done**, each item having been completed and tested locally by the developer to which the issue was assigned.

Romeo also ensures that all work towards this release has been pulled into the branch on his fork from which the release will be cut. If [pull requests]({{ site.github.repository_url }}/pulls) have been submitted upstream which resolve the issues assigned to this release, those pull requests should be merged into the branch at `romeogdetlevjr/Malcolm`, whether they were submitted initially against that fork or pulled in manually by Romeo as part of this release process. Pull requests are not accepted directly into the `main` branch of the official [upstream fork]({{ site.github.repository_url }}). In other words, the branch of Malcolm in Romeo's development fork should contain **everything** that is going to comprise this release of Malcolm.

There are several places in the Malcolm source code where the release version itself (e.g., `{{ site.malcolm.version }}`) needs to be present. Most of these places are in the documentation, consisting of markdown files, but others include [docker-compose.yml]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/docker-compose.yml), [docker-compose-dev.yml]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/docker-compose-dev.yml), and the [Kubernetes manifests]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/kubernetes). Most likely Romeo's first commit into his branch as he worked on this release was to bump those version strings ([like this](https://github.com/romeogdetlevjr/Malcolm/commit/cc7d0d8855b5cc4f04cd38ae22d1421c627444cc)), but he should verify now that he did so.

## 2. Build Malcolm container images using GitHub runners

Images and artifacts for release should not be built on Romeo's own development workstation. Instead, carefully reviews the documentation for [using GitHub runners to build Malcolm images](contributing-github-runners.md#GitHubRunners) (including setting up his [GitHub repository actions secrets and variables](contributing-github-runners.md#secrets-and-variables)) and starts builds of the GitHub container images [with a workflow or repository dispatch API trigger](contributing-github-runners.md#triggers). He monitors the [progress of the workflow actions]({{ site.github.repository_url }}/actions) and ensures that they complete successfully, including jobs for both `docker (linux/amd64)` and `docker (linux/arm64)` where applicable.

## 3. Build Malcolm ISO images using GitHub runners

The [workflow for building the Malcolm installer ISO]({{ site.github.repository_url }}/actions/workflows/malcolm-iso-build-docker-wrap-push-ghcr.yml) and [Hedgehog Linux installer ISO]({{ site.github.repository_url }}/actions/workflows/malcolm-hedgehog-profile-iso-build-docker-wrap-push-ghcr.yml) need to be run **after** all of the container image "build-and-push" actions have completed successfully, as those images are pulled and archived inside of the ISO itself. Once Romeo is sure that all of the actions for building the container images from the previous step have completed successfully, he initiates a run of the [`malcolm-iso-build-docker-wrap-push-ghcr`]({{ site.github.repository_url }}/actions/workflows/malcolm-iso-build-docker-wrap-push-ghcr.yml) and [`malcolm-hedgehog-profile-iso-build-docker-wrap-push-ghcr`]({{ site.github.repository_url }}/actions/workflows/malcolm-hedgehog-profile-iso-build-docker-wrap-push-ghcr.yml) actions.

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

The Hedgehog Linux [Raspberry Pi Image](hedgehog-raspi-build.md#HedgehogRaspiBuild) is also built on GitHub. As that image targets an ARM64 architecture, it can be pulled and extracted on an ARM64-based machine using the [convenience helper script](contributing-github-runners.md#convenience-scripts-for-development) mentioned earlier in step 4.

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