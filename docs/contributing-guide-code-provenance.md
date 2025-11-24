# Malcolm Code Provenance and Software Supply Chain

The purpose of this document is to outline general practices for ensuring that open source software included in Malcolm comes from trustworthy sources.

* [Code and Release Artifacts](#CodeAndReleaseArtifacts)
* [Upstream Components](#UpstreamComponents)
    - [Base Images for Containers and Installed Environments](#BaseImagesForContainersAndInstalledEnvironments)
        + [Container Images](#ContainerImages)
        + [ISO-Installed Environments](#ISOInstalledEnvironments)
    - [Software Package Repositories](#SoftwarePackageRepositories)
        + [Linux Distribution Package Repositories](#LinuxDistroRepos)
        + [Python Package Index (PyPI)](#PyPI)
        + [Binary Release Artifacts on GitHub](#GitHubReleaseArtifacts)
    - [Code Built From Source](#CodeBuiltFromSource)
    - [Standards of Trust for Providers of Upstream Code](#StandardsOfTrustForProvidersOfUpstreamCode)
    - [Incorporating Updates to Third-Party Code](#SoftwareUpdates)
* [Code Submissions (Pull Requests)](#CodeSubmissionsPullRequests)
* [Security Vulnerability Scanning](#SecurityVulnerabilityScanning)

## <a name="CodeAndReleaseArtifacts"></a> Code and Release Artifacts

Malcolm's source code and release artifacts are made up of the following:

* container images for Docker/Podman/Kubernetes
    - These contain the majority of the "brains" of Malcolm, and are used as the basis of all deployment models, whether ISO-installer based, Docker/Podman based, or cloud (Kubernetes) based.
* Desktop OS environments for [Malcolm](malcolm-hedgehog-e2e-iso-install.md#MalcolmDesktop) and Hedgehog Linux
    - These are ISO-installed environments that are primarily used for bare-metal or virtual machine installations. They include the container images mentioned above.
* The actual "[Malcolm source code](({{ site.github.repository_url }}))", which includes:
    - [scripts]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/scripts/) for installing and configuring Malcolm
    - "recipes" and contents used for building images
        + [container]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/Dockerfiles/) images
        + [Malcolm]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/malcolm-iso) ISO installer
        + [Hedgehog Linux]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/hedgehog-raspi) Raspberry Pi image
    - [documentation]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/docs)
    - [configuration files]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/config) storing user preferences

## <a name="UpstreamComponents"></a> Upstream Components

Malcolm is a tool suite that incorporates many open source components (some of which are listed [here](contributing-github-runners.md#GitHubRunners)).

![components](images/malcolm_components.png)

### <a name="BaseImagesForContainersAndInstalledEnvironments"></a> Base Images for Containers and Installed Environments

The main sources of Malcolm’s core tools and libraries are the 'base images' on which Malcolm is built. These base images are defined in:

* [Dockerfiles]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/Dockerfiles/) used to build container images
* scripts that use the [Debian Live](https://www.debian.org/devel/debian-live/) framework to build the x86_64 ISO and ARM64 [Raspberry Pi installer](hedgehog-raspi-build.md#HedgehogRaspiBuild) images

#### <a name="ContainerImages"></a> Container Images

Malcolm uses the official container images curated by Docker Hub or maintained by the developers of the various projects they represent.

The base images used to build Malcolm's images are:

* [alpine](https://hub.docker.com/_/alpine) (Docker Official Image)
* [debian](https://hub.docker.com/_/debian) (Docker Official Image)
* [docker.elastic.co](https://www.docker.elastic.co/)/[beats](https://www.docker.elastic.co/r/beats)/filebeat-oss (Elasticsearch Official Image)
* [docker.elastic.co](https://www.docker.elastic.co/)/[logstash](https://www.docker.elastic.co/r/logstash)/logstash-oss (Elasticsearch Official Image)
* [netboxcommunity/netbox](https://hub.docker.com/r/netboxcommunity/netbox) (Official Community-Maintained Docker-Sponsored OSS Image)
* [opensearchproject/opensearch](https://hub.docker.com/r/opensearchproject/opensearch) (Docker-Verified Official Publisher Image)
* [opensearchproject/opensearch-dashboards](https://hub.docker.com/r/opensearchproject/opensearch-dashboards) (Docker-Verified Official Publisher Image)
* [postgres:alpine](https://hub.docker.com/_/postgres) (Docker Official Image)
* [python:3-slim](https://hub.docker.com/_/python) (Docker Official Image)
* [redis:alpine](https://hub.docker.com/_/redis) (Docker Official Image)

As described on the [Docker Hub documentation](https://docs.docker.com/docker-hub/image-library/trusted-content/):

> Docker Hub's trusted content provides a curated selection of high-quality, secure images designed to give developers confidence in the reliability and security of the resources they use. These images are stable, regularly updated, and adhere to industry best practices, making them a strong foundation for building and deploying applications. Docker Hub's trusted content includes, Docker Official Images, Verified Publisher images, and Docker-Sponsored Open Source Software images.

Using these official images as the base of Malcolm's Docker images relies on a trusted upstream provider (Docker, Elasticsearch, NetBox, etc.) to provide a secure foundation upon which Malcolm is built. The images listed above are used by tens of thousands of organizations, projects, and developers worldwide.

#### <a name="ISOInstalledEnvironments"></a> ISO-Installed Environments

For the ISO installers for [Malcolm](malcolm-iso.md#ISOInstallation) and [Hedgehog Linux](hedgehog.md), and the [Hedgehog Linux Raspberry Pi Image](hedgehog-raspi-build.md#HedgehogRaspiBuild), Malcolm uses the [Debian Live](https://www.debian.org/devel/debian-live/) framework to build installation images based on Debian stable, which, as described in the [Debian FAQ](https://www.debian.org/doc/manuals/debian-faq/choosing.en.html#s3.1.5), "is rock solid. It does not break and has full security support."

Beyond building on this solid foundation, and as these environments are full-fledged operating systems, the [harbian-audit](https://github.com/hardenedlinux/harbian-audit) benchmarks are used as a basis for additional hardening that targets the following guidelines for establishing a secure configuration posture:

* [CIS Debian Linux Benchmarks](https://www.cisecurity.org/cis-benchmarks/cis-benchmarks-faq/)
* [DISA STIG (Security Technical Implementation Guides) for RHEL 7](https://www.stigviewer.com/stig/red_hat_enterprise_linux_7/) v2r5 Ubuntu v1r2 [adapted](https://github.com/hardenedlinux/STIG-OS-mirror/blob/master/redhat-STIG-DOCs/U_Red_Hat_Enterprise_Linux_7_V2R5_STIG.zip) for a Debian operating system
* Additional recommendations from [cisecurity.org](https://www.cisecurity.org/)

More details on this hardening can be found [here for Malcolm](hardening.md).

### <a name="SoftwarePackageRepositories"></a> Software Package Repositories

#### <a name="LinuxDistroRepos"></a> Linux Distribution Package Repositories

Whenever possible, Malcolm's container images and ISO installers install any additional software packages from the software repositories officially maintained by the underlying OS of the image. For example:

* [Alpine](https://wiki.alpinelinux.org/wiki/Repositories)'s official repositories supported by the Alpine Linux core team
* [Debian](https://wiki.debian.org/DebianRepository#Mirrors)'s official repositories curated by the Debian team
* [Amazon Linux 2023](https://docs.aws.amazon.com/linux/al2023/ug/what-is-amazon-linux.html)'s official repositories maintained by the Amazon Web Services (AWS) team, drawing from the Fedora and CentOS repositories upstream
* [Ubuntu](https://help.ubuntu.com/community/Repositories/Ubuntu)'s official repositories maintained by Canonical

Packages installed from these official Linux repositories are generally considered safe, as they undergo rigorous testing and security checks by the distribution maintainers, making them a reliable source for software installation compared to downloading from unknown third-party sources. As software bugs and vulnerabilities are discovered the affected packages are patched upstream and included in subsequent Malcolm releases.

#### <a name="PyPI"></a> Python Package Index (PyPI)

The other type of software repository used in Malcolm's image is [PyPI](https://pypi.org/), the Python Package Index. When official packages for Python libraries are not provided in the previously-mentioned repositories provided by Debian, Alpine, etc., they are published to PyPI by the creator of those libraries. PyPI is *not* inherently safe to the level that the official Linux distributions' packages repositories aim to be. For this reason, extra steps must be taken to ensure the additional Python libraries included in Malcolm are trustworthy. See [**Standards of Trust for Providers of Upstream Code**](#StandardsOfTrustForProvidersOfUpstreamCode) for more details.

#### <a name="GitHubReleaseArtifacts"></a> Binary Release Artifacts on GitHub

To reduce build time, some small standalone tools included in Malcolm are downloaded as binaries released in their respective projects' official [GitHub releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases). The same [**Standards of Trust for Providers of Upstream Code**](#StandardsOfTrustForProvidersOfUpstreamCode) apply for these artifacts as for binaries [compiled from source](#CodeBuiltFromSource) during the Malcolm build.

### <a name="CodeBuiltFromSource"></a> Code Built From Source

Some packages in Malcolm are not available as precompiled binaries and must be built from source. In order to ensure the code compiled is of legitimate origin, it is always downloaded directly from its originator (i.e., the author or organization that has released the source code). Usually this means downloading it from GitHub or from an organization's official website over HTTPS. See [**Standards of Trust for Providers of Upstream Code**](#StandardsOfTrustForProvidersOfUpstreamCode) for more details about determining trustworthiness of third-party code.

### <a name="StandardsOfTrustForProvidersOfUpstreamCode"></a> Standards of Trust for Providers of Upstream Code

Determining the trustworthiness of third-party source code is essential for maintaining the security and integrity of Malcolm's software supply chain.

#### Community Size and Activity

One key factor used to evaluate a project's suitability for inclusion in Malcolm is the size and activity of the project's community. Open-source projects with active issue tracking, regular releases, and responsive maintainers are generally more reliable than those with little engagement. A strong community presence — evident through GitHub stars, pull requests, discussions in Slack channels, or forums — indicates that many developers are invested in the project's health, making it less likely that malicious code goes unnoticed. Frequent updates and well-documented changes also suggest that the maintainers are proactive in addressing security vulnerabilities and improving the software.

#### Popularity and Adoption

Another critical aspect is project popularity and adoption. The more widely used a piece of software is, the more scrutiny it receives from developers, security researchers, and organizations relying on it. Large-scale adoption reduces the likelihood of undetected vulnerabilities or hidden backdoors since many independent contributors and companies have a vested interest in keeping the project secure. However, popularity alone isn't enough — it's important to check if reputable organizations use the project and whether they contribute back to its development. Reviewing security audits, dependency transparency, and any history of security incidents can further help in assessing whether a project can be trusted.

#### Technical Security

Beyond community activity and popularity, other technical factors should be considered. Reviewing a candidate project's dependency tree can reveal if it relies on well-maintained and trusted libraries or if it introduces risky, obscure dependencies. Checking for reproducible builds and signed releases ensures that the distributed code matches the source and hasn’t been tampered with. Additionally, verifying that the project follows security best practices — such as enforcing code reviews, providing cryptographic signatures for releases, and maintaining a clear disclosure process for vulnerabilities — can provide confidence in its reliability.

#### Relationships of Trust

Finally, the Malcolm team has developed professional working relationships and friendships with some of the teams behind many Malcolm components. Malcolm developers are active members of many of the communities surrounding those projects, and know those working on the code. This familiarity bolsters the Malcolm team's confidence and trust in those projects.

By combining these factors, the Malcolm team can make informed decisions about integrating third-party code into Malcolm.

### <a name="SoftwareUpdates"></a> Incorporating Updates to Third-Party Code

For software that is installed via [Linux distributions' package repositories](#LinuxDistroRepos), the Malcolm developers mostly take a "hands-off" approach: these packages are included in new Malcolm builds automatically as they are updated upstream. Infrequently, when a new major version of a base image is released (for example, the next stable release of Debian every few years or a new image for the next release of Alpine Linux), the Malcolm team will review changelogs and release notes and manually bump the Malcolm dependency up to the latest version. This is advisable as most new releases of distributions include improvements to features, performance, and security.

[Python libraries](#PyPI) used in Malcolm are all ["pinned"](https://pip.pypa.io/en/stable/topics/repeatable-installs/#pinning-the-package-versions) to a specific version which is manually updated when [a security vulnerability](#SecurityVulnerabilityScanning) is reported, new functionality is added, or for other reasons at a Malcolm developer's discretion. Package pinning helps prevent unexpected bugs or compatibility issues when new versions are released.

For other components of Malcolm, whether they are major components ([Arkime](https://github.com/arkime/arkime/releases), [OpenSearch](version), [Zeek](https://github.com/zeek/zeek/releases), etc.) or smaller tools ([Tini](https://github.com/krallin/tini/releases), [yq](https://github.com/mikefarah/yq), [supercronic](https://github.com/aptible/supercronic)), the Malcolm team stays abreast of new releases primarily through [GitHub notifications](https://docs.github.com/en/account-and-profile/managing-subscriptions-and-notifications-on-github/setting-up-notifications/about-notifications) triggered when a new release of that component is published. A Malcolm developer reviews the release notes accompanying new releases before deciding if and when to update the version included in Malcolm. The thoroughness of this review — from a cursory perusal of the release notes to a more in-depth review of the changed code itself — will vary depending on the team's familiarity and experience with the project in question.

New releases are always tested locally and with [`malcolm-test`](contributing-malcolm-test.md#MalcolmTest), the Malcolm system test suite, before they are merged into the main Malcolm source code repository for inclusion in a Malcolm release.

## <a name="CodeSubmissionsPullRequests"></a> Code Submissions (Pull Requests)

Malcolm, like other open source projects, occasionally receives code contributions from external parties. In source control parlance, these contributions are submitted as [pull requests](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/about-pull-requests).

Regardless of their origin or complexity, each pull request is carefully and thoroughly [reviewed](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/reviewing-changes-in-pull-requests/about-pull-request-reviews) by Malcolm developers, who:

* review every change, line-by-line, proposed in the pull request
* review the history (involvement in other communities on GitHub, contributions to other projects, their own repositories, etc.) of the party submitting the pull request to make, as much as possible, a determination that they're legitimate
* pay careful attention to identify new dependencies added by the pull request and apply the same [standards of trust for providers of upstream code](#StandardsOfTrustForProvidersOfUpstreamCode) should there be any
* never accept any pull request with binary artifacts, which cannot be reviewed in the same way source code can
* test the changes locally before accepting the pull request
* resolve any concerns before accepting the pull request
* get sign-off from a senior Malcolm developer before accepting the pull request

Pull requests that follow [best practices](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/getting-started/helping-others-review-your-changes), are [well-written](https://github.blog/developer-skills/github/how-to-write-the-perfect-pull-request/), and bring value to the Malcolm project are likely to be accepted once the criteria above have been met. If potential contributors are considering working on a significant pull request, it is always a good idea to reach out on the [Malcolm discussions board](https://github.com/cisagov/Malcolm/discussions) to touch base with the Malcolm team first.

## <a name="SecurityVulnerabilityScanning"></a> Security Vulnerability Scanning

When Malcolm's official container images are [built on GitHub](contributing-github-runners.md#GitHubRunners), they are automatically scanned with [Trivy](https://trivy.dev/latest/). Trivy can "find vulnerabilities (CVE) & misconfigurations (IaC) across code repositories, binary artifacts, container images, Kubernetes clusters, and more." When Trivy detects a vulnerability in a software package included in Malcolm, a report is automatically generated and uploaded to the Malcolm repository's [code scanning](https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning) dashboard on GitHub. These are periodically reviewed and addressed (by updating to a newer version of the affected dependency if it has become available, by applying other safeguards in the code to avoid the affected functionality, replacing the dependency with another alternative, or other solutions as determined on a case-by-case basis) by the Malcolm development team.

In addition to this proactive vulnerability scanning, GitHub also sends [Dependabot alerts](https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts) when it detects a vulnerable dependency in the Malcolm code base. These are also addressed as they arise.