# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities in Malcolm or Hedgehog Linux through [GitHub's private vulnerability reporting](https://github.com/cisagov/Malcolm/security/advisories/new) on CISA's fork of the Malcolm repository, or through [VINCE-NT](https://vulnerabilities.cisa.gov/cvdp/report/).

Please do not open a public issue, discussion, or pull request for a suspected vulnerability.

## Before you report

Please read [**Malcolm's security model**](docs/contributing-security-model.md) first. It describes Malcolm's trust boundaries, which ports a deployment exposes and under which settings, how authentication and role-based access control are enforced, what makes a report actionable, and which classes of finding are out of scope. A number of past reports have described Malcolm's intended design rather than a defect. That document explains those cases and the reasoning behind them. If the code contradicts what it says, that is worth reporting.

## What to expect

1. **Triage.** We review the report against the current source and tell you what we found, including where our reproduction differs from yours.
2. **A decision.** Either we confirm it and prepare a fix, or we explain why we are closing it.
3. **A fix in a release.** Confirmed issues are usually fixed in the next Malcolm release. We publish the advisory when that release ships, with credit to you unless you ask otherwise.
4. **A CVE, through CISA.** Malcolm is in [CISA](https://www.cve.org/PartnerInformation/ListofPartners/partner/CISA)'s CNA scope, which means GitHub cannot assign CVEs for Malcolm advisories. Confirmed vulnerabilities are duplicated into CISA's [VINCE-NT](https://vulnerabilities.cisa.gov/cvdp/report/) system for CVE assignment, and the GitHub advisory is updated with the CVE once assigned. Reporters are credited in both places. Assignment timing is CISA's rather than ours.

## Supported versions

Security fixes go into the next release of Malcolm, which uses [calendar versioning](https://calver.org/) for its [release]({{ site.github.repository_url }}/releases/latest) versioning. Older releases do not receive backported fixes, so [upgrading Malcolm](malcolm-upgrade.md#UpgradePlan) to the latest release is the supported mechanism for receiving security fixes.

## Third-party components

Malcolm integrates many [open source components](docs/components.md). Vulnerabilities in those belong to their own projects, though we want to hear about it when one is exploitable because of how Malcolm configures or deploys it.

Malcolm's container images are scanned with Trivy when built, and the repository receives Dependabot alerts. See [**Security Vulnerability Scanning**](docs/contributing-guide-code-provenance.md#SecurityVulnerabilityScanning).