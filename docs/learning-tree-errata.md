# <a name="LearningTreeErrata"></a>Malcolm Learning Tree: configuration notes and errata

The [Malcolm Learning Tree](https://github.com/cisagov/Malcolm/wiki/Learning)
links to recorded tutorials alongside written guidance. Malcolm's setup options
continue to change after a video is published. This page provides a **versioned
configuration reference** for users following an older tutorial.

**Reference version:** Malcolm 26.09.0 (repository `main`, October 2026).
The information below is verified against the configuration examples in that
version. It is **not** a claim that every listed setting appears in a particular
video. Always check the video's publication date and prefer the linked current
documentation when a control or prompt looks different.

## Where to find current configuration options

| Learning Tree topic | Current reference | What to check if a video differs |
| --- | --- | --- |
| Installing or configuring Malcolm | [Configuration guide](malcolm-config.md#ConfigAndTuning), [quick start](quickstart.md#QuickStart) | Use `./scripts/configure` to configure an installation. This is currently a link to `scripts/install.py`; the text and grouping of prompts may differ from a recording. |
| Malcolm versus Hedgehog sensor runs | [Live-analysis profiles](live-analysis.md#Profiles) | `MALCOLM_PROFILE=malcolm` runs the full suite; `MALCOLM_PROFILE=hedgehog` selects the sensor-focused profile. The option is in `config/process.env`. |
| Authentication and local account management | [Authentication guide](authsetup.md#AuthSetup) | `NGINX_AUTH_MODE` currently accepts `basic`, `ldap`, `keycloak`, `keycloak_remote`, or `no_authentication` (the default is `basic`). For credentials and certificates follow `./scripts/auth_setup`, not a copied value from a video. |
| OpenSearch connection | [Remote datastore guide](opensearch-instances.md#OpenSearchInstance) | `OPENSEARCH_PRIMARY=opensearch-local` and `OPENSEARCH_URL=https://opensearch:9200` are the shipped local defaults. A remote deployment needs its own URL, credentials, and TLS choices. |
| Live network capture | [Live-analysis guide](live-analysis.md#LocalPCAP) | `ARKIME_LIVE_CAPTURE=false` is the shipped default in `arkime-live.env`; interface selection uses `PCAP_IFACE` in `pcap-capture.env`. Do not assume an interface name from an example applies on your host. |
| Receiving logs from network sensors | [External log forwarding](live-analysis.md#ExternalForward) | `LOGSTASH_HOST=logstash:5044` is the **internal** default in `beats-common.env`. External sensors must use the reachable server and port, and the corresponding TLS settings. |
| Dashboards and default landing view | [Dashboard documentation](dashboards.md#Dashboards) | `OPENSEARCH_DEFAULT_DASHBOARD` is configured in `dashboards-helper.env`. A tutorial's screenshot may show an older dashboard or default selection. |
| Runtime data and starting or stopping Malcolm | [Running Malcolm](running.md#Running) | The `./scripts/start`, `./scripts/stop`, and `./scripts/wipe` actions are documented here. **Wipe destroys data**; do not execute it solely because a training video demonstrates it. |

The names shown in the table are the underlying environment variables. The
configuration interface may group them under different labels. User-selected
values, especially credentials, network interfaces and remote endpoints,
should be preserved when following an example.

## Check the running version first

1. Review your checkout's version and container image tags (for example, the
   `image:` entries in `docker-compose.yml`), and identify whether you're
   running a Malcolm installation or a Hedgehog sensor profile.
2. Check the live `config/*.env` files **on that installation**, not only
   the `config/*.env.example` templates. The examples document shipped
   defaults; the active values may have been changed by the installer or
   administrator.
3. Use the linked written documentation for the matching release, then return
   to the video for the concept or workflow. Avoid copying passwords, secrets,
   hostnames and network-interface values from recorded demonstrations.

## Report a new video/documentation mismatch

Use [issue #631](https://github.com/cisagov/Malcolm/issues/631) or the
[training discussion board](https://github.com/cisagov/Malcolm/discussions)
to report a remaining discrepancy. Include the Learning Tree module title,
a **video timestamp**, the date or version used in the video (when known),
your installed Malcolm version, the obsolete control or instruction, and the
current behavior. Do not include secrets or private hostnames.

**Maintainer note:** The Learning Tree is hosted in the GitHub Wiki (a separate
Git repository). Once this documentation change is accepted, link this page
from the wiki's *Learning* page so viewers can find the errata alongside its
videos. Changes to the documentation repository do not edit the wiki directly.
