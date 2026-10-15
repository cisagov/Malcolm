# Opt-in TLS decryption for Zeek

Malcolm can load Zeek's experimental TLS decryption policy when the analyst
already possesses the corresponding NSS-style session secrets, such as a
browser-generated `SSLKEYLOGFILE`. This can supplement Zeek analysis of a
corresponding PCAP.

**Zeek's decryption support is limited.** The documented policy supports
TLS 1.2 connections using `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`. TLS 1.3
and other suites are not decrypted. See [Zeek's TLS decryption guide](https://docs.zeek.org/en/master/frameworks/tls-decryption.html).

## Enable only for authorized captures

The option is **disabled by default**. The keylog is highly sensitive: it
may decrypt captured user traffic. Only use it for traffic you are
authorized to inspect, and apply the same access restrictions, secure
storage, rotation, and deletion policies as for raw packet captures.

Copy the keylog to a private directory ignored by Git and protect it from
other local users. The example below assumes the host user can read the
source keylog and that the Zeek container runs with a matching UID:

```bash
mkdir -p zeek/tls-secrets
install -m 0600 /secure/path/sslkeylog.txt zeek/tls-secrets/sslkeylog.txt
```

The default sample `config/zeek.env.example` includes the setting:

```text
ZEEK_TLS_KEYLOG_FILE=
```

To opt in, set the following in your **generated** `config/zeek.env`:

```text
ZEEK_TLS_KEYLOG_FILE=/run/secrets/zeek-sslkeys.txt
```

Only the container-side **path** goes in the environment, never the
secret contents. Keep `config/zeek.env` excluded from source control.

When starting Malcolm with Docker Compose, include the optional
[`docker-compose-zeek-tls.yml.example`](../docker-compose-zeek-tls.yml.example)
override, which mounts the host keylog read-only into both Zeek
services without auto-creating a missing key file:

```bash
docker compose -f docker-compose.yml   -f docker-compose-zeek-tls.yml.example up -d zeek
```

For deployments already managed by Malcolm, supply the same Compose override
on the relevant Zeek service restarts and subsequent upgrades. Confirm the
keylog is readable **inside** the container with the Zeek runtime UID; a
nonexistent or unreadable file prevents decryption, even if Zeek otherwise
starts. Do not change its permissions to world-readable as a workaround.

The extra `zeek-live` mount keeps the runtime file available in that
container, but this configuration is primarily for **offline PCAP
processing**. Supplying a static keylog at startup does not solve live
key-delivery timing or automatic keylog reload. Live decryption requires
a separately designed, authorized secret transport such as Zeek Broker
events, which this change does not configure.

## Verification and limits

1. Process a PCAP for which you possess a matching session keylog and that
   uses Zeek's supported TLS version and cipher suite.
2. Check the Zeek service logs for keylog-reader warnings and confirm that
   supported decrypted protocol events appear. The presence of the keylog
   alone does not guarantee successful decryption.
3. Compare with the same PCAP processed with `ZEEK_TLS_KEYLOG_FILE` empty,
   to establish which additional results are due to decryption.
4. When finished, remove the configuration option and key mount, secure or
   delete the keylog under your retention policy, and restart Zeek.

This is **not** TLS interception, a general TLS decryption engine, or a way
to decrypt arbitrary encrypted traffic without the matching session keys.

For Kubernetes, do not place secrets in ConfigMaps or repository manifests:
use an appropriately restricted Kubernetes Secret, a read-only mount, and
set the environment path in the relevant Zeek pod. The example Compose
override is not a Kubernetes configuration.
