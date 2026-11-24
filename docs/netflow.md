# NetFlow v9 ingestion

Malcolm can accept NetFlow v9 UDP exports through the Logstash NetFlow
decoder, map common fields to Elastic Common Schema (ECS), and use its
existing Beats log pipeline to store the events in OpenSearch. The decoded
vendor fields remain under `netflow`.

The input is **disabled by default**. NetFlow over UDP has no built-in
authentication or encryption. Limit the listener to trusted exporter
addresses with host and network firewalls, and never publish it to the
public Internet.

## Enable decoding

After running Malcolm's normal configuration process, edit
`config/logstash.env`:

```text
LOGSTASH_NETFLOW_LISTEN=true
LOGSTASH_NETFLOW_PORT=2055
```

Then restart the Logstash service as part of Malcolm's usual restart
procedure. Disabled listeners are omitted from the generated Logstash
pipeline configuration.

Malcolm's Filebeat image is the OSS build, which **does not include a
NetFlow input**. This feature therefore uses the separately installed
Apache-licensed Logstash NetFlow codec.

### Docker Compose

The example
[`docker-compose-netflow.yml.example`](../docker-compose-netflow.yml.example)
publishes UDP 2055 on **localhost only**. Start the normal Malcolm
deployment, then restart Logstash with the Compose override:

```bash
docker compose -f docker-compose.yml   -f docker-compose-netflow.yml.example up -d logstash
```

For a router on another host, change `127.0.0.1` in the override to
the host's trusted private IP address, then allow only the router's IP
at the firewall. The internal container port and `LOGSTASH_NETFLOW_PORT`
must match. A normal `./scripts/start` using the default Compose file
alone does not publish the external UDP port; reapply the override
after upgrades if required.

### Kubernetes

Set `LOGSTASH_NETFLOW_LISTEN=true` in Logstash's environment ConfigMap
and copy [`99-netflow.yml.example`](../kubernetes/99-netflow.yml.example)
to `kubernetes/99-netflow.yml`. The example creates only an internal
`ClusterIP` service, not a public load balancer. A trusted router
outside the cluster requires a separately secured, private UDP path.

## Network flow fields

| NetFlow v9 field | ECS field |
| --- | --- |
| `ipv4_src_addr` | `source.ip` |
| `ipv4_dst_addr` | `destination.ip` |
| `l4_src_port` | `source.port` |
| `l4_dst_port` | `destination.port` |
| `in_bytes` | `network.bytes` |
| `in_pkts` | `network.packets` |
| `protocol` | `network.transport` |

The incoming exporter IP is recorded in `observer.ip`. Records have
`event.module: netflow` and `event.dataset: netflow.v9`. Unknown
NetFlow vendor fields remain available under `netflow` without being
silently coerced into incorrect ECS fields.

The NetFlow v9 protocol requires exporters to periodically send **template
records** before sending the corresponding flow data. Missing templates,
incorrect exporter settings, network ACLs or UDP packet loss can all prevent
records from appearing. Check Logstash's service logs if no data arrives.

The initial listener handles v9 only. NetFlow does not contain packet
payloads, so it supplements rather than replaces Malcolm's packet capture
and Zeek/Arkime analysis.
