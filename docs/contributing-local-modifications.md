# <a name="LocalMods"></a>Local modifications

There are several ways to customize Malcolm's runtime behavior via local changes to configuration files. Many commonly-tweaked settings are discussed in the project [README](README.md) (see [Environment Variable Files](malcolm-config.md#MalcolmConfigEnvVars) and [Customizing event severity scoring](severity.md#SeverityConfig) for some examples).

## <a name="Bind"></a>Volume bind mounts

Some configuration changes can be put in place by modifying local copies of configuration files and then using a [bind mount](https://docs.docker.com/storage/bind-mounts/) to overlay the modified file onto the running Malcolm container. This is already done for many files and directories used to persist Malcolm configuration and data. For example, the default list of bind mounted files and directories for each Malcolm service is as follows:

`$ yq eval '.services = (.services | with_entries(.value = {"volumes": .value.volumes}))' docker-compose.yml`
```yaml
services:
  opensearch:
    volumes:
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./.opensearch.primary.curlrc
        target: /var/local/curlrc/.opensearch.primary.curlrc
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./.opensearch.secondary.curlrc
        target: /var/local/curlrc/.opensearch.secondary.curlrc
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./opensearch
        target: /usr/share/opensearch/data
      - type: bind
        bind:
          create_host_path: false
        source: ./opensearch-backup
        target: /opt/opensearch/backup
      - type: bind
        bind:
          create_host_path: false
        source: ./opensearch/opensearch.keystore
        target: /usr/share/opensearch/config/persist/opensearch.keystore
  dashboards-helper:
    volumes:
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./.opensearch.primary.curlrc
        target: /var/local/curlrc/.opensearch.primary.curlrc
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./.opensearch.secondary.curlrc
        target: /var/local/curlrc/.opensearch.secondary.curlrc
        read_only: true
  dashboards:
    volumes:
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./.opensearch.primary.curlrc
        target: /var/local/curlrc/.opensearch.primary.curlrc
        read_only: true
  logstash:
    volumes:
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./.opensearch.primary.curlrc
        target: /var/local/curlrc/.opensearch.primary.curlrc
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./.opensearch.secondary.curlrc
        target: /var/local/curlrc/.opensearch.secondary.curlrc
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./logstash/maps/malcolm_severity.yaml
        target: /etc/malcolm_severity.yaml
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./logstash/certs/ca.crt
        target: /certs/ca.crt
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./logstash/certs/server.crt
        target: /certs/server.crt
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./logstash/certs/server.key
        target: /certs/server.key
        read_only: true
  filebeat:
    volumes:
      - nginx-log-path:/nginx:ro
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./.opensearch.primary.curlrc
        target: /var/local/curlrc/.opensearch.primary.curlrc
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./zeek-logs
        target: /zeek
      - type: bind
        bind:
          create_host_path: false
        source: ./suricata-logs
        target: /suricata
      - type: bind
        bind:
          create_host_path: false
        source: ./filebeat/certs/ca.crt
        target: /certs/ca.crt
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./filebeat/certs/client.crt
        target: /certs/client.crt
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./filebeat/certs/client.key
        target: /certs/client.key
        read_only: true
  arkime:
    volumes:
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./.opensearch.primary.curlrc
        target: /var/local/curlrc/.opensearch.primary.curlrc
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./arkime/lua
        target: /opt/arkime/lua
        read_only: true        
      - type: bind
        bind:
          create_host_path: false
        source: ./arkime/rules
        target: /opt/arkime/rules
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./pcap
        target: /data/pcap
  arkime-live:
    volumes:
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./.opensearch.primary.curlrc
        target: /var/local/curlrc/.opensearch.primary.curlrc
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./arkime/lua
        target: /opt/arkime/lua
        read_only: true        
      - type: bind
        bind:
          create_host_path: false
        source: ./arkime/rules
        target: /opt/arkime/rules
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./pcap
        target: /data/pcap
  zeek:
    volumes:
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./pcap
        target: /pcap
      - type: bind
        bind:
          create_host_path: false
        source: ./zeek-logs/upload
        target: /zeek/upload
      - type: bind
        bind:
          create_host_path: false
        source: ./zeek-logs/extract_files
        target: /zeek/extract_files
      - type: bind
        bind:
          create_host_path: false
        source: ./zeek/intel
        target: /opt/zeek/share/zeek/site/intel
      - type: bind
        bind:
          create_host_path: false
        source: ./zeek/custom
        target: /opt/zeek/share/zeek/site/custom
        read_only: true
  zeek-live:
    volumes:
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./zeek-logs/live
        target: /zeek/live
      - type: bind
        bind:
          create_host_path: false
        source: ./zeek-logs/extract_files
        target: /zeek/extract_files
      - type: bind
        bind:
          create_host_path: false
        source: ./zeek/intel
        target: /opt/zeek/share/zeek/site/intel
      - type: bind
        bind:
          create_host_path: false
        source: ./zeek/custom
        target: /opt/zeek/share/zeek/site/custom
        read_only: true
  suricata:
    volumes:
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./suricata-logs
        target: /var/log/suricata
      - type: bind
        bind:
          create_host_path: false
        source: ./pcap
        target: /data/pcap
      - type: bind
        bind:
          create_host_path: false
        source: ./suricata/rules
        target: /opt/suricata/rules
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./suricata/include-configs
        target: /opt/suricata/include-configs
        read_only: true
  suricata-live:
    volumes:
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./suricata-logs
        target: /var/log/suricata
      - type: bind
        bind:
          create_host_path: false
        source: ./suricata/rules
        target: /opt/suricata/rules
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./suricata/include-configs
        target: /opt/suricata/include-configs
        read_only: true
  file-monitor:
    volumes:
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./zeek-logs/extract_files
        target: /zeek/extract_files
      - type: bind
        bind:
          create_host_path: false
        source: ./zeek-logs/current
        target: /zeek/logs
      - type: bind
        bind:
          create_host_path: false
        source: ./yara/rules
        target: /yara-rules/custom
        read_only: true
  pcap-capture:
    volumes:
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./pcap/upload
        target: /pcap
  pcap-monitor:
    volumes:
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./.opensearch.primary.curlrc
        target: /var/local/curlrc/.opensearch.primary.curlrc
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./zeek-logs
        target: /zeek
      - type: bind
        bind:
          create_host_path: false
        source: ./pcap
        target: /pcap
  upload:
    volumes:
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./pcap/upload
        target: /var/www/upload/server/php/chroot/files
  htadmin:
    volumes:
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./htadmin/metadata
        target: /var/www/htadmin/config/metadata
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/htpasswd
        target: /var/www/htadmin/auth/htpasswd
  freq:
    volumes:
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
  netbox:
    volumes:
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./netbox/config
        target: /etc/netbox/config
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./netbox/media
        target: /opt/netbox/netbox/media
      - type: bind
        bind:
          create_host_path: false
        source: ./netbox/preload
        target: /opt/netbox-preload/configmap
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./netbox/custom-plugins
        target: /opt/netbox-custom-plugins
        read_only: true
  postgres:
    volumes:
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./postgres
        target: /var/lib/postgresql/data
  redis:
    volumes:
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./redis
        target: /data
  redis-cache:
    volumes:
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
  api:
    volumes:
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./.opensearch.primary.curlrc
        target: /var/local/curlrc/.opensearch.primary.curlrc
        read_only: true
  nginx-proxy:
    volumes:
      - nginx-log-path:/var/log/nginx
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/ca-trust
        target: /var/local/ca-trust
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/nginx_ldap.conf
        target: /etc/nginx/nginx_ldap.conf
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/htpasswd
        target: /etc/nginx/auth/htpasswd
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/certs
        target: /etc/nginx/certs
        read_only: true
      - type: bind
        bind:
          create_host_path: false
        source: ./nginx/certs/dhparam.pem
        target: /etc/nginx/dhparam/dhparam.pem
        read_only: true
```

So, for example, if a user wanted to make a change to the `nginx-proxy` container's `nginx.conf` file, they could add the following line to the `volumes:` section of the `nginx-proxy` service in the `docker-compose.yml` file:

```
- ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
```

The change would take effect after stopping and starting Malcolm.

See the documentation on [bind mounts](https://docs.docker.com/storage/bind-mounts/) for more information on this technique.

## <a name="ContribBuild"></a>Building Malcolm's images

Another method for modifying local copies of Malcolm's services' containers is to [build custom](development.md#Build) containers with the modifications baked-in.

For example, imagine a user wanted to create a Malcolm container that includes a new dashboard for OpenSearch Dashboards and a new enrichment filter `.conf` file for Logstash. After placing these files under `./dashboards/dashboards` and `./logstash/pipelines/enrichment`, respectively, in the Malcolm working copy, run `./build.sh dashboards-helper logstash` to build just those containers. After the build completes, run `docker images` to see the fresh images for `ghcr.io/idaholab/malcolm/dashboards-helper` and `ghcr.io/idaholab/malcolm/logstash-oss`. Users may need to review the contents of the [Dockerfiles]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/Dockerfiles) to determine the correct service and filesystem location within that service's image depending on the nature of the task.

Alternately, forks of Malcolm on GitHub contain [workflow files]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/.github/workflows/) that contain instructions for GitHub to build the images and [sensor](live-analysis.md#Hedgehog) and [Malcolm](malcolm-iso.md#ISO) installer ISOs. The resulting images are named according to the pattern `ghcr.io/owner/malcolm/image:branch` (e.g., if the GitHub user `romeogdetlevjr` has forked Malcolm, the `arkime` container built for the `main` branch would be named `ghcr.io/romeogdetlevjr/malcolm/arkime:main`). To run a local instance of Malcolm using these images instead of the official ones, users would need to edit their `docker-compose.yml` file(s) and replace the `image:` tags according to this new pattern, or use the bash helper script `./shared/bin/github_image_helper.sh` to pull and re-tag the images.