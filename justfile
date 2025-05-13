call_recipe := just_executable() + " --justfile=" + justfile()

_base_config +CAPTURE_FLAGS:
  #!/usr/bin/env bash
  ./scripts/configure --defaults \
  --verbose "$VERBOSE" \
    --configure-file "$MALCOLM_COMPOSE_FILE" \
    --environment-dir "$MALCOLM_CONFIG_DIR" \
    --runtime "$MALCOLM_CONTAINER_RUNTIME" \
    --malcolm-profile "$MALCOLM_PROFILE" \
    --node-name "$NODE_NAME" \
    --dark-mode "$DARK_MODE" \
    --https "$HTTPS" \
    --nginx-resolver-ipv4 true \
    --nginx-resolver-ipv6 false \
    --restart-malcolm "$RESTART_MALCOLM" \
    --reverse-proxied "$REVERSE_PROXIED" \
    --traefik-host "$TRAEFIK_HOST" \
    --traefik-host-opensearch "$TRAEFIK_HOST_OPENSEARCH" \
    --traefik-entrypoint "$TRAEFIK_ENTRYPOINT" \
    --traefik-resolver "$TRAEFIK_RESOLVER" \
    --network-name "$NETWORK_NAME" \
    --opensearch "$OPENSEARCH" \
    --opensearch-memory "$OPENSEARCH_MEMORY" \
    --opensearch-url "$OPENSEARCH_URL" \
    --opensearch-ssl-verify "$OPENSEARCH_SSL_VERIFY" \
    --opensearch-secondary "$OPENSEARCH_SECONDARY" \
    --opensearch-secondary-url "$OPENSEARCH_SECONDARY_URL" \
    --opensearch-secondary-ssl-verify "$OPENSEARCH_SECONDARY_SSL_VERIFY" \
    --dashboards-url "$DASHBOARDS_URL" \
    --logstash-host "$LOGSTASH_HOST" \
    --logstash-memory "$LOGSTASH_MEMORY" \
    --logstash-workers "$LOGSTASH_WORKERS" \
    --logstash-expose "$LOGSTASH_EXPOSE" \
    --opensearch-expose "$OPENSEARCH_EXPOSE" \
    --filebeat-tcp-expose "$FILEBEAT_TCP_EXPOSE" \
    --sftp-expose "$SFTP_EXPOSE" \
    --syslog-tcp-port "$SYSLOG_PORT_TCP" \
    --syslog-udp-port "$SYSLOG_PORT_UDP" \
    --pcap-path "$PCAP_PATH" \
    --zeek-path "$ZEEK_PATH" \
    --suricata-path "$SURICATA_PATH" \
    --opensearch-path "$OPENSEARCH_PATH" \
    --opensearch-snapshot-path "$OPENSEARCH_SNAPSHOT_PATH" \
    --delete-old-pcap "$DELETE_OLD_PCAP" \
    --delete-pcap-threshold "$DELETE_PCAP_THRESHOLD" \
    --extracted-file-max-size-threshold "$EXTRACTED_FILE_MAX_SIZE_THRESHOLD" \
    --extracted-file-total-disk-usage-percent-threshold "$EXTRACTED_FILE_TOTAL_DISK_USAGE_PERCENT_THRESHOLD" \
    --delete-index-threshold "$DELETE_INDEX_THRESHOLD" \
    --index-management-enable "$INDEX_MANAGEMENT_ENABLE" \
    --index-management-hot-warm-enable "$INDEX_MANAGEMENT_HOT_WARM_ENABLE" \
    --index-management-optimization-time-period "$INDEX_MANAGEMENT_OPTIMIZATION_TIME_PERIOD" \
    --index-management-spi-data-retention "$INDEX_MANAGEMENT_SPI_DATA_RETENTION" \
    --index-management-replicas "$INDEX_MANAGEMENT_REPLICAS" \
    --index-management-weeks-of-history "$INDEX_MANAGEMENT_WEEKS_OF_HISTORY" \
    --index-management-segments "$INDEX_MANAGEMENT_SEGMENTS" \
    --auto-arkime "$AUTO_ARKIME" \
    --auto-suricata "$AUTO_SURICATA" \
    --suricata-rule-update "$SURICATA_RULE_UPDATE" \
    --auto-zeek "$AUTO_ZEEK" \
    --zeek-ics "$ZEEK_ICS" \
    --zeek-ics-best-guess "$ZEEK_ICS_BEST_GUESS" \
    --reverse-dns "$REVERSE_DNS" \
    --auto-oui "$AUTO_OUI" \
    --auto-freq "$AUTO_FREQ" \
    --zeek-intel-on-startup "$ZEEK_INTEL_ON_STARTUP" \
    --zeek-intel-feed-since "$ZEEK_INTEL_FEED_SINCE" \
    --zeek-intel-cron-expression "$ZEEK_INTEL_CRON_EXPRESSION" \
    --zeek-intel-item-expiration="$ZEEK_INTEL_TIME_EXPIRATION" \
    --file-extraction "$FILE_EXTRACTION" \
    --file-preservation "$FILE_PRESERVATION" \
    --extracted-file-server "$EXTRACTED_FILE_SERVER" \
    --extracted-file-server-zip "$EXTRACTED_FILE_SERVER_ZIP" \
    --extracted-file-server-password "$EXTRACTED_FILE_SERVER_PASSWORD" \
    --extracted-file-clamav "$EXTRACTED_FILE_CLAMAV" \
    --extracted-file-yara "$EXTRACTED_FILE_YARA" \
    --extracted-file-capa "$EXTRACTED_FILE_CAPA" \
    --virustotal-api-key "$VIRUSTOTAL_API_KEY" \
    --file-scan-rule-update "$FILE_SCAN_RULE_UPDATE" \
    --netbox "$NETBOX" \
    --netbox-url "$NETBOX_URL" \
    --netbox-enrich "$NETBOX_ENRICH" \
    --netbox-autopopulate "$NETBOX_AUTOPOPULATE" \
    --netbox-auto-prefixes "$NETBOX_AUTO_PREFIXES" \
    --netbox-site-name "$NETBOX_SITE_NAME" \
    --extra \
      "nginx.env:NGINX_LOG_ACCESS_AND_ERRORS=$NGINX_LOG_ACCESS_AND_ERRORS" \
      "arkime.env:ARKIME_ROTATE_INDEX=$ARKIME_ROTATE_INDEX" \
      "arkime.env:ARKIME_SPI_DATA_MAX_INDICES=$ARKIME_SPI_DATA_MAX_INDICES" \
      "arkime-offline.env:ARKIME_AUTO_ANALYZE_PCAP_THREADS=$ARKIME_AUTO_ANALYZE_PCAP_THREADS" \
      "filebeat.env:FILEBEAT_PREPARE_PROCESS_COUNT=$FILEBEAT_PREPARE_PROCESS_COUNT" \
      "logstash.env:LOGSTASH_ZEEK_IGNORED_LOGS=$LOGSTASH_ZEEK_IGNORED_LOGS" \
      "netbox-common.env:NETBOX_ENRICHMENT_DEBUG_TIMINGS=$NETBOX_ENRICHMENT_DEBUG_TIMINGS" \
      "netbox-common.env:NETBOX_ENRICHMENT_DEBUG=$NETBOX_ENRICHMENT_DEBUG" \
      "netbox.env:CSRF_TRUSTED_ORIGINS=$CSRF_TRUSTED_ORIGINS" \
      "nginx.env:NGINX_ERROR_LOG_LEVEL=$NGINX_ERROR_LOG_LEVEL" \
      "nginx.env:NGINX_KEYCLOAK_BASIC_AUTH=$NGINX_KEYCLOAK_BASIC_AUTH" \
      "opensearch.env:MALCOLM_NETWORK_INDEX_ALIAS=$MALCOLM_NETWORK_INDEX_ALIAS" \
      "opensearch.env:MALCOLM_NETWORK_INDEX_SUFFIX=$MALCOLM_NETWORK_INDEX_SUFFIX" \
      "opensearch.env:MALCOLM_OTHER_INDEX_ALIAS=$MALCOLM_OTHER_INDEX_ALIAS" \
      "opensearch.env:MALCOLM_OTHER_INDEX_SUFFIX=$MALCOLM_OTHER_INDEX_SUFFIX" \
      "suricata-offline.env:SURICATA_AUTO_ANALYZE_PCAP_THREADS=$SURICATA_AUTO_ANALYZE_PCAP_THREADS" \
      "upload-common.env:PCAP_PIPELINE_IGNORE_PREEXISTING=$PCAP_PIPELINE_IGNORE_PREEXISTING" \
      "upload-common.env:MALCOLM_API_DEBUG=$MALCOLM_API_DEBUG" \
      "zeek.env:CLAMD_MAX_REQUESTS=$CLAMD_MAX_REQUESTS" \
      "zeek.env:YARA_MAX_REQUESTS=$YARA_MAX_REQUESTS" \
      "zeek.env:CAPA_MAX_REQUESTS=$CAPA_MAX_REQUESTS" \
      "zeek.env:EXTRACTED_FILE_HTTP_SERVER_MAGIC=$EXTRACTED_FILE_HTTP_SERVER_MAGIC" \
      "zeek.env:EXTRACTED_FILE_IGNORE_EXISTING=$EXTRACTED_FILE_IGNORE_EXISTING" \
      "zeek.env:ZEEK_SYNCHROPHASOR_DETAILED=$ZEEK_SYNCHROPHASOR_DETAILED" \
      "zeek.env:ZEEK_DISABLE_ICS_GENISYS=$ZEEK_DISABLE_ICS_GENISYS" \
      "zeek.env:ZEEK_DISABLE_ICS_GE_SRTP=$ZEEK_DISABLE_ICS_GE_SRTP" \
      "zeek-offline.env:ZEEK_AUTO_ANALYZE_PCAP_THREADS=$ZEEK_AUTO_ANALYZE_PCAP_THREADS" \
      {{CAPTURE_FLAGS}}

config:
  {{call_recipe}} _base_config \
    --live-capture-iface "$LIVE_CAPTURE_IFACE" \
    --live-capture-filter "$LIVE_CAPTURE_FILTER" \
    --live-capture-iface-tweak "$LIVE_CAPTURE_IFACE_TWEAK" \
    --live-capture-stats "$LIVE_CAPTURE_STATS" \
    --live-capture-netsniff "$LIVE_CAPTURE_NETSNIFF" \
    --live-capture-tcpdump "$LIVE_CAPTURE_TCPDUMP" \
    --live-capture-zeek "$LIVE_CAPTURE_ZEEK" \
    --live-capture-suricata "$LIVE_CAPTURE_SURICATA"

config-nocap:
  {{call_recipe}} _base_config \
    --live-capture-iface-tweak false \
    --live-capture-stats false \
    --live-capture-netsniff false \
    --live-capture-tcpdump false \
    --live-capture-zeek false \
    --live-capture-suricata false

auth-setup:
  #!/usr/bin/env bash
  ./scripts/auth_setup --auth-noninteractive true \
    --verbose "$VERBOSE" \
    --file "$MALCOLM_COMPOSE_FILE" \
    --environment-dir "$MALCOLM_CONFIG_DIR" \
    --runtime "$MALCOLM_CONTAINER_RUNTIME" \
    --namespace "$MALCOLM_K8S_NAMESPACE" \
    --profile "$MALCOLM_PROFILE" \
    --auth-method "$AUTH_METHOD" \
    --auth-admin-username "$AUTH_ADMIN_USERNAME" \
    --auth-admin-password-openssl "$(echo -n "$AUTH_ADMIN_PASSWORD" | openssl passwd -1 --stdin)" \
    --auth-admin-password-htpasswd "$(echo -n "$AUTH_ADMIN_PASSWORD" | htpasswd -i -n -B username | cut -d: -f2 | head -n 1)" \
    --auth-arkime-password "$AUTH_ARKIME_PASSWORD" \
    --auth-generate-webcerts "$AUTH_GENERATE_WEBCERTS" \
    --auth-generate-fwcerts "$AUTH_GENERATE_FWCERTS" \
    --auth-keycloak-realm "$AUTH_KEYCLOAK_REALM" \
    --auth-keycloak-redirect-uri "$AUTH_KEYCLOAK_REDIRECT_URI" \
    --auth-keycloak-url "$AUTH_KEYCLOAK_URL" \
    --auth-keycloak-client-id "$AUTH_KEYCLOAK_CLIENT_ID" \
    --auth-keycloak-client-secret "$AUTH_KEYCLOAK_CLIENT_SECRET" \
    --auth-require-group "$AUTH_REQUIRE_GROUP" \
    --auth-require-role "$AUTH_REQUIRE_ROLE" \
    --auth-netbox-token "$NETBOX_TOKEN"

logs *SERVICES:
  #!/usr/bin/env bash
  ./scripts/logs \
    --verbose "$VERBOSE" \
    --file "$MALCOLM_COMPOSE_FILE" \
    --environment-dir "$MALCOLM_CONFIG_DIR" \
    --runtime "$MALCOLM_CONTAINER_RUNTIME" \
    --profile "$MALCOLM_PROFILE" \
    --namespace "$MALCOLM_K8S_NAMESPACE" \
    -s {{SERVICES}}

status *SERVICES:
  #!/usr/bin/env bash
  ./scripts/status \
    --verbose "$VERBOSE" \
    --file "$MALCOLM_COMPOSE_FILE" \
    --environment-dir "$MALCOLM_CONFIG_DIR" \
    --runtime "$MALCOLM_CONTAINER_RUNTIME" \
    --profile "$MALCOLM_PROFILE" \
    --namespace "$MALCOLM_K8S_NAMESPACE" \
    -s {{SERVICES}}

wipe:
  #!/usr/bin/env bash
  ./scripts/wipe \
    --verbose "$VERBOSE" \
    --file "$MALCOLM_COMPOSE_FILE" \
    --environment-dir "$MALCOLM_CONFIG_DIR" \
    --runtime "$MALCOLM_CONTAINER_RUNTIME" \
    --profile "$MALCOLM_PROFILE" \
    --namespace "$MALCOLM_K8S_NAMESPACE" \
    --delete-namespace "$MALCOLM_K8S_DELETE_NAMESPACE"

stop:
  #!/usr/bin/env bash
  ./scripts/stop \
    --verbose "$VERBOSE" \
    --file "$MALCOLM_COMPOSE_FILE" \
    --environment-dir "$MALCOLM_CONFIG_DIR" \
    --runtime "$MALCOLM_CONTAINER_RUNTIME" \
    --profile "$MALCOLM_PROFILE" \
    --namespace "$MALCOLM_K8S_NAMESPACE"

start:
  #!/usr/bin/env bash
  ./scripts/start \
    --quiet \
    --verbose "$VERBOSE" \
    --file "$MALCOLM_COMPOSE_FILE" \
    --environment-dir "$MALCOLM_CONFIG_DIR" \
    --runtime "$MALCOLM_CONTAINER_RUNTIME" \
    --profile "$MALCOLM_PROFILE" \
    --namespace "$MALCOLM_K8S_NAMESPACE" \
    --image-source "$MALCOLM_K8S_IMAGE_SOURCE" \
    --image-tag "$MALCOLM_K8S_IMAGE_TAG" \
    --inject-resources "$MALCOLM_K8S_INJECT_RESOURCES" \
    --no-capabilities "$MALCOLM_K8S_NO_CAPABILITIES" \
    --no-capture-pods "$MALCOLM_K8S_NO_CAPTURE_PODS" \
    --skip-persistent-volume-checks "$MALCOLM_K8S_SKIP_PERSISTENT_VOLUME_CHECKS"

restart:
  #!/usr/bin/env bash
  ./scripts/restart \
    --quiet \
    --verbose "$VERBOSE" \
    --file "$MALCOLM_COMPOSE_FILE" \
    --environment-dir "$MALCOLM_CONFIG_DIR" \
    --runtime "$MALCOLM_CONTAINER_RUNTIME" \
    --profile "$MALCOLM_PROFILE" \
    --namespace "$MALCOLM_K8S_NAMESPACE" \
    --image-source "$MALCOLM_K8S_IMAGE_SOURCE" \
    --image-tag "$MALCOLM_K8S_IMAGE_TAG" \
    --inject-resources "$MALCOLM_K8S_INJECT_RESOURCES" \
    --no-capabilities "$MALCOLM_K8S_NO_CAPABILITIES" \
    --no-capture-pods "$MALCOLM_K8S_NO_CAPTURE_PODS" \
    --skip-persistent-volume-checks "$MALCOLM_K8S_SKIP_PERSISTENT_VOLUME_CHECKS"

build *SERVICES:
  #!/usr/bin/env bash
  ./scripts/build.sh {{SERVICES}}

[positional-arguments]
upload *args='':
  #!/usr/bin/env bash

  PCAPS=()
  TAGS=()
  NETBOX_SITE_ID=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --tag)
        TAGS+=("$2")
        shift 2
        ;;
      --site)
        NETBOX_SITE_ID="$2"
        shift 2
        ;;
      --) # explicit end of options
        shift
        break
        ;;
      -*)
        echo "Unknown option: $1"
        exit 1
        ;;
      *)  # Start of PCAP list
        break
        ;;
      esac
  done

  # remaining arguments are PCAP files
  PCAPS+=("$@")

  if [[ -n "$MALCOLM_URL" ]]; then
    TAG_STRING=$(IFS=','; echo "${TAGS[*]}")
    for PCAP in "${PCAPS[@]}"; do
      if [[ -f "${PCAP}" ]]; then
        curl -sSL -XPOST -u "${AUTH_ADMIN_USERNAME}:${AUTH_ADMIN_PASSWORD}" \
          -F "filepond=@${PCAP}" \
          -F "tags=${TAG_STRING}" \
          -F "site-dropdown=${NETBOX_SITE_ID}" \
          "${MALCOLM_URL}/upload/server/php/submit.php"
      fi
    done
  fi
