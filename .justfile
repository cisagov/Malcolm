# .envrc and .justfile can be used by direnv (https://github.com/direnv/direnv) and
#   just (https://github.com/casey/just) for quicker turnaround for ./scripts/install.py
#   and ./scripts/auth_setup. This will all likely be made obsolete when cisagov/Malcolm#395
#   is complete. This hasn't been exhaustively tested, so it's recommended more for
#   development convenience than it is for production use.

call_recipe := just_executable() + " --justfile=" + justfile()

_base_config +CAPTURE_FLAG:
  #!/usr/bin/env bash

  SETTINGS_FILE="$(mktemp --suffix=.json)"
  JQ_FILE="$(mktemp --suffix=.jq)"
  ( [[ -n "${VERBOSE}" ]] && [[ "${VERBOSE}" != "false" ]] && [[ "${VERBOSE}" != "0" ]] ) && DEBUG=true || DEBUG=false

  python3 ./scripts/install.py --verbose "${DEBUG}" --configure --dry-run --non-interactive --defaults \
    --configure-file "${MALCOLM_COMPOSE_FILE}" \
    --environment-dir-input "${MALCOLM_CONFIG_DIR}" \
    --environment-dir-output "${MALCOLM_CONFIG_DIR}" \
    --export-malcolm-config-file "${SETTINGS_FILE}"

  if [[ "{{CAPTURE_FLAG}}" == "true" ]]; then
    CAPTURE_LIVE=true
    CAPTURE_IFACE="${LIVE_CAPTURE_IFACE}"
    CAPTURE_FILTER="${LIVE_CAPTURE_FILTER}"
    CAPTURE_IFACE_TWEAK=${LIVE_CAPTURE_IFACE_TWEAK}
    CAPTURE_STATS=${LIVE_CAPTURE_STATS}
    CAPTURE_NETSNIFF=${LIVE_CAPTURE_NETSNIFF}
    CAPTURE_TCPDUMP=${LIVE_CAPTURE_TCPDUMP}
    CAPTURE_ARKIME=${LIVE_CAPTURE_ARKIME}
    CAPTURE_ZEEK=${LIVE_CAPTURE_ZEEK}
    CAPTURE_SURICATA=${LIVE_CAPTURE_SURICATA}
    CAPTURE_ARKIME_NODE_HOST="${LIVE_CAPTURE_ARKIME_NODE_HOST}"
  else
    CAPTURE_LIVE=false
    CAPTURE_IFACE=lo
    CAPTURE_FILTER=
    CAPTURE_IFACE_TWEAK=false
    CAPTURE_STATS=false
    CAPTURE_NETSNIFF=false
    CAPTURE_TCPDUMP=false
    CAPTURE_ARKIME=false
    CAPTURE_ZEEK=false
    CAPTURE_SURICATA=false
    CAPTURE_ARKIME_NODE_HOST=
  fi

  ( [[ "${MALCOLM_CONTAINER_RUNTIME}" == "docker" ]] || [[ "${MALCOLM_CONTAINER_RUNTIME}" == "podman" ]] ) && ORCH_MODE=DOCKER_COMPOSE || ORCH_MODE=KUBERNETES
  ( [[ "${ZEEK_INTEL_ON_STARTUP}" == "true" ]] || [[ -n "${zeekIntelCronExpression}" ]] ) && ZEEK_INTEL=true || ZEEK_INTEL=false
  ( [[ -z "${OPENSEARCH_PATH}" ]] || [[ -z "${OPENSEARCH_SNAPSHOT_PATH}" ]] || [[ -z "${PCAP_PATH}" ]] || [[ -z "${SURICATA_PATH}" ]] || [[ -z "${ZEEK_PATH}" ]] ) && \
    DEFAULT_PATHS=true || DEFAULT_PATHS=false

  tee "${JQ_FILE}" >/dev/null <<EOF
    .configuration.runtimeBin = "${MALCOLM_CONTAINER_RUNTIME}"
    | .configuration.arkimeFreeSpaceG = "${DELETE_PCAP_THRESHOLD}"
    | .configuration.arkimeManagePCAP = ${DELETE_OLD_PCAP}
    | .configuration.autoArkime = ${AUTO_ARKIME}
    | .configuration.autoFreq = ${AUTO_FREQ}
    | .configuration.autoOui = ${AUTO_OUI}
    | .configuration.autoSuricata = ${AUTO_SURICATA}
    | .configuration.autoZeek = ${AUTO_ZEEK}
    | .configuration.capaScan = ${EXTRACTED_FILE_CAPA}
    | .configuration.captureLiveNetworkTraffic = ${CAPTURE_LIVE}
    | .configuration.clamAvScan = ${EXTRACTED_FILE_CLAMAV}
    | .configuration.containerNetworkName = "${NETWORK_NAME}"
    | .configuration.dashboardsDarkMode = ${DARK_MODE}
    | .configuration.dashboardsUrl = "${DASHBOARDS_URL}"
    | .configuration.dockerOrchestrationMode = "${ORCH_MODE}"
    | .configuration.exposeFilebeatTcp = ${FILEBEAT_TCP_EXPOSE}
    | .configuration.exposeLogstash = ${LOGSTASH_EXPOSE}
    | .configuration.exposeOpenSearch = ${OPENSEARCH_EXPOSE}
    | .configuration.exposeSFTP = ${SFTP_EXPOSE}
    | .configuration.extractedFileMaxPercentThreshold = ${EXTRACTED_FILE_TOTAL_DISK_USAGE_PERCENT_THRESHOLD}
    | .configuration.extractedFileMaxSizeThreshold = "${EXTRACTED_FILE_MAX_SIZE_THRESHOLD}"
    | .configuration.filebeatTcpDefaults = ${FILEBEAT_TCP_EXPOSE}
    | .configuration.fileCarveEnabled = true
    | .configuration.fileCarveHttpServeEncryptKey = "${EXTRACTED_FILE_SERVER_PASSWORD}"
    | .configuration.fileCarveHttpServer = ${EXTRACTED_FILE_SERVER}
    | .configuration.fileCarveHttpServerZip = ${EXTRACTED_FILE_SERVER_ZIP}
    | .configuration.fileCarveMode = "${FILE_EXTRACTION}"
    | .configuration.filePreserveMode = "${FILE_PRESERVATION}"
    | .configuration.fileScanRuleUpdate = ${FILE_SCAN_RULE_UPDATE}
    | .configuration.indexDir = "${OPENSEARCH_PATH}"
    | .configuration.indexManagementHistoryInWeeks = ${INDEX_MANAGEMENT_WEEKS_OF_HISTORY}
    | .configuration.indexManagementHotWarm = ${INDEX_MANAGEMENT_HOT_WARM_ENABLE}
    | .configuration.indexManagementOptimizationTimePeriod = "${INDEX_MANAGEMENT_OPTIMIZATION_TIME_PERIOD}"
    | .configuration.indexManagementOptimizeSessionSegments = ${INDEX_MANAGEMENT_SEGMENTS}
    | .configuration.indexManagementPolicy = ${INDEX_MANAGEMENT_ENABLE}
    | .configuration.indexManagementReplicas = ${INDEX_MANAGEMENT_REPLICAS}
    | .configuration.indexManagementSpiDataRetention = "${INDEX_MANAGEMENT_SPI_DATA_RETENTION}"
    | .configuration.indexPruneThreshold = "${DELETE_INDEX_THRESHOLD}"
    | .configuration.indexSnapshotDir = "${OPENSEARCH_SNAPSHOT_PATH}"
    | .configuration.logstashHost = "${LOGSTASH_HOST:-logstash:5044}"
    | .configuration.lsMemory = "${LOGSTASH_MEMORY}"
    | .configuration.lsWorkers = ${LOGSTASH_WORKERS}
    | .configuration.malcolmIcs = ${ZEEK_ICS}
    | .configuration.malcolmProfile = "${MALCOLM_PROFILE}"
    | .configuration.malcolmRestartPolicy = "${RESTART_MALCOLM}"
    | .configuration.netboxAutoPopulate = ${NETBOX_AUTOPOPULATE}
    | .configuration.netboxLogstashAutoSubnets = ${NETBOX_AUTO_PREFIXES}
    | .configuration.netboxLogstashEnrich = ${NETBOX_ENRICH}
    | .configuration.netboxMode = "${NETBOX}"
    | .configuration.netboxSiteName = "${NETBOX_SITE_NAME}"
    | .configuration.netboxUrl = "${NETBOX_URL}"
    | .configuration.nginxResolverIpv4 = ${NGINX_RESOLVER_IPV4}
    | .configuration.nginxResolverIpv6 = ${NGINX_RESOLVER_IPV6}
    | .configuration.nginxSSL = ${HTTPS}
    | .configuration.opensearchPrimaryMode = "${OPENSEARCH}"
    | .configuration.opensearchPrimarySslVerify = ${OPENSEARCH_SSL_VERIFY}
    | .configuration.opensearchPrimaryUrl = "${OPENSEARCH_URL}"
    | .configuration.opensearchSecondaryMode = "${OPENSEARCH_SECONDARY}"
    | .configuration.opensearchSecondarySslVerify = ${OPENSEARCH_SECONDARY_SSL_VERIFY}
    | .configuration.opensearchSecondaryUrl = "${OPENSEARCH_SECONDARY_URL}"
    | .configuration.osMemory = "${OPENSEARCH_MEMORY}"
    | .configuration.pcapDir = "${PCAP_PATH}"
    | .configuration.pcapNodeName = "${NODE_NAME}"
    | .configuration.reverseDns = ${REVERSE_DNS}
    | .configuration.suricataLogDir = "${SURICATA_PATH}"
    | .configuration.suricataRuleUpdate = ${SURICATA_RULE_UPDATE}
    | .configuration.syslogTcpPort = ${SYSLOG_PORT_TCP}
    | .configuration.syslogUdpPort = ${SYSLOG_PORT_UDP}
    | .configuration.traefikEntrypoint = "${TRAEFIK_ENTRYPOINT}"
    | .configuration.traefikHost = "${TRAEFIK_HOST}"
    | .configuration.traefikLabels = ${REVERSE_PROXIED}
    | .configuration.traefikOpenSearchHost = "${TRAEFIK_HOST_OPENSEARCH}"
    | .configuration.traefikResolver = "${TRAEFIK_RESOLVER}"
    | .configuration.useDefaultStorageLocations = ${DEFAULT_PATHS}
    | .configuration.vtotApiKey = "${VIRUSTOTAL_API_KEY}"
    | .configuration.yaraScan = ${EXTRACTED_FILE_YARA}
    | .configuration.zeekICSBestGuess = ${ZEEK_ICS_BEST_GUESS}
    | .configuration.zeekIntelCronExpression = "${ZEEK_INTEL_CRON_EXPRESSION}"
    | .configuration.zeekIntelFeedSince = "${ZEEK_INTEL_FEED_SINCE}"
    | .configuration.zeekIntelItemExpiration = "${ZEEK_INTEL_ITEM_EXPIRATION}"
    | .configuration.zeekIntelOnStartup = ${ZEEK_INTEL_ON_STARTUP}
    | .configuration.zeekPullIntelligenceFeeds = ${ZEEK_INTEL}
    | .configuration.zeekLogDir = "${ZEEK_PATH}"
    | .configuration.pcapIface = "${CAPTURE_IFACE}"
    | .configuration.pcapFilter = "${CAPTURE_FILTER}"
    | .configuration.tweakIface = ${CAPTURE_IFACE_TWEAK}
    | .configuration.captureStats = ${CAPTURE_STATS}
    | .configuration.pcapNetSniff = ${CAPTURE_NETSNIFF}
    | .configuration.pcapTcpDump = ${CAPTURE_TCPDUMP}
    | .configuration.liveArkime = ${CAPTURE_ARKIME}
    | .configuration.liveArkimeNodeHost = "${CAPTURE_ARKIME_NODE_HOST}"
    | .configuration.liveZeek = ${CAPTURE_ZEEK}
    | .configuration.liveSuricata = ${CAPTURE_SURICATA}
  EOF

  jq -f "${JQ_FILE}" "${SETTINGS_FILE}" | sponge "${SETTINGS_FILE}"

  python3 ./scripts/install.py --verbose "${DEBUG}" --configure --non-interactive --import-malcolm-config-file "${SETTINGS_FILE}" \
    --extra \
          "arkime-offline.env:ARKIME_AUTO_ANALYZE_PCAP_THREADS=$ARKIME_AUTO_ANALYZE_PCAP_THREADS" \
          "arkime.env:ARKIME_ALLOW_WISE_GUI_CONFIG=$ARKIME_ALLOW_WISE_GUI_CONFIG" \
          "arkime.env:ARKIME_EXPOSE_WISE_GUI=$ARKIME_EXPOSE_WISE_GUI" \
          "arkime.env:ARKIME_ROTATE_INDEX=$ARKIME_ROTATE_INDEX" \
          "arkime.env:ARKIME_SPI_DATA_MAX_INDICES=$ARKIME_SPI_DATA_MAX_INDICES" \
          "filebeat.env:FILEBEAT_PREPARE_PROCESS_COUNT=$FILEBEAT_PREPARE_PROCESS_COUNT" \
          "logstash.env:LOGSTASH_ZEEK_IGNORED_LOGS=$LOGSTASH_ZEEK_IGNORED_LOGS" \
          "netbox-common.env:NETBOX_AUTO_POPULATE_SUBNETS=$NETBOX_AUTO_POPULATE_SUBNETS" \
          "netbox-common.env:NETBOX_ENRICHMENT_DEBUG=$NETBOX_ENRICHMENT_DEBUG" \
          "netbox-common.env:NETBOX_ENRICHMENT_DEBUG_TIMINGS=$NETBOX_ENRICHMENT_DEBUG_TIMINGS" \
          "netbox.env:CSRF_TRUSTED_ORIGINS=$CSRF_TRUSTED_ORIGINS" \
          "nginx.env:NGINX_ERROR_LOG_LEVEL=$NGINX_ERROR_LOG_LEVEL" \
          "nginx.env:NGINX_KEYCLOAK_BASIC_AUTH=$NGINX_KEYCLOAK_BASIC_AUTH" \
          "nginx.env:NGINX_LOG_ACCESS_AND_ERRORS=$NGINX_LOG_ACCESS_AND_ERRORS" \
          "opensearch.env:MALCOLM_NETWORK_INDEX_ALIAS=$MALCOLM_NETWORK_INDEX_ALIAS" \
          "opensearch.env:MALCOLM_NETWORK_INDEX_SUFFIX=$MALCOLM_NETWORK_INDEX_SUFFIX" \
          "opensearch.env:MALCOLM_OTHER_INDEX_ALIAS=$MALCOLM_OTHER_INDEX_ALIAS" \
          "opensearch.env:MALCOLM_OTHER_INDEX_SUFFIX=$MALCOLM_OTHER_INDEX_SUFFIX" \
          "suricata-offline.env:SURICATA_AUTO_ANALYZE_PCAP_PROCESSES=$SURICATA_AUTO_ANALYZE_PCAP_PROCESSES" \
          "suricata-offline.env:SURICATA_AUTO_ANALYZE_PCAP_THREADS=$SURICATA_AUTO_ANALYZE_PCAP_THREADS" \
          "upload-common.env:MALCOLM_API_DEBUG=$MALCOLM_API_DEBUG" \
          "upload-common.env:PCAP_PIPELINE_IGNORE_PREEXISTING=$PCAP_PIPELINE_IGNORE_PREEXISTING" \
          "zeek-offline.env:ZEEK_AUTO_ANALYZE_PCAP_THREADS=$ZEEK_AUTO_ANALYZE_PCAP_THREADS" \
          "zeek.env:CAPA_MAX_REQUESTS=$CAPA_MAX_REQUESTS" \
          "zeek.env:CLAMD_MAX_REQUESTS=$CLAMD_MAX_REQUESTS" \
          "zeek.env:EXTRACTED_FILE_HTTP_SERVER_MAGIC=$EXTRACTED_FILE_HTTP_SERVER_MAGIC" \
          "zeek.env:EXTRACTED_FILE_IGNORE_EXISTING=$EXTRACTED_FILE_IGNORE_EXISTING" \
          "zeek.env:YARA_MAX_REQUESTS=$YARA_MAX_REQUESTS" \
          "zeek.env:ZEEK_DISABLE_ICS_GE_SRTP=$ZEEK_DISABLE_ICS_GE_SRTP" \
          "zeek.env:ZEEK_DISABLE_ICS_GENISYS=$ZEEK_DISABLE_ICS_GENISYS" \
          "zeek.env:ZEEK_SYNCHROPHASOR_DETAILED=$ZEEK_SYNCHROPHASOR_DETAILED"

  rm -f "${SETTINGS_FILE}" "${JQ_FILE}"

config:
  {{call_recipe}} _base_config "true"

config-nocap:
  {{call_recipe}} _base_config "false"

auth-setup:
  #!/usr/bin/env bash
  ( [[ -n "${VERBOSE}" ]] && [[ "${VERBOSE}" != "false" ]] && [[ "${VERBOSE}" != "0" ]] ) && DEBUG='-vvvv' || DEBUG=''
  ./scripts/auth_setup $DEBUG --auth-noninteractive true \
    --file "$MALCOLM_COMPOSE_FILE" \
    --environment-dir "$MALCOLM_CONFIG_DIR" \
    --runtime "$MALCOLM_CONTAINER_RUNTIME" \
    --namespace "$MALCOLM_K8S_NAMESPACE" \
    --profile "$MALCOLM_PROFILE" \
    --auth-method "$AUTH_METHOD" \
    --auth-generate-opensearch-internal-creds "$AUTH_GENERATE_OPENSEARCH_CREDS" \
    --auth-generate-netbox-passwords "$AUTH_GENERATE_NETBOX_PASSWORDS" \
    --auth-generate-redis-password "$AUTH_GENERATE_REDIS_PASSWORD" \
    --auth-generate-postgres-password "$AUTH_GENERATE_POSTGRES_PASSWORD" \
    --auth-generate-keycloak-db-password "$AUTH_GENERATE_KEYCLOAK_DB_PASSWORD" \
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
    --auth-keycloak-bootstrap-password "$AUTH_KEYCLOAK_BOOTSTRAP_PASSWORD" \
    --auth-require-group "$AUTH_REQUIRE_GROUP" \
    --auth-require-role "$AUTH_REQUIRE_ROLE" \
    --auth-netbox-token "$NETBOX_TOKEN" \
    --auth-role-based-access-control "$ROLE_BASED_ACCESS"

logs *SERVICES:
  #!/usr/bin/env bash
  ( [[ -n "${VERBOSE}" ]] && [[ "${VERBOSE}" != "false" ]] && [[ "${VERBOSE}" != "0" ]] ) && DEBUG='-vvvv' || DEBUG=''
  ./scripts/logs $DEBUG \
    --file "$MALCOLM_COMPOSE_FILE" \
    --environment-dir "$MALCOLM_CONFIG_DIR" \
    --runtime "$MALCOLM_CONTAINER_RUNTIME" \
    --profile "$MALCOLM_PROFILE" \
    --namespace "$MALCOLM_K8S_NAMESPACE" \
    -s {{SERVICES}}

status *SERVICES:
  #!/usr/bin/env bash
  ( [[ -n "${VERBOSE}" ]] && [[ "${VERBOSE}" != "false" ]] && [[ "${VERBOSE}" != "0" ]] ) && DEBUG='-vvvv' || DEBUG=''
  ./scripts/status $DEBUG \
    --file "$MALCOLM_COMPOSE_FILE" \
    --environment-dir "$MALCOLM_CONFIG_DIR" \
    --runtime "$MALCOLM_CONTAINER_RUNTIME" \
    --profile "$MALCOLM_PROFILE" \
    --namespace "$MALCOLM_K8S_NAMESPACE" \
    -s {{SERVICES}}

wipe:
  #!/usr/bin/env bash
  ( [[ -n "${VERBOSE}" ]] && [[ "${VERBOSE}" != "false" ]] && [[ "${VERBOSE}" != "0" ]] ) && DEBUG='-vvvv' || DEBUG=''
  ./scripts/wipe $DEBUG \
    --file "$MALCOLM_COMPOSE_FILE" \
    --environment-dir "$MALCOLM_CONFIG_DIR" \
    --runtime "$MALCOLM_CONTAINER_RUNTIME" \
    --profile "$MALCOLM_PROFILE" \
    --namespace "$MALCOLM_K8S_NAMESPACE" \
    --delete-namespace "$MALCOLM_K8S_DELETE_NAMESPACE"

nuke:
  {{call_recipe}} wipe
  rm -rf ./postgres/*

stop:
  #!/usr/bin/env bash
  ( [[ -n "${VERBOSE}" ]] && [[ "${VERBOSE}" != "false" ]] && [[ "${VERBOSE}" != "0" ]] ) && DEBUG='-vvvv' || DEBUG=''
  ./scripts/stop $DEBUG \
    --file "$MALCOLM_COMPOSE_FILE" \
    --environment-dir "$MALCOLM_CONFIG_DIR" \
    --runtime "$MALCOLM_CONTAINER_RUNTIME" \
    --profile "$MALCOLM_PROFILE" \
    --namespace "$MALCOLM_K8S_NAMESPACE"

start:
  #!/usr/bin/env bash
  ( [[ -n "${VERBOSE}" ]] && [[ "${VERBOSE}" != "false" ]] && [[ "${VERBOSE}" != "0" ]] ) && DEBUG='-vvvv' || DEBUG=''
  ./scripts/start $DEBUG \
    --quiet \
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

restart *SERVICES:
  #!/usr/bin/env bash
  ( [[ -n "${VERBOSE}" ]] && [[ "${VERBOSE}" != "false" ]] && [[ "${VERBOSE}" != "0" ]] ) && DEBUG='-vvvv' || DEBUG=''
  ./scripts/restart $DEBUG \
    --quiet \
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
    --skip-persistent-volume-checks "$MALCOLM_K8S_SKIP_PERSISTENT_VOLUME_CHECKS" \
    -s {{SERVICES}}

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
