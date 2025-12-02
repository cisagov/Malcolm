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
    --configure-file "${MALCOLM_COMPOSE_FILE:-docker-compose.yml}" \
    --environment-dir-input "${MALCOLM_CONFIG_DIR:-config}" \
    --environment-dir-output "${MALCOLM_CONFIG_DIR:-config}" \
    --export-malcolm-config-file "${SETTINGS_FILE}"

  if [[ "{{CAPTURE_FLAG}}" == "true" ]]; then
    CAPTURE_LIVE=true
    if [[ "${LIVE_CAPTURE_IFACE:-primary}" == "primary" ]]; then
        command -v ip >/dev/null 2>&1 && CAPTURE_IFACE=$(ip route get 255.255.255.255 2>/dev/null | awk '/dev/ {print $4}') || CAPTURE_IFACE='lo'
    else
        CAPTURE_IFACE="${LIVE_CAPTURE_IFACE}"
    fi
    CAPTURE_FILTER="${LIVE_CAPTURE_FILTER}"
    CAPTURE_IFACE_TWEAK=${LIVE_CAPTURE_IFACE_TWEAK:-true}
    CAPTURE_STATS=${LIVE_CAPTURE_STATS:-true}
    CAPTURE_NETSNIFF=${LIVE_CAPTURE_NETSNIFF:-true}
    CAPTURE_TCPDUMP=${LIVE_CAPTURE_TCPDUMP:-false}
    CAPTURE_ARKIME=${LIVE_CAPTURE_ARKIME:-false}
    CAPTURE_ZEEK=${LIVE_CAPTURE_ZEEK:-true}
    CAPTURE_SURICATA=${LIVE_CAPTURE_SURICATA:-true}
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

  ( [[ "${MALCOLM_CONTAINER_RUNTIME:-docker}" == "docker" ]] || [[ "${MALCOLM_CONTAINER_RUNTIME}" == "podman" ]] ) && ORCH_MODE=DOCKER_COMPOSE || ORCH_MODE=KUBERNETES
  ( [[ "${ZEEK_INTEL_ON_STARTUP:-false}" == "true" ]] || [[ -n "${ZEEK_INTEL_CRON_EXPRESSION}" ]] ) && ZEEK_INTEL=true || ZEEK_INTEL=false
  ( [[ -z "${OPENSEARCH_PATH}" ]] || [[ -z "${OPENSEARCH_SNAPSHOT_PATH}" ]] || [[ -z "${PCAP_PATH}" ]] || [[ -z "${SURICATA_PATH}" ]] || [[ -z "${ZEEK_PATH}" ]] ) && \
    DEFAULT_PATHS=true || DEFAULT_PATHS=false

  tee "${JQ_FILE}" >/dev/null <<EOF
    .configuration.runtimeBin = "${MALCOLM_CONTAINER_RUNTIME:-docker}"
    | .configuration.processUserId = ${PUID:-$(id -u)}
    | .configuration.processGroupId = ${PGID:-$(id -g)}
    | .configuration.arkimeFreeSpaceG = "${DELETE_PCAP_THRESHOLD:-1%}"
    | .configuration.arkimeManagePCAP = ${DELETE_OLD_PCAP:-false}
    | .configuration.arkimeExposeWise = ${ARKIME_EXPOSE_WISE_GUI:-false}
    | .configuration.arkimeAllowWiseConfig = ${ARKIME_ALLOW_WISE_GUI_CONFIG:-false}
    | .configuration.arkimeWiseUrl = "${ARKIME_WISE_SERVICE_URL:-http://arkime:8081}"
    | .configuration.autoArkime = ${AUTO_ARKIME:-true}
    | .configuration.autoFreq = ${AUTO_FREQ:-true}
    | .configuration.autoOui = ${AUTO_OUI:-true}
    | .configuration.autoSuricata = ${AUTO_SURICATA:-true}
    | .configuration.autoZeek = ${AUTO_ZEEK:-true}
    | .configuration.capaScan = ${EXTRACTED_FILE_CAPA:-true}
    | .configuration.captureLiveNetworkTraffic = ${CAPTURE_LIVE}
    | .configuration.clamAvScan = ${EXTRACTED_FILE_CLAMAV:-true}
    | .configuration.containerNetworkName = "${NETWORK_NAME}"
    | .configuration.dashboardsDarkMode = ${DARK_MODE:-true}
    | .configuration.dashboardsUrl = "${DASHBOARDS_URL:-http://dashboards:5601/dashboards}"
    | .configuration.dockerOrchestrationMode = "${ORCH_MODE}"
    | .configuration.exposeFilebeatTcp = ${FILEBEAT_TCP_EXPOSE:-false}
    | .configuration.exposeLogstash = ${LOGSTASH_EXPOSE:-false}
    | .configuration.exposeOpenSearch = ${OPENSEARCH_EXPOSE:-false}
    | .configuration.exposeSFTP = ${SFTP_EXPOSE:-false}
    | .configuration.extraTags = "${EXTRA_TAGS:-}"
    | .configuration.extractedFileMaxPercentThreshold = ${EXTRACTED_FILE_TOTAL_DISK_USAGE_PERCENT_THRESHOLD:-100}
    | .configuration.extractedFileMaxSizeThreshold = "${EXTRACTED_FILE_MAX_SIZE_THRESHOLD:-1T}"
    | .configuration.filebeatTcpDefaults = ${FILEBEAT_TCP_EXPOSE:-false}
    | .configuration.fileCarveEnabled = true
    | .configuration.fileCarveHttpServeEncryptKey = "${EXTRACTED_FILE_SERVER_PASSWORD:-infected}"
    | .configuration.fileCarveHttpServer = ${EXTRACTED_FILE_SERVER:-true}
    | .configuration.fileCarveHttpServerZip = ${EXTRACTED_FILE_SERVER_ZIP:-true}
    | .configuration.fileCarveMode = "${FILE_EXTRACTION:-interesting}"
    | .configuration.filePreserveMode = "${FILE_PRESERVATION:-quarantined}"
    | .configuration.fileScanRuleUpdate = ${FILE_SCAN_RULE_UPDATE:-false}
    | .configuration.indexDir = "${OPENSEARCH_PATH}"
    | .configuration.indexManagementHistoryInWeeks = ${INDEX_MANAGEMENT_WEEKS_OF_HISTORY:-13}
    | .configuration.indexManagementHotWarm = ${INDEX_MANAGEMENT_HOT_WARM_ENABLE:-false}
    | .configuration.indexManagementOptimizationTimePeriod = "${INDEX_MANAGEMENT_OPTIMIZATION_TIME_PERIOD}"
    | .configuration.indexManagementOptimizeSessionSegments = ${INDEX_MANAGEMENT_SEGMENTS:-1}
    | .configuration.indexManagementPolicy = ${INDEX_MANAGEMENT_ENABLE:-false}
    | .configuration.indexManagementReplicas = ${INDEX_MANAGEMENT_REPLICAS:-0}
    | .configuration.indexManagementSpiDataRetention = "${INDEX_MANAGEMENT_SPI_DATA_RETENTION}"
    | .configuration.indexPruneThreshold = "${DELETE_INDEX_THRESHOLD:-10T}"
    | .configuration.indexSnapshotDir = "${OPENSEARCH_SNAPSHOT_PATH}"
    | .configuration.logstashHost = "${LOGSTASH_HOST:-logstash:5044}"
    | .configuration.lsMemory = "${LOGSTASH_MEMORY}"
    | .configuration.lsWorkers = ${LOGSTASH_WORKERS}
    | .configuration.malcolmIcs = ${ZEEK_ICS:-true}
    | .configuration.malcolmProfile = "${MALCOLM_PROFILE:-malcolm}"
    | .configuration.malcolmRestartPolicy = "${RESTART_MALCOLM:-no}"
    | .configuration.netboxAutoPopulate = ${NETBOX_AUTOPOPULATE:-false}
    | .configuration.netboxLogstashAutoCreatePrefix = ${NETBOX_AUTO_PREFIXES:-false}
    | .configuration.netboxAutoPopulateSubnetFilter = "${NETBOX_AUTO_POPULATE_SUBNETS}"
    | .configuration.netboxLogstashEnrich = ${NETBOX_ENRICH:-true}
    | .configuration.netboxMode = "${NETBOX:-local}"
    | .configuration.netboxSiteName = "${NETBOX_SITE_NAME:-Malcolm}"
    | .configuration.netboxUrl = "${NETBOX_URL}"
    | .configuration.nginxResolverIpv4 = ${NGINX_RESOLVER_IPV4:-true}
    | .configuration.nginxResolverIpv6 = ${NGINX_RESOLVER_IPV6:-false}
    | .configuration.nginxSSL = ${HTTPS:-true}
    | .configuration.opensearchPrimaryMode = "${OPENSEARCH:-opensearch-local}"
    | .configuration.opensearchPrimarySslVerify = ${OPENSEARCH_SSL_VERIFY:-false}
    | .configuration.opensearchPrimaryUrl = "${OPENSEARCH_URL:-https://opensearch:9200}"
    | .configuration.opensearchSecondaryMode = "${OPENSEARCH_SECONDARY:-<MALCOLM_CONFIG_NONE>}"
    | .configuration.opensearchSecondarySslVerify = ${OPENSEARCH_SECONDARY_SSL_VERIFY:-false}
    | .configuration.opensearchSecondaryUrl = "${OPENSEARCH_SECONDARY_URL}"
    | .configuration.osMemory = "${OPENSEARCH_MEMORY}"
    | .configuration.pcapDir = "${PCAP_PATH}"
    | .configuration.pcapNodeName = "${NODE_NAME:-$(hostname -s)}"
    | .configuration.reverseDns = ${REVERSE_DNS:-false}
    | .configuration.suricataLogDir = "${SURICATA_PATH}"
    | .configuration.suricataRuleUpdate = ${SURICATA_RULE_UPDATE:-false}
    | .configuration.syslogTcpPort = ${SYSLOG_PORT_TCP:-0}
    | .configuration.syslogUdpPort = ${SYSLOG_PORT_UDP:-0}
    | .configuration.traefikEntrypoint = "${TRAEFIK_ENTRYPOINT}"
    | .configuration.traefikHost = "${TRAEFIK_HOST}"
    | .configuration.traefikLabels = ${REVERSE_PROXIED:-false}
    | .configuration.traefikOpenSearchHost = "${TRAEFIK_HOST_OPENSEARCH}"
    | .configuration.traefikResolver = "${TRAEFIK_RESOLVER}"
    | .configuration.useDefaultStorageLocations = ${DEFAULT_PATHS}
    | .configuration.vtotApiKey = "${VIRUSTOTAL_API_KEY}"
    | .configuration.yaraScan = ${EXTRACTED_FILE_YARA:-true}
    | .configuration.zeekICSBestGuess = ${ZEEK_ICS_BEST_GUESS:-true}
    | .configuration.zeekIntelCronExpression = "${ZEEK_INTEL_CRON_EXPRESSION}"
    | .configuration.zeekIntelFeedSince = "${ZEEK_INTEL_FEED_SINCE:-24 hours ago}"
    | .configuration.zeekIntelItemExpiration = "${ZEEK_INTEL_ITEM_EXPIRATION:-1min}"
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
    | .configuration.liveArkimeCompressionType = "${LIVE_CAPTURE_ARKIME_COMPRESSION:-none}"
    | .configuration.liveArkimeCompressionLevel = ${LIVE_CAPTURE_ARKIME_COMPRESSION_LEVEL:-0}
    | .configuration.liveArkimeNodeHost = "${CAPTURE_ARKIME_NODE_HOST}"
    | .configuration.liveZeek = ${CAPTURE_ZEEK}
    | .configuration.liveSuricata = ${CAPTURE_SURICATA}
  EOF

  jq -f "${JQ_FILE}" "${SETTINGS_FILE}" | sponge "${SETTINGS_FILE}"

  python3 ./scripts/install.py --verbose "${DEBUG}" --configure --non-interactive \
    --configure-file "${MALCOLM_COMPOSE_FILE:-docker-compose.yml}" \
    --environment-dir-output "${MALCOLM_CONFIG_DIR:-config}" \
    --import-malcolm-config-file "${SETTINGS_FILE}" \
    --extra \
          "arkime-offline.env:ARKIME_AUTO_ANALYZE_PCAP_THREADS=${ARKIME_AUTO_ANALYZE_PCAP_THREADS:-2}" \
          "arkime.env:ARKIME_ROTATE_INDEX=${ARKIME_ROTATE_INDEX:-daily}" \
          "arkime.env:ARKIME_SPI_DATA_MAX_INDICES=${ARKIME_SPI_DATA_MAX_INDICES:-7}" \
          "filebeat.env:FILEBEAT_PREPARE_PROCESS_COUNT=${FILEBEAT_PREPARE_PROCESS_COUNT:-2}" \
          "logstash.env:LOGSTASH_ZEEK_IGNORED_LOGS=${LOGSTASH_ZEEK_IGNORED_LOGS:-loaded_scripts,png,stderr,stdout}" \
          "netbox-common.env:NETBOX_ENRICHMENT_DEBUG=${NETBOX_ENRICHMENT_DEBUG:-false}" \
          "netbox-common.env:NETBOX_ENRICHMENT_DEBUG_TIMINGS=${NETBOX_ENRICHMENT_DEBUG_TIMINGS:-false}" \
          "netbox.env:CSRF_TRUSTED_ORIGINS=${CSRF_TRUSTED_ORIGINS:-https://*}" \
          "nginx.env:NGINX_ERROR_LOG_LEVEL=${NGINX_ERROR_LOG_LEVEL}" \
          "nginx.env:NGINX_KEYCLOAK_BASIC_AUTH=${NGINX_KEYCLOAK_BASIC_AUTH:-false}" \
          "nginx.env:NGINX_LOG_ACCESS_AND_ERRORS=${NGINX_LOG_ACCESS_AND_ERRORS:-true}" \
          "opensearch.env:MALCOLM_NETWORK_INDEX_ALIAS=${MALCOLM_NETWORK_INDEX_ALIAS:-malcolm_network}" \
          "opensearch.env:MALCOLM_NETWORK_INDEX_SUFFIX=${MALCOLM_NETWORK_INDEX_SUFFIX:-'%{%y%m%d}'}" \
          "opensearch.env:MALCOLM_OTHER_INDEX_ALIAS=${MALCOLM_OTHER_INDEX_ALIAS:-malcolm_other}" \
          "opensearch.env:MALCOLM_OTHER_INDEX_SUFFIX=${MALCOLM_OTHER_INDEX_SUFFIX:-'%{%y%m%d}'}" \
          "suricata-offline.env:SURICATA_AUTO_ANALYZE_PCAP_PROCESSES=${SURICATA_AUTO_ANALYZE_PCAP_PROCESSES:-2}" \
          "suricata-offline.env:SURICATA_AUTO_ANALYZE_PCAP_THREADS=${SURICATA_AUTO_ANALYZE_PCAP_THREADS:-0}" \
          "upload-common.env:MALCOLM_API_DEBUG=${MALCOLM_API_DEBUG:-false}" \
          "upload-common.env:PCAP_PIPELINE_IGNORE_PREEXISTING=${PCAP_PIPELINE_IGNORE_PREEXISTING:-false}" \
          "zeek-offline.env:ZEEK_AUTO_ANALYZE_PCAP_THREADS=${ZEEK_AUTO_ANALYZE_PCAP_THREADS:-2}" \
          "zeek.env:CAPA_MAX_REQUESTS=${CAPA_MAX_REQUESTS:-2}" \
          "zeek.env:CLAMD_MAX_REQUESTS=${CLAMD_MAX_REQUESTS:-4}" \
          "zeek.env:EXTRACTED_FILE_HTTP_SERVER_MAGIC=${EXTRACTED_FILE_HTTP_SERVER_MAGIC:-true}" \
          "zeek.env:EXTRACTED_FILE_IGNORE_EXISTING=${EXTRACTED_FILE_IGNORE_EXISTING:-false}" \
          "zeek.env:YARA_MAX_REQUESTS=${YARA_MAX_REQUESTS:-4}" \
          "zeek.env:ZEEK_DISABLE_ICS_GE_SRTP=${ZEEK_DISABLE_ICS_GE_SRTP:-false}" \
          "zeek.env:ZEEK_DISABLE_ICS_GENISYS=${ZEEK_DISABLE_ICS_GENISYS:-true}" \
          "zeek.env:ZEEK_SYNCHROPHASOR_DETAILED=${ZEEK_SYNCHROPHASOR_DETAILED:-false}"

  rm -f "${SETTINGS_FILE}" "${JQ_FILE}"

config:
  {{call_recipe}} _base_config "true"

config-nocap:
  {{call_recipe}} _base_config "false"

auth-setup:
  #!/usr/bin/env bash
  ( [[ -n "${VERBOSE}" ]] && [[ "${VERBOSE}" != "false" ]] && [[ "${VERBOSE}" != "0" ]] ) && DEBUG='-vvvv' || DEBUG=''
  ./scripts/auth_setup ${DEBUG} --auth-noninteractive true \
    --file "${MALCOLM_COMPOSE_FILE:-docker-compose.yml}" \
    --environment-dir "${MALCOLM_CONFIG_DIR:-config}" \
    --runtime "${MALCOLM_CONTAINER_RUNTIME:-docker}" \
    --namespace "${MALCOLM_K8S_NAMESPACE:-malcolm}" \
    --profile "${MALCOLM_PROFILE:-malcolm}" \
    --auth-method "${AUTH_METHOD:-basic}" \
    --auth-generate-opensearch-internal-creds "${AUTH_GENERATE_OPENSEARCH_CREDS}" \
    --auth-generate-netbox-passwords "${AUTH_GENERATE_NETBOX_PASSWORDS:-false}" \
    --auth-generate-redis-password "${AUTH_GENERATE_REDIS_PASSWORD:-true}" \
    --auth-generate-postgres-password "${AUTH_GENERATE_POSTGRES_PASSWORD:-false}" \
    --auth-generate-keycloak-db-password "${AUTH_GENERATE_KEYCLOAK_DB_PASSWORD:-true}" \
    --auth-admin-username "${AUTH_ADMIN_USERNAME}" \
    --auth-admin-password-openssl "$(echo -n "${AUTH_ADMIN_PASSWORD}" | openssl passwd -1 --stdin)" \
    --auth-admin-password-htpasswd "$(echo -n "${AUTH_ADMIN_PASSWORD}" | htpasswd -i -n -B username | cut -d: -f2 | head -n 1)" \
    --auth-arkime-password "${AUTH_ARKIME_PASSWORD:-Malcolm}" \
    --auth-generate-webcerts "${AUTH_GENERATE_WEBCERTS:-true}" \
    --auth-generate-fwcerts "${AUTH_GENERATE_FWCERTS:-true}" \
    --auth-keycloak-realm "${AUTH_KEYCLOAK_REALM:-master}" \
    --auth-keycloak-redirect-uri "${AUTH_KEYCLOAK_REDIRECT_URI:-/index.html}" \
    --auth-keycloak-url "${AUTH_KEYCLOAK_URL}" \
    --auth-keycloak-client-id "${AUTH_KEYCLOAK_CLIENT_ID}" \
    --auth-keycloak-client-secret "${AUTH_KEYCLOAK_CLIENT_SECRET}" \
    --auth-keycloak-bootstrap-password "${AUTH_KEYCLOAK_BOOTSTRAP_PASSWORD}" \
    --auth-require-group "${AUTH_REQUIRE_GROUP}" \
    --auth-require-role "${AUTH_REQUIRE_ROLE}" \
    --auth-netbox-token "${NETBOX_TOKEN}" \
    --auth-role-based-access-control "${ROLE_BASED_ACCESS:-true}"

logs *SERVICES:
  #!/usr/bin/env bash
  ( [[ -n "${VERBOSE}" ]] && [[ "${VERBOSE}" != "false" ]] && [[ "${VERBOSE}" != "0" ]] ) && DEBUG='-vvvv' || DEBUG=''
  ./scripts/logs $DEBUG \
    --file "${MALCOLM_COMPOSE_FILE:-docker-compose.yml}" \
    --environment-dir "${MALCOLM_CONFIG_DIR:-config}" \
    --runtime "${MALCOLM_CONTAINER_RUNTIME:-docker}" \
    --namespace "${MALCOLM_K8S_NAMESPACE:-malcolm}" \
    --profile "${MALCOLM_PROFILE:-malcolm}" \
    -s {{SERVICES}}

status *SERVICES:
  #!/usr/bin/env bash
  ( [[ -n "${VERBOSE}" ]] && [[ "${VERBOSE}" != "false" ]] && [[ "${VERBOSE}" != "0" ]] ) && DEBUG='-vvvv' || DEBUG=''
  ./scripts/status $DEBUG \
    --file "${MALCOLM_COMPOSE_FILE:-docker-compose.yml}" \
    --environment-dir "${MALCOLM_CONFIG_DIR:-config}" \
    --runtime "${MALCOLM_CONTAINER_RUNTIME:-docker}" \
    --namespace "${MALCOLM_K8S_NAMESPACE:-malcolm}" \
    --profile "${MALCOLM_PROFILE:-malcolm}" \
    -s {{SERVICES}}

wipe:
  #!/usr/bin/env bash
  ( [[ -n "${VERBOSE}" ]] && [[ "${VERBOSE}" != "false" ]] && [[ "${VERBOSE}" != "0" ]] ) && DEBUG='-vvvv' || DEBUG=''
  ./scripts/wipe $DEBUG \
    --file "${MALCOLM_COMPOSE_FILE:-docker-compose.yml}" \
    --environment-dir "${MALCOLM_CONFIG_DIR:-config}" \
    --runtime "${MALCOLM_CONTAINER_RUNTIME:-docker}" \
    --namespace "${MALCOLM_K8S_NAMESPACE:-malcolm}" \
    --profile "${MALCOLM_PROFILE:-malcolm}" \
    --delete-namespace "${MALCOLM_K8S_DELETE_NAMESPACE:-false}"

nuke:
  {{call_recipe}} wipe
  rm -rf ./postgres/*

stop:
  #!/usr/bin/env bash
  ( [[ -n "${VERBOSE}" ]] && [[ "${VERBOSE}" != "false" ]] && [[ "${VERBOSE}" != "0" ]] ) && DEBUG='-vvvv' || DEBUG=''
  ./scripts/stop $DEBUG \
    --file "${MALCOLM_COMPOSE_FILE:-docker-compose.yml}" \
    --environment-dir "${MALCOLM_CONFIG_DIR:-config}" \
    --runtime "${MALCOLM_CONTAINER_RUNTIME:-docker}" \
    --namespace "${MALCOLM_K8S_NAMESPACE:-malcolm}" \
    --profile "${MALCOLM_PROFILE:-malcolm}"

start:
  #!/usr/bin/env bash
  ( [[ -n "${VERBOSE}" ]] && [[ "${VERBOSE}" != "false" ]] && [[ "${VERBOSE}" != "0" ]] ) && DEBUG='-vvvv' || DEBUG=''
  ./scripts/start $DEBUG \
    --quiet \
    --file "${MALCOLM_COMPOSE_FILE:-docker-compose.yml}" \
    --environment-dir "${MALCOLM_CONFIG_DIR:-config}" \
    --runtime "${MALCOLM_CONTAINER_RUNTIME:-docker}" \
    --namespace "${MALCOLM_K8S_NAMESPACE:-malcolm}" \
    --profile "${MALCOLM_PROFILE:-malcolm}" \
    --image-source "${MALCOLM_K8S_IMAGE_SOURCE:-ghcr.io/mmguero-dev/Malcolm}" \
    --image-tag "${MALCOLM_K8S_IMAGE_TAG:-main}" \
    --inject-resources "${MALCOLM_K8S_INJECT_RESOURCES:-false}" \
    --no-capabilities "${MALCOLM_K8S_NO_CAPABILITIES:-false}" \
    --no-capture-pods "${MALCOLM_K8S_NO_CAPTURE_PODS:-true}" \
    --skip-persistent-volume-checks "${MALCOLM_K8S_SKIP_PERSISTENT_VOLUME_CHECKS:-false}"

restart *SERVICES:
  #!/usr/bin/env bash
  ( [[ -n "${VERBOSE}" ]] && [[ "${VERBOSE}" != "false" ]] && [[ "${VERBOSE}" != "0" ]] ) && DEBUG='-vvvv' || DEBUG=''
  ./scripts/restart $DEBUG \
    --quiet \
    --file "${MALCOLM_COMPOSE_FILE:-docker-compose.yml}" \
    --environment-dir "${MALCOLM_CONFIG_DIR:-config}" \
    --runtime "${MALCOLM_CONTAINER_RUNTIME:-docker}" \
    --namespace "${MALCOLM_K8S_NAMESPACE:-malcolm}" \
    --profile "${MALCOLM_PROFILE:-malcolm}" \
    --image-source "${MALCOLM_K8S_IMAGE_SOURCE:-ghcr.io/mmguero-dev/Malcolm}" \
    --image-tag "${MALCOLM_K8S_IMAGE_TAG:-main}" \
    --inject-resources "${MALCOLM_K8S_INJECT_RESOURCES:-false}" \
    --no-capabilities "${MALCOLM_K8S_NO_CAPABILITIES:-false}" \
    --no-capture-pods "${MALCOLM_K8S_NO_CAPTURE_PODS:-true}" \
    --skip-persistent-volume-checks "${MALCOLM_K8S_SKIP_PERSISTENT_VOLUME_CHECKS:-false}" \
    -s {{SERVICES}}

build *SERVICES:
  #!/usr/bin/env bash
  ./scripts/build.sh {{SERVICES}}

pull:
  #!/usr/bin/env bash
  [[ -x ./scripts/github_image_helper.sh ]] && \
    ./scripts/github_image_helper.sh "$(./scripts/github_image_helper.sh 99999 2>&1 | grep PullAndTagGithubWorkflowImages | awk '{print $1}')" || \
    "${MALCOLM_CONTAINER_RUNTIME:-docker}" compose --file "${MALCOLM_COMPOSE_FILE:-docker-compose.yml}" --profile "${MALCOLM_PROFILE:-malcolm}" pull

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
