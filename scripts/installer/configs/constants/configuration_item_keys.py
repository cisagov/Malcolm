#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Configuration key constants for Malcolm
"""

# Analysis options
KEY_CONFIG_ITEM_AUTO_ARKIME = "autoArkime"
KEY_CONFIG_ITEM_AUTO_SURICATA = "autoSuricata"
KEY_CONFIG_ITEM_SURICATA_RULE_UPDATE = "suricataRuleUpdate"
KEY_CONFIG_ITEM_AUTO_ZEEK = "autoZeek"
KEY_CONFIG_ITEM_MALCOLM_ICS = "malcolmIcs"
KEY_CONFIG_ITEM_ZEEK_ICS_BEST_GUESS = "zeekICSBestGuess"
KEY_CONFIG_ITEM_REVERSE_DNS = "reverseDns"
KEY_CONFIG_ITEM_AUTO_OUI = "autoOui"
KEY_CONFIG_ITEM_AUTO_FREQ = "autoFreq"

# Live traffic capture options
KEY_CONFIG_ITEM_PCAP_IFACE = "pcapIface"
KEY_CONFIG_ITEM_PCAP_FILTER = "pcapFilter"
KEY_CONFIG_ITEM_TWEAK_IFACE = "tweakIface"
KEY_CONFIG_ITEM_CAPTURE_STATS = "captureStats"
KEY_CONFIG_ITEM_LIVE_ARKIME = "liveArkime"
KEY_CONFIG_ITEM_LIVE_ARKIME_NODE_HOST = "liveArkimeNodeHost"
KEY_CONFIG_ITEM_LIVE_ARKIME_COMP_TYPE = "liveArkimeCompressionType"
KEY_CONFIG_ITEM_LIVE_ARKIME_COMP_LEVEL = "liveArkimeCompressionLevel"
KEY_CONFIG_ITEM_PCAP_NETSNIFF = "pcapNetSniff"
KEY_CONFIG_ITEM_PCAP_TCPDUMP = "pcapTcpDump"
KEY_CONFIG_ITEM_LIVE_ZEEK = "liveZeek"
KEY_CONFIG_ITEM_LIVE_SURICATA = "liveSuricata"
KEY_CONFIG_ITEM_PCAP_NODE_NAME = "pcapNodeName"
KEY_CONFIG_ITEM_EXTRA_TAGS = "extraTags"
KEY_CONFIG_ITEM_ARKIME_EXPOSE_WISE = "arkimeExposeWise"
KEY_CONFIG_ITEM_ARKIME_ALLOW_WISE_CONFIG = "arkimeAllowWiseConfig"
KEY_CONFIG_ITEM_ARKIME_EXPOSE_WISE = "arkimeExposeWise"
KEY_CONFIG_ITEM_ARKIME_WISE_URL = "arkimeWiseUrl"

# Docker options
KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY = "malcolmRestartPolicy"
KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME = "containerNetworkName"
KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE = "dockerOrchestrationMode"
KEY_CONFIG_ITEM_PROCESS_GROUP_ID = "processGroupId"
KEY_CONFIG_ITEM_PROCESS_USER_ID = "processUserId"

# Filebeat options
KEY_CONFIG_ITEM_FILEBEAT_TCP_DEFAULTS = "filebeatTcpDefaults"
KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT = "filebeatTcpLogFormat"
KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_SOURCE_FIELD = "filebeatTcpParseSourceField"
KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_TARGET_FIELD = "filebeatTcpParseTargetField"
KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_DROP_FIELD = "filebeatTcpParseDropField"
KEY_CONFIG_ITEM_FILEBEAT_TCP_TAG = "filebeatTcpTag"

# File carve/extraction options
KEY_CONFIG_ITEM_FILE_CARVE_ENABLED = "fileCarveEnabled"
KEY_CONFIG_ITEM_FILE_CARVE_MODE = "fileCarveMode"
KEY_CONFIG_ITEM_FILE_PRESERVE_MODE = "filePreserveMode"
KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER = "fileCarveHttpServer"
KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER_ZIP = "fileCarveHttpServerZip"
KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVE_ENCRYPT_KEY = "fileCarveHttpServeEncryptKey"
KEY_CONFIG_ITEM_CLAM_AV_SCAN = "clamAvScan"
KEY_CONFIG_ITEM_YARA_SCAN = "yaraScan"
KEY_CONFIG_ITEM_CAPA_SCAN = "capaScan"
KEY_CONFIG_ITEM_VTOT_API_KEY = "vtotApiKey"
KEY_CONFIG_ITEM_FILE_SCAN_RULE_UPDATE = "fileScanRuleUpdate"

# Logstash options
KEY_CONFIG_ITEM_LS_MEMORY = "lsMemory"
KEY_CONFIG_ITEM_LS_WORKERS = "lsWorkers"
KEY_CONFIG_ITEM_LOGSTASH_HOST = "logstashHost"

# NetBox options
KEY_CONFIG_ITEM_NETBOX_MODE = "netboxMode"
KEY_CONFIG_ITEM_NETBOX_LOGSTASH_ENRICH = "netboxLogstashEnrich"
KEY_CONFIG_ITEM_NETBOX_AUTO_POPULATE = "netboxAutoPopulate"
KEY_CONFIG_ITEM_NETBOX_LOGSTASH_AUTO_CREATE_PREFIX = "netboxLogstashAutoCreatePrefix"
KEY_CONFIG_ITEM_NETBOX_AUTO_POPULATE_SUBNET_FILTER = "netboxAutoPopulateSubnetFilter"
KEY_CONFIG_ITEM_NETBOX_SITE_NAME = "netboxSiteName"
KEY_CONFIG_ITEM_NETBOX_URL = "netboxUrl"

# Network options
KEY_CONFIG_ITEM_NGINX_SSL = "nginxSSL"
KEY_CONFIG_ITEM_NGINX_RESOLVER_IPV4 = "nginxResolverIpv4"
KEY_CONFIG_ITEM_NGINX_RESOLVER_IPV6 = "nginxResolverIpv6"
KEY_CONFIG_ITEM_TRAEFIK_HOST = "traefikHost"
KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST = "traefikOpenSearchHost"
KEY_CONFIG_ITEM_TRAEFIK_ENTRYPOINT = "traefikEntrypoint"
KEY_CONFIG_ITEM_TRAEFIK_RESOLVER = "traefikResolver"
KEY_CONFIG_ITEM_TRAEFIK_LABELS = "traefikLabels"
KEY_CONFIG_ITEM_OPEN_PORTS = "openPortsSelection"
KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC = "captureLiveNetworkTraffic"  # captureSelection in legacy installer

# Malcolm ISO-installed environment specific extensions
KEY_CONFIG_ITEM_REACHBACK_REQUEST_ACL = "reachbackRequestAcl"
KEY_CONFIG_ITEM_AUX_FW_AIDE = "auxFwAide"
KEY_CONFIG_ITEM_AUX_FW_AUDITLOG = "auxFwAuditlog"
KEY_CONFIG_ITEM_AUX_FW_CPU = "auxFwCPU"
KEY_CONFIG_ITEM_AUX_FW_DF = "auxFwDf"
KEY_CONFIG_ITEM_AUX_FW_DISK = "auxFwDisk"
KEY_CONFIG_ITEM_AUX_FW_KMSG = "auxFwKmsg"
KEY_CONFIG_ITEM_AUX_FW_MEM = "auxFwMem"
KEY_CONFIG_ITEM_AUX_FW_NETWORK = "auxFwNetwork"
KEY_CONFIG_ITEM_AUX_FW_SYSTEMD = "auxFwSystemd"
KEY_CONFIG_ITEM_AUX_FW_THERMAL = "auxFwThermal"
KEY_CONFIG_ITEM_PRUNE_PCAP = "malSysPrunePcap"
KEY_CONFIG_ITEM_PRUNE_LOGS = "malSysPruneLogs"

# Open ports options
KEY_CONFIG_ITEM_EXPOSE_LOGSTASH = "exposeLogstash"
KEY_CONFIG_ITEM_EXPOSE_OPENSEARCH = "exposeOpenSearch"
KEY_CONFIG_ITEM_EXPOSE_FILEBEAT_TCP = "exposeFilebeatTcp"
KEY_CONFIG_ITEM_EXPOSE_SFTP = "exposeSFTP"
KEY_CONFIG_ITEM_SYSLOG_TCP_PORT = "syslogTcpPort"
KEY_CONFIG_ITEM_SYSLOG_UDP_PORT = "syslogUdpPort"

# OpenSearch options
KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE = "opensearchPrimaryMode"
KEY_CONFIG_ITEM_OS_MEMORY = "osMemory"
KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL = "opensearchPrimaryUrl"
KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_SSL_VERIFY = "opensearchPrimarySslVerify"
KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_MODE = "opensearchSecondaryMode"
KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_URL = "opensearchSecondaryUrl"
KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_SSL_VERIFY = "opensearchSecondarySslVerify"
KEY_CONFIG_ITEM_DASHBOARDS_URL = "dashboardsUrl"
KEY_CONFIG_ITEM_SECONDARY_DOCUMENT_STORE = "secondaryDocumentStore"

# Runtime options
KEY_CONFIG_ITEM_RUNTIME_BIN = "runtimeBin"
KEY_CONFIG_ITEM_MALCOLM_PROFILE = "malcolmProfile"
KEY_CONFIG_ITEM_DASHBOARDS_DARK_MODE = "dashboardsDarkMode"
KEY_CONFIG_ITEM_IMAGE_ARCH = "imageArch"
# This is used for Hedgehog run profile to provide the host/IP for the remote Malcolm instance.
#   It doesn't correspond to a single .env value, just convenience to not have to enter it in 4 places.
KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST = "remoteMalcolmHost"

# Storage options
KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS = "cleanUpOldArtifacts"
KEY_CONFIG_ITEM_CLEAN_UP_OLD_INDICES = "cleanUpOldIndices"
KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS = "useDefaultStorageLocations"
KEY_CONFIG_ITEM_PCAP_DIR = "pcapDir"
KEY_CONFIG_ITEM_ZEEK_LOG_DIR = "zeekLogDir"
KEY_CONFIG_ITEM_SURICATA_LOG_DIR = "suricataLogDir"
KEY_CONFIG_ITEM_INDEX_DIR = "indexDir"
KEY_CONFIG_ITEM_INDEX_SNAPSHOT_DIR = "indexSnapshotDir"
KEY_CONFIG_ITEM_ARKIME_MANAGE_PCAP = "arkimeManagePCAP"
KEY_CONFIG_ITEM_ARKIME_FREESPACEG = "arkimeFreeSpaceG"
KEY_CONFIG_ITEM_EXTRACTED_FILE_MAX_SIZE_THRESHOLD = "extractedFileMaxSizeThreshold"
KEY_CONFIG_ITEM_EXTRACTED_FILE_MAX_PERCENT_THRESHOLD = "extractedFileMaxPercentThreshold"
KEY_CONFIG_ITEM_INDEX_PRUNE_THRESHOLD = "indexPruneThreshold"
KEY_CONFIG_ITEM_INDEX_PRUNE_NAME_SORT = "indexPruneNameSort"
KEY_CONFIG_ITEM_INDEX_MANAGEMENT_POLICY = "indexManagementPolicy"
KEY_CONFIG_ITEM_INDEX_MANAGEMENT_HOT_WARM = "indexManagementHotWarm"
KEY_CONFIG_ITEM_INDEX_MANAGEMENT_OPTIMIZATION_TIME_PERIOD = "indexManagementOptimizationTimePeriod"
KEY_CONFIG_ITEM_INDEX_MANAGEMENT_SPI_DATA_RETENTION = "indexManagementSpiDataRetention"
KEY_CONFIG_ITEM_INDEX_MANAGEMENT_REPLICAS = "indexManagementReplicas"
KEY_CONFIG_ITEM_INDEX_MANAGEMENT_HISTORY_IN_WEEKS = "indexManagementHistoryInWeeks"
KEY_CONFIG_ITEM_INDEX_MANAGEMENT_OPTIMIZE_SESSION_SEGMENTS = "indexManagementOptimizeSessionSegments"

# Threat intelligence feed options
KEY_CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS = "zeekPullIntelligenceFeeds"
KEY_CONFIG_ITEM_ZEEK_INTEL_ON_STARTUP = "zeekIntelOnStartup"
KEY_CONFIG_ITEM_ZEEK_INTEL_FEED_SINCE = "zeekIntelFeedSince"
KEY_CONFIG_ITEM_ZEEK_INTEL_CRON_EXPRESSION = "zeekIntelCronExpression"
KEY_CONFIG_ITEM_ZEEK_INTEL_ITEM_EXPIRATION = "zeekIntelItemExpiration"


def get_configuration_item_keys_dict():
    """Get all configuration item constants from this module."""
    constants = {}
    # Iterate over globals to find all defined constants in this module
    for key_name, key_value in globals().items():
        # Ensure that we are only processing string values
        if isinstance(key_value, str):
            # Check if the variable name matches the pattern for config items
            if key_name.startswith("KEY_CONFIG_ITEM_"):
                constants[key_value] = key_name
    return constants


# A dictionary representation of all environment keys, created once at module load.
ALL_CONFIGURATION_ITEM_KEYS_DICT = get_configuration_item_keys_dict()


def get_set_of_configuration_item_keys():
    return set(ALL_CONFIGURATION_ITEM_KEYS_DICT.keys())
