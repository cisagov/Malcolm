#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Environment variable keys
"""

from scripts.malcolm_constants import CONTAINER_RUNTIME_KEY, PROFILE_KEY

KEY_ENV_ARKIME_MANAGE_PCAP_FILES = "MANAGE_PCAP_FILES"  # Whether or not Arkime is allowed to delete uploaded/captured PCAP
KEY_ENV_ARKIME_FREESPACEG = "ARKIME_FREESPACEG"  # Threshold for Arkime PCAP deletion
KEY_ENV_ARKIME_LIVE_CAPTURE = "ARKIME_LIVE_CAPTURE"  # live traffic analysis with Arkime capture (only available with remote opensearch or elasticsearch)
KEY_ENV_ARKIME_LIVE_NODE_HOST = (
    "ARKIME_LIVE_NODE_HOST"  # capture source "node host" for live Arkime capture
)
KEY_ENV_ARKIME_ROTATED_PCAP = "ARKIME_ROTATED_PCAP"  # rotated captured PCAP analysis with Arkime (not live capture)
KEY_ENV_ARKIME_AUTO_ANALYZE_PCAP_FILES = (
    "ARKIME_AUTO_ANALYZE_PCAP_FILES"  # automatic uploaded pcap analysis with Arkime
)
KEY_ENV_ARKIME_INDEX_MANAGEMENT_ENABLED = (
    "INDEX_MANAGEMENT_ENABLED"  # Should Arkime use an ILM policy?
)
KEY_ENV_ARKIME_INDEX_MANAGEMENT_HOT_WARM_ENABLED = "INDEX_MANAGEMENT_HOT_WARM_ENABLED"  # Should Arkime use a hot/warm design in which non-session data is stored in a warm index? (see https://https://arkime.com/faq#ilm)
KEY_ENV_ARKIME_INDEX_MANAGEMENT_OPTIMIZATION_PERIOD = "INDEX_MANAGEMENT_OPTIMIZATION_PERIOD"  # Time in hours/days before moving (Arkime indexes to warm) and force merge (number followed by h or d), default 30
KEY_ENV_ARKIME_INDEX_MANAGEMENT_RETENTION_TIME = "INDEX_MANAGEMENT_RETENTION_TIME"  # Time in hours/days before deleting Arkime indexes (number followed by h or d), default 90
KEY_ENV_ARKIME_INDEX_MANAGEMENT_OLDER_SESSION_REPLICAS = "INDEX_MANAGEMENT_OLDER_SESSION_REPLICAS"  # Number of replicas for older sessions indices in the ILM policy, default 0
KEY_ENV_ARKIME_INDEX_MANAGEMENT_HISTORY_RETENTION_WEEKS = "INDEX_MANAGEMENT_HISTORY_RETENTION_WEEKS"  # Number of weeks of history to keep, default 13
KEY_ENV_ARKIME_INDEX_MANAGEMENT_SEGMENTS = "INDEX_MANAGEMENT_SEGMENTS"  # Number of segments to optimize sessions to in the ILM policy, default 1

KEY_ENV_CONTAINER_RUNTIME_KEY = CONTAINER_RUNTIME_KEY

KEY_ENV_FILEBEAT_TCP_LISTEN = (
    "FILEBEAT_TCP_LISTEN"  # expose a filebeat TCP input listener
)
KEY_ENV_FILEBEAT_TCP_LOG_FORMAT = "FILEBEAT_TCP_LOG_FORMAT"  # log format expected for events sent to the filebeat TCP input listener
KEY_ENV_FILEBEAT_TCP_PARSE_SOURCE_FIELD = "FILEBEAT_TCP_PARSE_SOURCE_FIELD"  # source field name to parse for events sent to the filebeat TCP input listener
KEY_ENV_FILEBEAT_TCP_PARSE_TARGET_FIELD = "FILEBEAT_TCP_PARSE_TARGET_FIELD"  # target field name to store decoded JSON fields for events sent to the filebeat TCP input listener
KEY_ENV_FILEBEAT_TCP_PARSE_DROP_FIELD = "FILEBEAT_TCP_PARSE_DROP_FIELD"  # field to drop in events sent to the filebeat TCP input listener
KEY_ENV_FILEBEAT_TCP_TAG = "FILEBEAT_TCP_TAG"  # tag to append to events sent to the filebeat TCP input listener
KEY_ENV_FILEBEAT_SYSLOG_TCP_LISTEN = "FILEBEAT_SYSLOG_TCP_LISTEN"  # Syslog over TCP
KEY_ENV_FILEBEAT_SYSLOG_TCP_PORT = "FILEBEAT_SYSLOG_TCP_PORT"
KEY_ENV_FILEBEAT_SYSLOG_UDP_LISTEN = "FILEBEAT_SYSLOG_UDP_LISTEN"  # Syslog over UDP
KEY_ENV_FILEBEAT_SYSLOG_UDP_PORT = "FILEBEAT_SYSLOG_UDP_PORT"
KEY_ENV_FILEBEAT_WATCHER_POLLING = (
    "FILEBEAT_WATCHER_POLLING"  # Use polling for file watching vs. native
)

KEY_ENV_FREQ_LOOKUP = "FREQ_LOOKUP"  # freq.py string randomness calculations

KEY_ENV_LOGSTASH_PIPELINE_WORKERS = "pipeline.workers"  # logstash pipeline workers
KEY_ENV_LOGSTASH_HOST = "LOGSTASH_HOST"  # Logstash host and port
KEY_ENV_LOGSTASH_REVERSE_DNS = (
    "LOGSTASH_REVERSE_DNS"  # automatic local reverse dns lookup
)
KEY_ENV_LOGSTASH_OUI_LOOKUP = "LOGSTASH_OUI_LOOKUP"  # automatic MAC OUI lookup
KEY_ENV_LOGSTASH_JAVA_OPTS = "LS_JAVA_OPTS"  # logstash memory allowance

KEY_ENV_NETBOX_ENRICHMENT = (
    "NETBOX_ENRICHMENT"  # enrich network traffic metadata via NetBox API calls
)
KEY_ENV_NETBOX_AUTO_CREATE_PREFIX = "NETBOX_AUTO_CREATE_PREFIX"  # create missing NetBox subnet prefixes based on observed network traffic
KEY_ENV_NETBOX_AUTO_POPULATE = "NETBOX_AUTO_POPULATE"  # populate the NetBox inventory based on observed network traffic
KEY_ENV_NETBOX_DEFAULT_SITE = "NETBOX_DEFAULT_SITE"  # NetBox default site name
KEY_ENV_NETBOX_URL = "NETBOX_URL"  # remote netbox URL
KEY_ENV_NETBOX_MODE = "NETBOX_MODE"  # netbox mode

KEY_ENV_NGINX_SSL = (
    "NGINX_SSL"  # HTTPS (nginxSSL=True) vs unencrypted HTTP (nginxSSL=False)
)
KEY_ENV_NGINX_RESOLVER_IPV4_OFF = (
    "NGINX_RESOLVER_IPV4_OFF"  # "off" parameters for IPv4/IPv6 for NGINX resolver
)
KEY_ENV_NGINX_RESOLVER_IPV6_OFF = "NGINX_RESOLVER_IPV6_OFF"

KEY_ENV_OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT = (
    "OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT"  # delete based on index pattern size
)
KEY_ENV_OPENSEARCH_INDEX_SIZE_PRUNE_NAME_SORT = "OPENSEARCH_INDEX_SIZE_PRUNE_NAME_SORT"  # delete based on index pattern size (sorted by name vs. creation time)
KEY_ENV_OPENSEARCH_PRIMARY = (
    "OPENSEARCH_PRIMARY"  # OpenSearch primary instance is local vs. remote
)
KEY_ENV_OPENSEARCH_URL = "OPENSEARCH_URL"  # OpenSearch primary instance URL
KEY_ENV_OPENSEARCH_SSL_CERTIFICATE_VERIFICATION = "OPENSEARCH_SSL_CERTIFICATE_VERIFICATION"  # OpenSearch primary instance needs SSL verification
KEY_ENV_OPENSEARCH_SECONDARY_URL = (
    "OPENSEARCH_SECONDARY_URL"  # OpenSearch secondary instance URL
)
KEY_ENV_OPENSEARCH_SECONDARY_SSL_CERTIFICATE_VERIFICATION = "OPENSEARCH_SECONDARY_SSL_CERTIFICATE_VERIFICATION"  # OpenSearch secondary instance needs SSL verification
KEY_ENV_OPENSEARCH_SECONDARY = (
    "OPENSEARCH_SECONDARY"  # OpenSearch secondary remote instance is enabled
)
KEY_ENV_OPENSEARCH_JAVA_OPTS = "OPENSEARCH_JAVA_OPTS"  # OpenSearch memory allowance
KEY_ENV_OPENSEARCH_DASHBOARDS_URL = "DASHBOARDS_URL"  # OpenSearch Dashboards URL
KEY_ENV_OPENSEARCH_DASHBOARDS_DARKMODE = (
    "DASHBOARDS_DARKMODE"  # turn on dark mode, or not
)

KEY_ENV_PCAP_ENABLE_NETSNIFF = "PCAP_ENABLE_NETSNIFF"  # capture pcaps via netsniff-ng
KEY_ENV_PCAP_ENABLE_TCPDUMP = "PCAP_ENABLE_TCPDUMP"  # capture pcaps via tcpdump
KEY_ENV_PCAP_IFACE_TWEAK = "PCAP_IFACE_TWEAK"  # disable NIC hardware offloading features and adjust ring buffers
KEY_ENV_PCAP_IFACE = "PCAP_IFACE"  # capture interface(s)
KEY_ENV_PCAP_FILTER = "PCAP_FILTER"  # capture filter
KEY_ENV_PCAP_NODE_NAME = (
    "PCAP_NODE_NAME"  # capture source "node name" for locally processed PCAP files
)
KEY_ENV_PCAP_PIPELINE_POLLING = (
    "PCAP_PIPELINE_POLLING"  # Use polling for file watching vs. native
)

KEY_ENV_PGID = "PGID"  # process Group ID
KEY_ENV_PUID = "PUID"  # process User ID
KEY_ENV_PROFILE_KEY = PROFILE_KEY

KEY_ENV_SURICATA_UPDATE_RULES = (
    "SURICATA_UPDATE_RULES"  # Suricata signature updates (via suricata-update)
)
KEY_ENV_SURICATA_DISABLE_ICS_ALL = (
    "SURICATA_DISABLE_ICS_ALL"  # disable/enable ICS analyzers
)
KEY_ENV_SURICATA_LIVE_CAPTURE = (
    "SURICATA_LIVE_CAPTURE"  # live traffic analysis with Suricata
)
KEY_ENV_SURICATA_STATS_ENABLED = (
    "SURICATA_STATS_ENABLED"  # live capture statistics for Suricata
)
KEY_ENV_SURICATA_STATS_EVE_ENABLED = "SURICATA_STATS_EVE_ENABLED"
KEY_ENV_SURICATA_ROTATED_PCAP = "SURICATA_ROTATED_PCAP"  # rotated captured PCAP analysis with Suricata (not live capture)
KEY_ENV_SURICATA_AUTO_ANALYZE_PCAP_FILES = (
    "SURICATA_AUTO_ANALYZE_PCAP_FILES"  # automatic uploaded pcap analysis with suricata
)

KEY_ENV_ZEEK_VTOT_API2_KEY = "VTOT_API2_KEY"  # virustotal API key
KEY_ENV_ZEEK_EXTRACTOR_MODE = "ZEEK_EXTRACTOR_MODE"  # zeek file extraction mode
KEY_ENV_ZEEK_FILE_PRESERVATION = (
    "EXTRACTED_FILE_PRESERVATION"  # zeek file preservation mode
)
KEY_ENV_ZEEK_DISABLE_ICS_ALL = "ZEEK_DISABLE_ICS_ALL"  # disable/enable ICS analyzers
KEY_ENV_ZEEK_DISABLE_BEST_GUESS_ICS = (
    "ZEEK_DISABLE_BEST_GUESS_ICS"  # disable/enable ICS best guess
)
KEY_ENV_ZEEK_LIVE_CAPTURE = "ZEEK_LIVE_CAPTURE"  # live traffic analysis with Zeek
KEY_ENV_ZEEK_DISABLE_STATS = "ZEEK_DISABLE_STATS"  # live capture statistics for Zeek
KEY_ENV_ZEEK_ROTATED_PCAP = (
    "ZEEK_ROTATED_PCAP"  # rotated captured PCAP analysis with Zeek (not live capture)
)
KEY_ENV_ZEEK_AUTO_ANALYZE_PCAP_FILES = (
    "ZEEK_AUTO_ANALYZE_PCAP_FILES"  # automatic uploaded pcap analysis with Zeek
)
KEY_ENV_ZEEK_INTEL_REFRESH_ON_STARTUP = "ZEEK_INTEL_REFRESH_ON_STARTUP"  # Pull from threat intelligence feeds on container startup
KEY_ENV_ZEEK_INTEL_REFRESH_CRON_EXPRESSION = "ZEEK_INTEL_REFRESH_CRON_EXPRESSION"  # Cron expression for scheduled pulls from threat intelligence feeds
KEY_ENV_ZEEK_INTEL_FEED_SINCE = (
    "ZEEK_INTEL_FEED_SINCE"  # Threat indicator "since" period
)
KEY_ENV_ZEEK_INTEL_ITEM_EXPIRATION = "ZEEK_INTEL_ITEM_EXPIRATION"  # Intel::item_expiration timeout for intelligence items
KEY_ENV_ZEEK_FILE_PRUNE_THRESHOLD_TOTAL_DISK_USAGE_PERCENT = "EXTRACTED_FILE_PRUNE_THRESHOLD_TOTAL_DISK_USAGE_PERCENT"  # total disk fill threshold for pruning zeek extracted files
KEY_ENV_ZEEK_FILE_PRUNE_THRESHOLD_MAX_SIZE = "EXTRACTED_FILE_PRUNE_THRESHOLD_MAX_SIZE"  # zeek extracted files maximum consumption threshold
KEY_ENV_ZEEK_FILE_HTTP_SERVER_ENABLE = (
    "EXTRACTED_FILE_HTTP_SERVER_ENABLE"  # HTTP server for extracted files
)
KEY_ENV_ZEEK_FILE_HTTP_SERVER_ZIP = (
    "EXTRACTED_FILE_HTTP_SERVER_ZIP"  # ZIP HTTP server for extracted files
)
KEY_ENV_ZEEK_FILE_HTTP_SERVER_KEY = "EXTRACTED_FILE_HTTP_SERVER_KEY"  # key for encrypted HTTP-served extracted files (' -> '' for escaping in YAML)
KEY_ENV_ZEEK_FILE_ENABLE_YARA = "EXTRACTED_FILE_ENABLE_YARA"  # file scanning via yara
KEY_ENV_ZEEK_FILE_ENABLE_CAPA = (
    "EXTRACTED_FILE_ENABLE_CAPA"  # PE file scanning via capa
)
KEY_ENV_ZEEK_FILE_ENABLE_CLAMAV = (
    "EXTRACTED_FILE_ENABLE_CLAMAV"  # file scanning via clamav
)
KEY_ENV_ZEEK_FILE_ENABLE_VTOT = (
    "EXTRACTED_FILE_ENABLE_VTOT"  # file scanning via virustotal
)
KEY_ENV_ZEEK_FILE_UPDATE_RULES = "EXTRACTED_FILE_UPDATE_RULES"  # rule updates (yara/capa via git, clamav via freshclam)
KEY_ENV_ZEEK_FILE_WATCHER_POLLING = (
    "EXTRACTED_FILE_WATCHER_POLLING"  # Use polling for file watching vs. native
)


def get_env_key_dict():
    """Get all environment key constants from this module."""
    constants = {}
    # Iterate over globals to find all defined constants in this module
    for key_name, key_value in globals().items():
        # Ensure that we are only processing string values
        if isinstance(key_value, str):
            # Check if the variable name matches the pattern for env keys or specific imported keys
            if key_name.startswith("KEY_ENV_") or key_name in (
                "PROFILE_KEY",
                "CONTAINER_RUNTIME_KEY",
            ):
                constants[key_value] = key_value
    return constants


# A dictionary representation of all environment keys, created once at module load.
ALL_ENV_KEYS_DICT = get_env_key_dict()
