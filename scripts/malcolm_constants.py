#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

import enum
from collections import defaultdict
from enum import Enum, Flag, auto


###################################################################################################
PROFILE_KEY = "MALCOLM_PROFILE"
PROFILE_MALCOLM = "malcolm"
PROFILE_HEDGEHOG = "hedgehog"
CONTAINER_RUNTIME_KEY = "MALCOLM_CONTAINER_RUNTIME"

###################################################################################################
PLATFORM_WINDOWS = "Windows"
PLATFORM_MAC = "Darwin"
PLATFORM_LINUX = "Linux"
PLATFORM_LINUX_ALMA = "almalinux"
PLATFORM_LINUX_AMAZON = "amzn"
PLATFORM_LINUX_CENTOS = "centos"
PLATFORM_LINUX_DEBIAN = "debian"
PLATFORM_LINUX_ELEMENTARY = "elementary"
PLATFORM_LINUX_FEDORA = "fedora"
PLATFORM_LINUX_MINT = "linuxmint"
PLATFORM_LINUX_POP = "pop"
PLATFORM_LINUX_RHEL = "rhel"
PLATFORM_LINUX_ROCKY = "rocky"
PLATFORM_LINUX_UBUNTU = "ubuntu"
PLATFORM_LINUX_ZORIN = "zorin"

###################################################################################################
# Default values for process user ID and group ID
PUID_DEFAULT = 1000
PGID_DEFAULT = 1000

###################################################################################################
YAML_VERSION = (1, 1)

###################################################################################################
LOGSTASH_JAVA_OPTS_DEFAULT = "-server -Xmx2500m -Xms2500m -Xss2048k -XX:-HeapDumpOnOutOfMemoryError -Djava.security.egd=file:/dev/./urandom -Dlog4j.formatMsgNoLookups=true"
OPENSEARCH_JAVA_OPTS_DEFAULT = "-server -Xmx10g -Xms10g -Xss256k -XX:-HeapDumpOnOutOfMemoryError -Djava.security.egd=file:/dev/./urandom -Dlog4j.formatMsgNoLookups=true"


###################################################################################################
# Constants for run modes
class PresentationMode(Enum):
    MODE_TUI = auto()  # Text-based User Interface
    MODE_DUI = auto()  # Dialogs
    MODE_GUI = auto()  # Graphical
    MODE_SILENT = auto()  # Silent mode


###################################################################################################
# Constants for Malcolm image prefix and dotfile secret key
MALCOLM_IMAGE_PREFIX = "ghcr.io/idaholab/malcolm/"
MALCOLM_VERSION = "26.08.0"

###################################################################################################
# Constants for Malcolm configmap directory replacer
MALCOLM_DOTFILE_SECRET_KEY = "K8S_SECRET"
MALCOLM_CONFIGMAP_DIR_REPLACER = "_MALDIR_"

###################################################################################################
# Directory path constants
HEDGEHOG_PCAP_DIR = "pcap"
HEDGEHOG_ZEEK_DIR = "zeek"
MALCOLM_DB_DIR = "datastore"
MALCOLM_PCAP_DIR = "pcap"
MALCOLM_LOGS_DIR = "logs"

###################################################################################################
SERVICE_PORT_HEDGEHOG_PROFILE_ARKIME_VIEWER = "8005"
SERVICE_PORT_HEDGEHOG_PROFILE_EXTRACTED_FILES = "8006"

# Malcolm extension fields for docker-compose
COMPOSE_MALCOLM_EXTENSION = "x-malcolm"
COMPOSE_MALCOLM_EXTENSION_HEDGEHOG = "hedgehog"
COMPOSE_MALCOLM_EXTENSION_HEDGEHOG_REACHBACK_REQUEST_ACL = "request_acl"
COMPOSE_MALCOLM_EXTENSION_AUX_FW = "aux-forwarders"
COMPOSE_MALCOLM_EXTENSION_AUX_FW_AIDE = "aide"
COMPOSE_MALCOLM_EXTENSION_AUX_FW_AUDITLOG = "auditlog"
COMPOSE_MALCOLM_EXTENSION_AUX_FW_CPU = "cpu"
COMPOSE_MALCOLM_EXTENSION_AUX_FW_DF = "df"
COMPOSE_MALCOLM_EXTENSION_AUX_FW_DISK = "disk"
COMPOSE_MALCOLM_EXTENSION_AUX_FW_KMSG = "kmsg"
COMPOSE_MALCOLM_EXTENSION_AUX_FW_MEM = "mem"
COMPOSE_MALCOLM_EXTENSION_AUX_FW_NETWORK = "network"
COMPOSE_MALCOLM_EXTENSION_AUX_FW_SYSTEMD = "systemd"
COMPOSE_MALCOLM_EXTENSION_AUX_FW_THERMAL = "thermal"
COMPOSE_MALCOLM_EXTENSION_PRUNE = "prune"
COMPOSE_MALCOLM_EXTENSION_PRUNE_PCAP = "pcap"
COMPOSE_MALCOLM_EXTENSION_PRUNE_LOGS = "logs"

###################################################################################################
# Directory path constants for volume mapping

# Container paths (inside containers) used for volume mappings
FILEBEAT_SURICATA_LOG_CONTAINER_PATH = "/suricata"
FILEBEAT_ZEEK_LOG_CONTAINER_PATH = "/zeek"
FILEBEAT_FILESCAN_LOG_PATH = "/filescan"
FILESCAN_LOG_CONTAINER_PATH = "/filescan/data/logs"
OPENSEARCH_BACKUP_CONTAINER_PATH = "/opt/opensearch/backup"
OPENSEARCH_DATA_CONTAINER_PATH = "/usr/share/opensearch/data"
PCAP_CAPTURE_CONTAINER_PATH = "/pcap"
PCAP_DATA_CONTAINER_PATH = "/data/pcap"
SURICATA_LOG_CONTAINER_PATH = "/var/log/suricata"
UPLOAD_ARTIFACT_CONTAINER_PATH = "/var/www/upload/server/php/chroot/files"
ZEEK_EXTRACT_FILES_CONTAINER_PATH = "/zeek/extract_files"
ZEEK_LIVE_LOG_CONTAINER_PATH = "/zeek/live"
ZEEK_LOG_UPLOAD_CONTAINER_PATH = "/zeek/upload"

# Default host directories when config values are not set
DEFAULT_FILESCAN_LOG_DIR = "./filescan-logs"
DEFAULT_INDEX_DIR = "./opensearch"
DEFAULT_INDEX_SNAPSHOT_DIR = "./opensearch-backup"
DEFAULT_PCAP_DIR = "./pcap"
DEFAULT_SURICATA_LOG_DIR = "./suricata-logs"
DEFAULT_ZEEK_LOG_DIR = "./zeek-logs"

MALCOLM_ENRICHABLE_LOG_TYPES = [
    "all",
    "default",
    "ics",
    "ot",
    "filescan.strelka",
    "suricata.alert",
    "zeek.analyzer",
    "zeek.bacnet",
    "zeek.bacnet_device_control",
    "zeek.bacnet_discovery",
    "zeek.bacnet_property",
    "zeek.bestguess",
    "zeek.bsap_ip_header",
    "zeek.bsap_ip_rdb",
    "zeek.bsap_serial_header",
    "zeek.bsap_serial_rdb",
    "zeek.bsap_serial_rdb_ext",
    "zeek.c1222",
    "zeek.c1222_authentication_value",
    "zeek.c1222_dereg_reg_service",
    "zeek.c1222_identification_service",
    "zeek.c1222_logon_security_service",
    "zeek.c1222_read_write_service",
    "zeek.c1222_resolve_service",
    "zeek.c1222_service_error",
    "zeek.c1222_trace_service",
    "zeek.c1222_user_information",
    "zeek.c1222_wait_service",
    "zeek.capture_loss",
    "zeek.cip",
    "zeek.cip_identity",
    "zeek.cip_io",
    "zeek.conn",
    "zeek.cotp",
    "zeek.dce_rpc",
    "zeek.dhcp",
    "zeek.dnp3",
    "zeek.dnp3_control",
    "zeek.dnp3_objects",
    "zeek.dns",
    "zeek.ecat_aoe_info",
    "zeek.ecat_arp_info",
    "zeek.ecat_coe_info",
    "zeek.ecat_dev_info",
    "zeek.ecat_foe_info",
    "zeek.ecat_log_address",
    "zeek.ecat_registers",
    "zeek.ecat_soe_info",
    "zeek.enip",
    "zeek.files",
    "zeek.ftp",
    "zeek.fuid",
    "zeek.ge_srtp",
    "zeek.genisys",
    "zeek.gquic",
    "zeek.hart_ip",
    "zeek.hart_ip_common_commands",
    "zeek.hart_ip_direct_pdu_command",
    "zeek.hart_ip_session_record",
    "zeek.hart_ip_universal_commands",
    "zeek.http",
    "zeek.intel",
    "zeek.ipsec",
    "zeek.irc",
    "zeek.ja4d",
    "zeek.ja4ssh",
    "zeek.kerberos",
    "zeek.known_certs",
    "zeek.known_hosts",
    "zeek.known_modbus",
    "zeek.known_routers",
    "zeek.known_services",
    "zeek.ldap",
    "zeek.ldap_search",
    "zeek.login",
    "zeek.modbus",
    "zeek.modbus_detailed",
    "zeek.modbus_mask_write_register",
    "zeek.modbus_read_device_identification",
    "zeek.modbus_read_write_multiple_registers",
    "zeek.mqtt_connect",
    "zeek.mqtt_publish",
    "zeek.mqtt_subscribe",
    "zeek.mysql",
    "zeek.notice",
    "zeek.ntlm",
    "zeek.ntp",
    "zeek.ocsp",
    "zeek.omron_fins",
    "zeek.omron_fins_data_link_status_read",
    "zeek.omron_fins_detail",
    "zeek.omron_fins_error",
    "zeek.omron_fins_file",
    "zeek.omron_fins_network_status_read",
    "zeek.opcua_binary",
    "zeek.opcua_binary_activate_session",
    "zeek.opcua_binary_activate_session_client_software_cert",
    "zeek.opcua_binary_activate_session_locale_id",
    "zeek.opcua_binary_aggregate_filter",
    "zeek.opcua_binary_browse",
    "zeek.opcua_binary_browse_description",
    "zeek.opcua_binary_browse_request_continuation_point",
    "zeek.opcua_binary_browse_response_references",
    "zeek.opcua_binary_browse_result",
    "zeek.opcua_binary_close_session",
    "zeek.opcua_binary_create_monitored_items",
    "zeek.opcua_binary_create_monitored_items_create_item",
    "zeek.opcua_binary_create_session",
    "zeek.opcua_binary_create_session_discovery",
    "zeek.opcua_binary_create_session_endpoints",
    "zeek.opcua_binary_create_session_user_token",
    "zeek.opcua_binary_create_subscription",
    "zeek.opcua_binary_data_change_filter",
    "zeek.opcua_binary_diag_info_detail",
    "zeek.opcua_binary_event_filter",
    "zeek.opcua_binary_event_filter_attribute_operand",
    "zeek.opcua_binary_event_filter_attribute_operand_browse_paths",
    "zeek.opcua_binary_event_filter_element_operand",
    "zeek.opcua_binary_event_filter_literal_operand",
    "zeek.opcua_binary_event_filter_select_clause",
    "zeek.opcua_binary_event_filter_simple_attribute_operand",
    "zeek.opcua_binary_event_filter_simple_attribute_operand_browse_paths",
    "zeek.opcua_binary_event_filter_where_clause",
    "zeek.opcua_binary_event_filter_where_clause_elements",
    "zeek.opcua_binary_get_endpoints",
    "zeek.opcua_binary_get_endpoints_description",
    "zeek.opcua_binary_get_endpoints_discovery",
    "zeek.opcua_binary_get_endpoints_locale_id",
    "zeek.opcua_binary_get_endpoints_profile_uri",
    "zeek.opcua_binary_get_endpoints_user_token",
    "zeek.opcua_binary_opensecure_channel",
    "zeek.opcua_binary_read",
    "zeek.opcua_binary_read_nodes_to_read",
    "zeek.opcua_binary_read_results",
    "zeek.opcua_binary_status_code_detail",
    "zeek.opcua_binary_variant_array_dims",
    "zeek.opcua_binary_variant_data",
    "zeek.opcua_binary_variant_data_value",
    "zeek.opcua_binary_variant_extension_object",
    "zeek.opcua_binary_variant_metadata",
    "zeek.opcua_binary_write",
    "zeek.ospf",
    "zeek.pe",
    "zeek.postgresql",
    "zeek.profinet",
    "zeek.profinet_dce_rpc",
    "zeek.profinet_io_cm",
    "zeek.radius",
    "zeek.rdp",
    "zeek.redis",
    "zeek.rfb",
    "zeek.roc_plus",
    "zeek.roc_plus_configurable_opcode",
    "zeek.roc_plus_data_request",
    "zeek.roc_plus_file_transfer",
    "zeek.roc_plus_historical_min_max_vals",
    "zeek.roc_plus_history_information",
    "zeek.roc_plus_history_point_data",
    "zeek.roc_plus_login",
    "zeek.roc_plus_peer_to_peer_network_messages",
    "zeek.roc_plus_realtime_clock",
    "zeek.roc_plus_single_point_parameters",
    "zeek.roc_plus_store_and_forward",
    "zeek.roc_plus_sys_cfg",
    "zeek.roc_plus_time_period_history_points",
    "zeek.roc_plus_transaction_history",
    "zeek.roc_plus_user_defined_info",
    "zeek.s7comm",
    "zeek.s7comm_known_devices",
    "zeek.s7comm_plus",
    "zeek.s7comm_read_szl",
    "zeek.s7comm_upload_download",
    "zeek.signatures",
    "zeek.sip",
    "zeek.smb_cmd",
    "zeek.smb_files",
    "zeek.smb_mapping",
    "zeek.smtp",
    "zeek.snmp",
    "zeek.socks",
    "zeek.software",
    "zeek.ssh",
    "zeek.ssl",
    "zeek.stun",
    "zeek.stun_nat",
    "zeek.synchrophasor",
    "zeek.synchrophasor_cfg",
    "zeek.synchrophasor_cfg_detail",
    "zeek.synchrophasor_cmd",
    "zeek.synchrophasor_data",
    "zeek.synchrophasor_data_detail",
    "zeek.synchrophasor_hdr",
    "zeek.syslog",
    "zeek.tds",
    "zeek.tds_rpc",
    "zeek.tds_sql_batch",
    "zeek.tftp",
    "zeek.tunnel",
    "zeek.websocket",
    "zeek.weird",
    "zeek.wireguard",
    "zeek.x509",
]

MALCOLM_ENRICHABLE_LOG_TYPES_DEFAULT = [
    "filescan.strelka",
    "suricata.alert",
    "zeek.conn",
    "zeek.dce_rpc",
    "zeek.dhcp",
    "zeek.dns",
    "zeek.known_hosts",
    "zeek.known_routers",
    "zeek.known_services",
    "zeek.login",
    "zeek.notice",
    "zeek.ntlm",
    "zeek.rdp",
    "zeek.rfb",
    "zeek.signatures",
    "zeek.smb_cmd",
    "zeek.smb_files",
    "zeek.smb_mapping",
    "zeek.software",
    "zeek.ssh",
    "zeek.weird",
]

MALCOLM_STRELKA_SCANNERS_DEFAULT = [
    "ScanBatch",
    "ScanBmpEof",
    "ScanBzip2",
    "ScanClamav",
    "ScanDmg",
    "ScanDocx",
    "ScanDonut",
    "ScanEmail",
    "ScanEncryptedDoc",
    "ScanEncryptedZip",
    "ScanEntropy",
    "ScanExiftool",
    "ScanGifEof",
    "ScanGzip",
    "ScanHtml",
    "ScanIqy",
    "ScanIso",
    "ScanJarManifest",
    "ScanJavascript",
    "ScanJnlp",
    "ScanJpegEof",
    "ScanJson",
    "ScanLibarchive",
    "ScanLnk",
    "ScanLsb",
    "ScanLzma",
    "ScanMacho",
    "ScanManifest",
    "ScanMsi",
    "ScanOle",
    "ScanOnenote",
    "ScanPdf",
    "ScanPe",
    "ScanPgp",
    "ScanPhp",
    "ScanPkcs7",
    "ScanPlist",
    "ScanPngEof",
    "ScanPyinstaller",
    "ScanQr",
    "ScanRar",
    "ScanRpm",
    "ScanRtf",
    "ScanSevenZip",
    "ScanSwf",
    "ScanTar",
    "ScanTnef",
    "ScanTranscode",
    "ScanUdf",
    "ScanUpx",
    "ScanUrl",
    "ScanVb",
    "ScanVba",
    "ScanVhd",
    "ScanVsto",
    "ScanXar",
    "ScanXl4ma",
    "ScanXml",
    "ScanYara",
    "ScanZip",
    "ScanZlib",
    "ScanZstd",
]


###################################################################################################
# methods for Malcolm's connection to a data store
class DatabaseMode(enum.IntFlag):
    OpenSearchLocal = enum.auto()
    OpenSearchRemote = enum.auto()
    ElasticsearchRemote = enum.auto()
    DatabaseUnset = enum.auto()


DATABASE_MODE_LABELS = defaultdict(lambda: "")
DATABASE_MODE_ENUMS = defaultdict(lambda: DatabaseMode.DatabaseUnset)
DATABASE_MODE_LABELS[DatabaseMode.OpenSearchLocal] = "opensearch-local"
DATABASE_MODE_LABELS[DatabaseMode.OpenSearchRemote] = "opensearch-remote"
DATABASE_MODE_LABELS[DatabaseMode.ElasticsearchRemote] = "elasticsearch-remote"
DATABASE_MODE_ENUMS["opensearch-local"] = DatabaseMode.OpenSearchLocal
DATABASE_MODE_ENUMS["opensearch-remote"] = DatabaseMode.OpenSearchRemote
DATABASE_MODE_ENUMS["elasticsearch-remote"] = DatabaseMode.ElasticsearchRemote


# Image architecture constants
class ImageArchitecture(Enum):
    AMD64 = "amd64"
    ARM64 = "arm64"


class OrchestrationFramework(Flag):
    UNKNOWN = auto()
    DOCKER_COMPOSE = auto()
    KUBERNETES = auto()


OrchestrationFrameworksSupported = OrchestrationFramework.DOCKER_COMPOSE | OrchestrationFramework.KUBERNETES


class WidgetType(Enum):
    TEXT = auto()
    PASSWORD = auto()
    CHECKBOX = auto()
    RADIO = auto()
    SELECT = auto()
    MULTISELECT = auto()
    DATE = auto()
    TIME = auto()
    DATETIME = auto()
    NUMBER = auto()
    DIRECTORY = auto()


class SettingsFileFormat(Enum):
    JSON = "JSON"
    YAML = "YAML"
    UNKNOWN = "UNKNOWN"
