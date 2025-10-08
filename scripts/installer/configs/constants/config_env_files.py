#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Environment file constants
"""

ENV_FILE_ARKIME_LIVE = "arkime-live.env"
ENV_FILE_ARKIME_OFFLINE = "arkime-offline.env"
ENV_FILE_ARKIME_SECRET = "arkime-secret.env"
ENV_FILE_ARKIME = "arkime.env"
ENV_FILE_AUTH_COMMON = "auth-common.env"
ENV_FILE_AUTH = "auth.env"
ENV_FILE_BEATS_COMMON = "beats-common.env"
ENV_FILE_DASHBOARDS = "dashboards.env"
ENV_VAR_ACTIONS = "env-var-actions.yml"  # yml file
ENV_FILE_DASHBOARDS_HELPER = "dashboards-helper.env"
ENV_FILE_FILEBEAT = "filebeat.env"
ENV_FILE_KEYCLOAK = "keycloak.env"
ENV_FILE_KUBERNETES_CONTAINER_RESOURCES = (
    "kubernetes-container-resources.yml"  # yml file
)
ENV_FILE_LOGSTASH = "logstash.env"
ENV_FILE_LOOKUP_COMMON = "lookup-common.env"
ENV_FILE_NETBOX_COMMON = "netbox-common.env"
ENV_FILE_NETBOX_SECRET = "netbox-secret.env"
ENV_FILE_NETBOX = "netbox.env"
ENV_FILE_NGINX = "nginx.env"
ENV_FILE_OPENSEARCH = "opensearch.env"
ENV_FILE_PCAP_CAPTURE = "pcap-capture.env"
ENV_FILE_POSTGRES = "postgres.env"
ENV_FILE_PROCESS = "process.env"
ENV_FILE_REDIS = "redis.env"
ENV_FILE_SSL = "ssl.env"
ENV_FILE_SURICATA_LIVE = "suricata-live.env"
ENV_FILE_SURICATA_OFFLINE = "suricata-offline.env"
ENV_FILE_SURICATA = "suricata.env"
ENV_FILE_UPLOAD_COMMON = "upload-common.env"
ENV_FILE_ZEEK_LIVE = "zeek-live.env"
ENV_FILE_ZEEK_OFFLINE = "zeek-offline.env"
ENV_FILE_ZEEK_SECRET = "zeek-secret.env"
ENV_FILE_ZEEK = "zeek.env"


def get_env_files_dict():
    """Get all environment file constants from this module."""
    constants = {}
    # Iterate over globals to find all defined constants in this module
    for key_name, key_value in globals().items():
        # Ensure that we are only processing string values
        if isinstance(key_value, str):
            # Check if the variable name matches the pattern for env files
            if key_name.startswith("ENV_FILE_"):
                constants[key_value] = key_value
    return constants


# A dictionary representation of all environment files, created once at module load.
ALL_ENV_FILES_DICT = get_env_files_dict()
