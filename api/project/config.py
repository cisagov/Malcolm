import os


basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    ARKIME_FIELDS_INDEX = f"{os.getenv('ARKIME_FIELDS_INDEX', 'arkime_fields')}"
    MALCOLM_NETWORK_INDEX_PATTERN = f"{os.getenv('MALCOLM_NETWORK_INDEX_PATTERN', 'arkime_sessions3-*')}"
    MALCOLM_NETWORK_INDEX_TIME_FIELD = f"{os.getenv('MALCOLM_NETWORK_INDEX_TIME_FIELD', 'firstPacket')}"
    MALCOLM_OTHER_INDEX_PATTERN = f"{os.getenv('MALCOLM_OTHER_INDEX_PATTERN', 'malcolm_beats_*')}"
    MALCOLM_OTHER_INDEX_TIME_FIELD = f"{os.getenv('MALCOLM_OTHER_INDEX_TIME_FIELD', '@timestamp')}"
    ARKIME_NETWORK_INDEX_PATTERN = f"{os.getenv('ARKIME_NETWORK_INDEX_PATTERN', 'arkime_sessions3-*')}"
    ARKIME_NETWORK_INDEX_TIME_FIELD = f"{os.getenv('ARKIME_NETWORK_INDEX_TIME_FIELD', 'firstPacket')}"

    ARKIME_SSL = f"{os.getenv('ARKIME_SSL', 'true')}"
    ARKIME_HOST = f"{os.getenv('ARKIME_HOST', 'arkime')}"
    ARKIME_PORT = int(f"{os.getenv('ARKIME_VIEWER_PORT', os.getenv('ARKIME_PORT', '8005'))}".split(':')[-1])
    BUILD_DATE = f"{os.getenv('BUILD_DATE', 'unknown')}"
    DASHBOARDS_URL = f"{os.getenv('DASHBOARDS_URL', 'http://dashboards:5601/dashboards')}"
    DASHBOARDS_HELPER_HOST = f"{os.getenv('DASHBOARDS_HELPER_HOST', 'dashboards-helper')}"
    DASHBOARDS_MAPS_PORT = int(f"{os.getenv('DASHBOARDS_MAPS_PORT', '28991')}")
    DOCTYPE_DEFAULT = f"{os.getenv('DOCTYPE_DEFAULT', 'network')}"
    FILEBEAT_HOST = f"{os.getenv('FILEBEAT_HOST', 'filebeat')}"
    FILEBEAT_TCP_JSON_PORT = int(f"{os.getenv('FILEBEAT_TCP_JSON_PORT', '5045')}")
    FREQ_URL = f"{os.getenv('FREQ_URL', 'http://freq:10004')}"
    LOGSTASH_API_PORT = int(f"{os.getenv('LOGSTASH_API_PORT', '9600')}")
    LOGSTASH_HOST = f"{os.getenv('LOGSTASH_HOST', 'logstash')}"
    LOGSTASH_LJ_PORT = int(f"{os.getenv('LOGSTASH_LJ_PORT', '5044')}")
    MALCOLM_API_DEBUG = f"{os.getenv('MALCOLM_API_DEBUG', 'false')}"
    MALCOLM_API_PREFIX = f"{os.getenv('MALCOLM_API_PREFIX', 'mapi')}"
    MALCOLM_TEMPLATE = f"{os.getenv('MALCOLM_TEMPLATE', 'malcolm_template')}"
    MALCOLM_VERSION = f"{os.getenv('MALCOLM_VERSION', 'unknown')}"
    NETBOX_URL = os.getenv('NETBOX_URL') or 'http://netbox:8080/netbox'
    NETBOX_TOKEN = f"{os.getenv('NETBOX_TOKEN') or os.getenv('SUPERUSER_API_TOKEN', '')}"
    OPENSEARCH_CREDS_CONFIG_FILE = (
        f"{os.getenv('OPENSEARCH_CREDS_CONFIG_FILE', '/var/local/curlrc/.opensearch.primary.curlrc')}"
    )
    OPENSEARCH_PRIMARY = f"{os.getenv('OPENSEARCH_PRIMARY', 'opensearch-local')}"
    OPENSEARCH_SSL_CERTIFICATE_VERIFICATION = f"{os.getenv('OPENSEARCH_SSL_CERTIFICATE_VERIFICATION', 'false')}"
    OPENSEARCH_URL = f"{os.getenv('OPENSEARCH_URL', 'http://opensearch:9200')}"
    PCAP_MONITOR_HOST = f"{os.getenv('PCAP_MONITOR_HOST', 'pcap-monitor')}"
    PCAP_TOPIC_PORT = int(f"{os.getenv('PCAP_TOPIC_PORT', '30441')}")
    RESULT_SET_LIMIT = int(f"{os.getenv('RESULT_SET_LIMIT', '500')}")
    VCS_REVISION = f"{os.getenv('VCS_REVISION', 'unknown')}"
    ZEEK_EXTRACTED_FILE_LOGGER_HOST = f"{os.getenv('ZEEK_EXTRACTED_FILE_LOGGER_HOST', 'file-monitor')}"
    ZEEK_EXTRACTED_FILE_LOGGER_TOPIC_PORT = int(f"{os.getenv('ZEEK_EXTRACTED_FILE_LOGGER_TOPIC_PORT', '5988')}")
    ZEEK_EXTRACTED_FILE_MONITOR_HOST = f"{os.getenv('ZEEK_EXTRACTED_FILE_MONITOR_HOST', 'file-monitor')}"
    ZEEK_EXTRACTED_FILE_TOPIC_PORT = int(f"{os.getenv('ZEEK_EXTRACTED_FILE_TOPIC_PORT', '5987')}")
