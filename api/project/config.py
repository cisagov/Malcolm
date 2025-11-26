import os


basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    ARKIME_FIELDS_INDEX = os.getenv('ARKIME_FIELDS_INDEX', 'arkime_fields')
    MALCOLM_NETWORK_INDEX_PATTERN = os.getenv('MALCOLM_NETWORK_INDEX_PATTERN', 'arkime_sessions3-*')
    MALCOLM_NETWORK_INDEX_TIME_FIELD = os.getenv('MALCOLM_NETWORK_INDEX_TIME_FIELD', 'firstPacket')
    MALCOLM_OTHER_INDEX_PATTERN = os.getenv('MALCOLM_OTHER_INDEX_PATTERN', 'malcolm_beats_*')
    MALCOLM_OTHER_INDEX_TIME_FIELD = os.getenv('MALCOLM_OTHER_INDEX_TIME_FIELD', '@timestamp')
    ARKIME_NETWORK_INDEX_PATTERN = os.getenv('ARKIME_NETWORK_INDEX_PATTERN', 'arkime_sessions3-*')
    ARKIME_NETWORK_INDEX_TIME_FIELD = os.getenv('ARKIME_NETWORK_INDEX_TIME_FIELD', 'firstPacket')
    ARKIME_STATS_INDEX_PATTERN = "arkime_stats_*"

    ARKIME_SSL = os.getenv('ARKIME_SSL', 'true')
    ARKIME_HOST = os.getenv('ARKIME_HOST', 'arkime')
    ARKIME_PORT = int(os.getenv('ARKIME_VIEWER_PORT', os.getenv('ARKIME_PORT', '8005')).split(':')[-1])
    BUILD_DATE = os.getenv('BUILD_DATE', 'unknown')
    DASHBOARDS_URL = os.getenv('DASHBOARDS_URL', 'http://dashboards:5601/dashboards')
    DASHBOARDS_HELPER_HOST = os.getenv('DASHBOARDS_HELPER_HOST', 'dashboards-helper')
    DASHBOARDS_MAPS_PORT = int(os.getenv('DASHBOARDS_MAPS_PORT', '28991'))
    DOCTYPE_DEFAULT = os.getenv('DOCTYPE_DEFAULT', 'network')
    FILEBEAT_HOST = os.getenv('FILEBEAT_HOST', 'filebeat')
    FILEBEAT_TCP_JSON_PORT = int(os.getenv('FILEBEAT_TCP_JSON_PORT', '5045'))
    FREQ_URL = os.getenv('FREQ_URL', 'http://freq:10004')
    LOGSTASH_API_PORT = int(os.getenv('LOGSTASH_API_PORT', '9600'))
    LOGSTASH_HOST = os.getenv('LOGSTASH_HOST', 'logstash')
    LOGSTASH_LJ_PORT = int(os.getenv('LOGSTASH_LJ_PORT', '5044'))
    MALCOLM_API_DEBUG = os.getenv('MALCOLM_API_DEBUG', 'false')
    MALCOLM_API_PREFIX = os.getenv('MALCOLM_API_PREFIX', 'mapi')
    MALCOLM_TEMPLATE = os.getenv('MALCOLM_TEMPLATE', 'malcolm_template')
    MALCOLM_VERSION = os.getenv('MALCOLM_VERSION', 'unknown')
    NETBOX_URL = os.getenv('NETBOX_URL') or 'http://netbox:8080/netbox'
    NETBOX_TOKEN = os.getenv('NETBOX_TOKEN') or os.getenv('SUPERUSER_API_TOKEN', '')
    OPENSEARCH_CREDS_CONFIG_FILE = os.getenv(
        'OPENSEARCH_CREDS_CONFIG_FILE', '/var/local/curlrc/.opensearch.primary.curlrc'
    )
    OPENSEARCH_PRIMARY = os.getenv('OPENSEARCH_PRIMARY', 'opensearch-local')
    OPENSEARCH_SSL_CERTIFICATE_VERIFICATION = os.getenv('OPENSEARCH_SSL_CERTIFICATE_VERIFICATION', 'false')
    OPENSEARCH_URL = os.getenv('OPENSEARCH_URL', 'https://opensearch:9200')
    PCAP_MONITOR_HOST = os.getenv('PCAP_MONITOR_HOST', 'pcap-monitor')
    PCAP_TOPIC_PORT = int(os.getenv('PCAP_TOPIC_PORT', '30441'))
    RESULT_SET_LIMIT = int(os.getenv('RESULT_SET_LIMIT', '500'))
    VCS_REVISION = os.getenv('VCS_REVISION', 'unknown')

    # TODO: filescan/strelka
    # ZEEK_EXTRACTED_FILE_LOGGER_HOST = os.getenv('ZEEK_EXTRACTED_FILE_LOGGER_HOST', 'file-monitor')
    # ZEEK_EXTRACTED_FILE_LOGGER_TOPIC_PORT = int(os.getenv('ZEEK_EXTRACTED_FILE_LOGGER_TOPIC_PORT', '5988'))
    # ZEEK_EXTRACTED_FILE_MONITOR_HOST = os.getenv('ZEEK_EXTRACTED_FILE_MONITOR_HOST', 'file-monitor')
    # ZEEK_EXTRACTED_FILE_TOPIC_PORT = int(os.getenv('ZEEK_EXTRACTED_FILE_TOPIC_PORT', '5987'))

    ROLE_BASED_ACCESS = os.getenv('ROLE_BASED_ACCESS', 'false')
    ROLE_ADMIN = os.getenv('ROLE_ADMIN', '')
    ROLE_READ_ACCESS = os.getenv('ROLE_READ_ACCESS', '')
    ROLE_READ_WRITE_ACCESS = os.getenv('ROLE_READ_WRITE_ACCESS', '')
    ROLE_DASHBOARDS_READ_ACCESS = os.getenv('ROLE_DASHBOARDS_READ_ACCESS', '')
    ROLE_DASHBOARDS_READ_ALL_APPS_ACCESS = os.getenv('ROLE_DASHBOARDS_READ_ALL_APPS_ACCESS', '')
    ROLE_DASHBOARDS_READ_WRITE_ACCESS = os.getenv('ROLE_DASHBOARDS_READ_WRITE_ACCESS', '')
    ROLE_DASHBOARDS_READ_WRITE_ALL_APPS_ACCESS = os.getenv('ROLE_DASHBOARDS_READ_WRITE_ALL_APPS_ACCESS', '')
    ROLE_NETBOX_READ_ACCESS = os.getenv('ROLE_NETBOX_READ_ACCESS', '')
    ROLE_NETBOX_READ_WRITE_ACCESS = os.getenv('ROLE_NETBOX_READ_WRITE_ACCESS', '')
    ROLE_UPLOAD = os.getenv('ROLE_UPLOAD', '')
