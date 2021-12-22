import os


basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    ARKIME_INDEX_PATTERN = f"{os.getenv('ARKIME_INDEX_PATTERN', 'arkime_sessions3-*')}"
    ARKIME_INDEX_TIME_FIELD = f"{os.getenv('ARKIME_INDEX_TIME_FIELD', 'firstPacket')}"
    BUILD_DATE = f"{os.getenv('BUILD_DATE', 'unknown')}"
    MALCOLM_VERSION = f"{os.getenv('MALCOLM_VERSION', 'unknown')}"
    OPENSEARCH_URL = f"{os.getenv('OPENSEARCH_URL', 'http://opensearch:9200')}"
    RESULT_SET_LIMIT = int(f"{os.getenv('RESULT_SET_LIMIT', '1000')}")
    VCS_REVISION = f"{os.getenv('VCS_REVISION', 'unknown')}"
