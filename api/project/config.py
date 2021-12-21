import os


basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
  OPENSEARCH_URL = f"{os.getenv('OPENSEARCH_URL', 'http://opensearch:9200')}"
  MALCOLM_VERSION = f"{os.getenv('MALCOLM_VERSION', 'unknown')}"
  BUILD_DATE = f"{os.getenv('BUILD_DATE', 'unknown')}"
  VCS_REVISION = f"{os.getenv('VCS_REVISION', 'unknown')}"
