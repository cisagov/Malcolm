"""Put each component's source directory on sys.path for the tests in shared/tests."""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# highest precedence first
SOURCE_DIRS = (
    REPO_ROOT / 'zeek' / 'scripts',
    REPO_ROOT / 'shared' / 'bin',
    REPO_ROOT / 'scripts',
    REPO_ROOT / 'filescan' / 'python-filescan',
    REPO_ROOT / 'dashboards' / 'scripts',
    REPO_ROOT / 'api',
)

sys.path[0:0] = [str(p) for p in SOURCE_DIRS if str(p) not in sys.path]
