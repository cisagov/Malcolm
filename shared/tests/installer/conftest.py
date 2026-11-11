"""Setup for the installer tests in shared/tests/installer.

These tests import the installer as the `scripts.installer` package, so the repository root goes
on sys.path. It's appended rather than inserted, so the component source directories that
shared/tests/conftest.py puts first still take precedence for the other tests. This directory goes
on sys.path too, for the installer_mocks helper module.

This also does what the old scripts/installer/tests runners did: the installer's console output
is turned off, unless MALCOLM_INSTALLER_TEST_DEBUG is set (the equivalent of their --debug
option), which leaves it on and turns on debug logging for the installer modules.
"""

import logging
import os
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parents[2]

for path in (str(TESTS_DIR), str(REPO_ROOT)):
    if path not in sys.path:
        sys.path.append(path)

from scripts.installer.utils.logger_utils import InstallerLogger  # noqa: E402

if os.environ.get("MALCOLM_INSTALLER_TEST_DEBUG"):
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
        datefmt="%H:%M:%S",
    )
    for module in ("scripts.installer", "scripts.malcolm_config", "scripts.malcolm_utils"):
        logging.getLogger(module).setLevel(logging.DEBUG)
else:
    InstallerLogger.set_console_output(False)
