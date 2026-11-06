"""Exercise the production Ruby NetBox filter without optional gems or a server."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HARNESS = Path(__file__).parent / 'fixtures' / 'netbox_identity_harness.rb'
SCRIPT = ROOT / 'logstash' / 'ruby' / 'netbox_enrich.rb'


def test_netbox_identity_regressions():
    ruby = shutil.which('ruby')
    if ruby is None:
        pytest.skip('requires ruby')
    result = subprocess.run(
        [ruby, str(HARNESS), str(SCRIPT)],
        text=True,
        capture_output=True,
        check=True,
        timeout=90,
    )
    checks = json.loads(result.stdout)
    assert len(checks) == 44
    assert all(checks.values()), checks
