"""Verify theme bootstrap preserves administrator choices and fails closed."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'keycloak/scripts/configure-login-theme.sh'
pytestmark = pytest.mark.skipif(not shutil.which('jq'), reason='requires jq')


@pytest.fixture
def admin(tmp_path):
    script = tmp_path / 'kcadm'
    script.write_text('#!' + sys.executable + '\n' + '''
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
record = dict(args=args)
if args[0] == 'update':
    record['json'] = json.loads(Path(args[args.index('-f') + 1]).read_text())
with open(os.environ['ADMIN_LOG'], 'a') as f:
    f.write(json.dumps(record) + '\\n')
if args[0] == 'get':
    print(os.environ['REALM_RESPONSE'])
    sys.exit(int(os.environ.get('GET_STATUS', '0')))
sys.exit(int(os.environ.get('UPDATE_STATUS', '0')))
''')
    script.chmod(0o755)
    return script, tmp_path / 'calls.jsonl', tmp_path


def run(admin, response, theme='malcolm', **extra):
    script, log, tmp_path = admin
    result = subprocess.run(
        ['bash', str(SCRIPT), str(script), 'test-realm', theme],
        env=os.environ | {'REALM_RESPONSE': response, 'ADMIN_LOG': str(log), 'TMPDIR': str(tmp_path)} | extra,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    return result, calls


@pytest.mark.parametrize('response', ['{}', '{"loginTheme":null}', '{"loginTheme":""}'])
def test_applies_default_only_to_unset_theme(admin, response):
    result, calls = run(admin, response)
    assert result.returncode == 0, result.stderr
    assert calls[0]['args'] == ['get', 'realms/test-realm', '--fields', 'loginTheme']
    assert calls[1]['args'][:2] == ['update', 'realms/test-realm']
    assert calls[1]['json'] == {'loginTheme': 'malcolm'}
    assert not Path(calls[1]['args'][-1]).exists()


@pytest.mark.parametrize('theme', ['custom-company-theme', 'keycloak.v2', 'keycloak', 'malcolm'])
def test_keeps_explicit_theme(admin, theme):
    result, calls = run(admin, json.dumps({'loginTheme': theme}))
    assert result.returncode == 0
    assert len(calls) == 1


def test_empty_setting_disables_setup(admin):
    result, calls = run(admin, '{}', theme='')
    assert result.returncode == 0
    assert calls == []


@pytest.mark.parametrize('response', ['not json', '[]', 'null', '{"loginTheme":42}', '{"error":"Forbidden"}'])
def test_bad_response_does_not_change_realm(admin, response):
    result, calls = run(admin, response)
    assert result.returncode != 0
    assert len(calls) == 1


def test_failed_get_does_not_change_realm(admin):
    result, calls = run(admin, '{}', GET_STATUS='1')
    assert result.returncode != 0
    assert len(calls) == 1


def test_failed_update_propagates_and_cleans_up(admin):
    result, calls = run(admin, '{}', UPDATE_STATUS='7')
    assert result.returncode == 7
    assert not Path(calls[-1]['args'][-1]).exists()


def test_theme_name_is_encoded_as_json(admin):
    result, calls = run(admin, '{}', theme='custom"theme')
    assert result.returncode == 0
    assert calls[-1]['json'] == {'loginTheme': 'custom"theme'}


def test_theme_inherits_security_sensitive_forms():
    path = ROOT / 'keycloak/themes/malcolm/login'
    props = (path / 'theme.properties').read_text()
    assert 'parent=keycloak.v2' in props
    assert 'styles=css/styles.css css/malcolm.css' in props
    assert not list(path.glob('*.ftl'))
    assert not list(path.rglob('*.js'))
    css = (path / 'resources/css/malcolm.css').read_text()
    assert 'https://' not in css and 'http://' not in css
    assert 'forced-colors' in css
