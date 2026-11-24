"""Exercise YARA ruleset publication failures without starting Strelka."""

import os
from pathlib import Path
import subprocess

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / 'strelka/backend/yara_rules_setup.sh'


@pytest.fixture
def rule_update(tmp_path):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    rules = tmp_path / 'rules'
    rules.mkdir()
    (rules / 'custom').mkdir()
    (rules / 'custom' / 'example.yar').write_text('rule example { condition: true }\n')
    compiled = rules / 'rules.compiled'
    compiled.write_bytes(b'previous rules')

    def stub(name, body):
        executable = bin_dir / name
        executable.write_text('#!/bin/bash\nset -eu\n' + body + '\n')
        executable.chmod(0o755)

    stub(
        'yarac',
        '''
for output in "$@"; do :; done
if [[ "$output" == /dev/null ]]; then exit 0; fi
if [[ "$FAIL_COMPILE" == 1 ]]; then exit 17; fi
printf 'new rules' > "$output"
''',
    )
    stub(
        'mv',
        '''
if [[ "$FAIL_PUBLISH" == 1 ]]; then exit 23; fi
if [[ -e "$6" ]]; then cp "$6" "$6.prev"; fi
/bin/mv -f "$5" "$6"
''',
    )
    stub('yara', 'printf "number of rules: 1\\n"')
    stub('supervisorctl', 'printf "%s\\n" "$*" > "$RESTART_LOG"')
    # Isolate the script's pre-existing fixed statistics scratch path from the host.
    stub('touch', '[[ "$*" == /tmp/dummy ]]')
    stub('rm', '[[ "$*" == "-f /tmp/dummy" ]]')
    restart_log = tmp_path / 'restarted'
    env = {
        **os.environ,
        'PATH': f'{bin_dir}:{os.environ["PATH"]}',
        'RULES_UPDATE_ENABLED': 'false',
        'YARA_CUSTOM_RULES_ONLY': 'true',
        'YARA_COMPILED_RULES_FILE': 'rules.compiled',
        'RESTART_LOG': str(restart_log),
        'FAIL_COMPILE': '0',
        'FAIL_PUBLISH': '0',
    }

    def run(**overrides):
        return subprocess.run(
            ['bash', str(SCRIPT), '-c', '-s', '-r', str(tmp_path / 'source'), '-y', str(rules)],
            env={**env, **overrides},
            capture_output=True,
            text=True,
            timeout=15,
        )

    return run, compiled, restart_log


def test_successful_publication_restarts_scanner(rule_update):
    run, compiled, restart = rule_update
    result = run()
    assert result.returncode == 0, result.stderr
    assert compiled.read_bytes() == b'new rules'
    assert restart.read_text().strip() == 'restart backend:*'
    assert 'Compiled 1 YARA rule files' in result.stdout


@pytest.mark.parametrize('failure, status', [('FAIL_COMPILE', 17), ('FAIL_PUBLISH', 23)])
def test_failed_update_does_not_report_success_or_restart(rule_update, failure, status):
    run, compiled, restart = rule_update
    result = run(**{failure: '1'})
    assert result.returncode == status, result.stderr
    assert compiled.read_bytes() == b'previous rules'
    assert not restart.exists()
    assert 'Compiled 1 YARA rule files' not in result.stdout
