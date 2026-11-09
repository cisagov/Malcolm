"""Check canonical Zeek user-agent mappings and optional real Logstash processing.

Set LOGSTASH_TEST_IMAGE to the image used by Dockerfiles/logstash.Dockerfile
(e.g. docker.elastic.co/logstash/logstash-oss:9.5.6) to run the event tests.
The image must already be available locally. No network access is required.
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PROTOCOLS = ('gquic', 'http', 'sip', 'smtp', 'websocket')
ARKIME_FIELDS = {'gquic': ('quic', 'useragent'), 'http': ('http', 'useragent'), 'smtp': ('email', 'useragent')}


def cases():
    result = []
    for protocol in PROTOCOLS:
        for variant in ('string', 'array', 'existing'):
            incoming = ['agent-one', 'agent-two'] if variant == 'array' else 'agent-one'
            event = {'case_id': f'{protocol}-{variant}', 'zeek': {protocol: {'user_agent': incoming, 'other': 'keep'}}}
            expected = incoming
            if variant == 'existing':
                event['user_agent'] = {'original': 'existing-agent', 'name': 'keep-name'}
                expected = ['existing-agent', 'agent-one']
            result.append((event, protocol, incoming, expected))
    result += [
        ({'case_id': 'missing', 'zeek': {'http': {'other': 'keep'}}}, None, None, None),
        ({'case_id': 'unrelated', 'zeek': {'custom': {'user_agent': 'keep'}}}, None, None, None),
        ({'case_id': 'existing-only', 'user_agent': {'original': 'keep'}}, None, None, 'keep'),
        (
            {'case_id': 'combined', 'zeek': {'http': {'user_agent': 'browser'}, 'smtp': {'user_agent': 'mailer'}}},
            None,
            None,
            ['browser', 'mailer'],
        ),
        (
            {
                'case_id': 'existing-array',
                'user_agent': {'original': ['existing-one', 'existing-two']},
                'zeek': {'sip': {'user_agent': ['agent-one', 'agent-two']}},
            },
            'sip',
            ['agent-one', 'agent-two'],
            ['existing-one', 'existing-two', 'agent-one', 'agent-two'],
        ),
    ]
    return result


CASES = cases()


def affected_filters():
    mutation = (ROOT / 'logstash/pipelines/zeek/1200_zeek_mutate.conf').read_text()
    normalization = (ROOT / 'logstash/pipelines/zeek/1300_zeek_normalize.conf').read_text()
    compatibility = []
    for protocol in ARKIME_FIELDS:
        match = re.search(r'    if \(\[zeek\]\[' + protocol + r'\]\[user_agent\]\) \{.*?\n    \}', mutation, re.S)
        assert match, f'Missing Arkime compatibility filter for {protocol}'
        compatibility.append(match.group())
    start = normalization.index('  # User agents #####')
    end = normalization.index('  # Hashes #####', start)
    section = normalization[start:end]
    # Reapply the normalization alone, with unique plugin IDs, to check idempotence.
    repeated = section.replace('ecs_useragent_', 'ecs_useragent_repeat_')
    return '\n'.join(compatibility) + '\n' + section + '\n' + repeated


@pytest.fixture(scope='module')
def processed(tmp_path_factory):
    image = os.getenv('LOGSTASH_TEST_IMAGE')
    if not image:
        pytest.skip('set LOGSTASH_TEST_IMAGE to run the real Logstash event tests')
    if not shutil.which('docker'):
        pytest.skip('Docker is required for the Logstash event tests')
    directory = tmp_path_factory.mktemp('user-agent-logstash')
    directory.chmod(0o755)
    pipeline = directory / 'pipeline.conf'
    pipeline.write_text(
        'input { stdin { codec => json_lines { ecs_compatibility => disabled } } }\n'
        'filter {\n' + affected_filters() + '\n}\n'
        'output { stdout { codec => json_lines } }\n'
    )
    command = [
        'docker',
        'run',
        '--rm',
        '-i',
        '--network=none',
        '--pull=never',
        '--memory=1g',
        '--cpus=2',
        '-e',
        'LS_JAVA_OPTS=-Xms256m -Xmx512m',
        '-v',
        f'{directory}:/test:ro',
        image,
        '-f',
        '/test/pipeline.conf',
        '--pipeline.workers',
        '1',
        '--pipeline.ordered',
        'true',
        '--log.level',
        'error',
        '--api.enabled',
        'false',
    ]
    result = subprocess.run(
        command,
        input=''.join(json.dumps(case[0]) + '\n' for case in CASES),
        text=True,
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    records = {}
    for line in result.stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and 'case_id' in event:
            records[event['case_id']] = event
    assert set(records) == {case[0]['case_id'] for case in CASES}, result.stdout + result.stderr
    return records


@pytest.mark.parametrize('case', CASES, ids=[case[0]['case_id'] for case in CASES])
def test_actual_filters_preserve_values_and_remove_duplicates(processed, case):
    event, protocol, incoming, expected = case
    output = processed[event['case_id']]
    assert output.get('user_agent', {}).get('original') == expected
    assert not any('failure' in tag or 'exception' in tag for tag in output.get('tags', []))
    for name in PROTOCOLS:
        assert 'user_agent' not in output.get('zeek', {}).get(name, {})
    if protocol in ARKIME_FIELDS:
        parent, field = ARKIME_FIELDS[protocol]
        assert output[parent][field] == (incoming if isinstance(incoming, list) else [incoming])
    if event['case_id'] == 'unrelated':
        assert output['zeek']['custom']['user_agent'] == 'keep'
    if protocol and 'other' in event['zeek'][protocol]:
        assert output['zeek'][protocol]['other'] == 'keep'
    if 'name' in event.get('user_agent', {}):
        assert output['user_agent']['name'] == 'keep-name'


@pytest.mark.parametrize('protocol', PROTOCOLS)
def test_template_no_longer_maps_duplicate_field(protocol):
    data = json.loads((ROOT / 'dashboards/templates/composable/component/zeek.json').read_text())
    assert 'user_agent' not in data['template']['mappings']['properties']['zeek']['properties'][protocol]['properties']


@pytest.mark.parametrize('protocol', PROTOCOLS)
def test_arkime_views_use_the_canonical_field(protocol):
    config = (ROOT / 'arkime/etc/config.ini').read_text()
    fields = (ROOT / 'arkime/wise/source.zeeklogs.js').read_text()
    assert f'zeek.{protocol}.user_agent' not in config
    assert f'"zeek.{protocol}.user_agent"' not in fields
    view = next(line for line in config.splitlines() if line.startswith(f'o_zeek_{protocol}='))
    assert 'user_agent.original' in view.split('fields:', 1)[1].split(',')
    assert fields.count('      "user_agent.original",') == 1


def test_bundled_dashboards_do_not_reference_removed_fields():
    for path in (ROOT / 'dashboards/dashboards').rglob('*.json'):
        content = path.read_text()
        assert all(f'zeek.{protocol}.user_agent' not in content for protocol in PROTOCOLS), str(path)
