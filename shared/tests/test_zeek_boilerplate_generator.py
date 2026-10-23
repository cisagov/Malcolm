"""Offline parser/output regressions for Zeek-to-Malcolm boilerplate generation.

zeekscript/python-slugify are optional developer-script dependencies; the
standard Malcolm shared test suite does not need them for normal ingestion.
"""

import json
from pathlib import Path
import subprocess
import sys

import pytest

pytest.importorskip('zeekscript')
pytest.importorskip('slugify')

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/zeek_script_to_malcolm_boilerplate.py'


def zeek_file(tmp_path, namespace, path, *, include_conn_id=True):
    name = f'{namespace.lower()}.zeek'
    conn = 'id: conn_id &log;' if include_conn_id else ''
    script = tmp_path / name
    script.write_text(
        f'''module {namespace};
export {{
  redef enum Log::ID += {{ EXAMPLE_LOG }};
  type Info: record {{
    ts: time &log;
    {conn}
    payload: string &log;
    secret: string &optional;
  }};
}}
event zeek_init() {{
  Log::create_stream({namespace}::EXAMPLE_LOG, [$columns={namespace}::Info, $path="{path}"]);
}}
'''
    )
    return script


def generate(tmp_path, sources, *extra):
    files = [str(tmp_path / name) for name in ('out.conf', 'out.ini', 'out.json', 'records.json')]
    cmd = [
        sys.executable,
        str(SCRIPT),
        '--input',
        *[str(path) for path in sources],
        '--logstash',
        files[0],
        '--arkime',
        files[1],
        '--index',
        files[2],
        '--json',
        files[3],
        '--proto',
        'tcp',
        '--service',
        'test_service',
        *extra,
    ]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=35)
    assert proc.returncode == 0, proc.stderr
    return (
        Path(files[0]).read_text(),
        Path(files[1]).read_text(),
        json.loads(Path(files[2]).read_text()),
        json.loads(Path(files[3]).read_text()),
    )


def test_single_script_resolves_stream_and_logged_fields(tmp_path):
    source = zeek_file(tmp_path, 'Foo', 'foo')
    logstash, arkime, index, data = generate(tmp_path, [source])
    assert '[log_source] == "foo"' in logstash
    assert '[zeek_cols][payload]' in logstash
    assert '[zeek_cols][secret]' not in logstash
    assert '# foo.zeek ' in logstash
    assert '"[zeek_cols][proto]" => "tcp"' in logstash
    assert 'zeek.foo.payload=' in arkime
    assert index['template']['mappings']['properties']['zeek']['properties']['foo']['properties']['payload'] == {'type': 'keyword'}
    assert len(data['records']) == 1
    assert [field['name'] for field in data['records'][0]['fields']] == [
        'ts', 'orig_h', 'orig_p', 'resp_h', 'resp_p', 'payload'
    ]


def test_two_modules_with_same_info_record_are_distinct(tmp_path):
    first = zeek_file(tmp_path, 'Alpha', 'alpha-log')
    second = zeek_file(tmp_path, 'Beta', 'beta-log')
    logstash, arkime, index, data = generate(tmp_path, [first, second])
    assert logstash.count('if ([log_source] == "alpha_log")') == 1
    assert logstash.count('if ([log_source] == "beta_log")') == 1
    assert '# alpha.zeek ' in logstash
    assert '# beta.zeek ' in logstash
    assert {record['path'] for record in data['records']} == {'alpha_log', 'beta_log'}
    assert 'zeek.alpha_log.payload=' in arkime
    assert 'zeek.beta_log.payload=' in arkime
    assert set(index['template']['mappings']['properties']['zeek']['properties']) == {'alpha_log', 'beta_log'}


def test_input_order_does_not_relabel_sources(tmp_path):
    first = zeek_file(tmp_path, 'Alpha', 'alpha-log')
    second = zeek_file(tmp_path, 'Beta', 'beta-log')
    logstash, _, _, _ = generate(tmp_path, [second, first])
    alpha = logstash.index('if ([log_source] == "alpha_log")')
    beta = logstash.index('if ([log_source] == "beta_log")')
    assert '# alpha.zeek ' in logstash[alpha:alpha + 250]
    assert '# beta.zeek ' in logstash[beta:beta + 250]


def test_no_expand_id_preserves_conn_id_column(tmp_path):
    script = zeek_file(tmp_path, 'Alpha', 'alpha')
    logstash, _, _, data = generate(tmp_path, [script], '--no-expand-id')
    assert '[zeek_cols][id]' in logstash
    assert '[zeek_cols][orig_h]' not in logstash
    assert 'id' in [field['name'] for field in data['records'][0]['fields']]


def test_no_input_generates_empty_outputs_without_crashing(tmp_path):
    logstash, arkime, index, data = generate(tmp_path, [])
    assert logstash.startswith('filter {')
    assert not data['records']
    assert index['template']['mappings']['properties'] == {}
    assert '[custom-views]' in arkime


def test_real_bundled_zeek_scripts_keep_separate_log_paths(tmp_path):
    sources = [ROOT / 'zeek/config/login.zeek', ROOT / 'zeek/config/guess.zeek']
    logstash, _, _, data = generate(tmp_path, sources)
    assert logstash.count('if ([log_source] == "login")') == 1
    assert logstash.count('if ([log_source] == "bestguess")') == 1
    assert {record['path'] for record in data['records'] if record['fields']} == {'login', 'bestguess'}


def test_stream_mapping_declared_in_another_script(tmp_path):
    record_script = tmp_path / 'record.zeek'
    record_script.write_text(
        'module Sensor;\nexport { type Info: record { ts: time &log; value: count &log; }; }\n'
    )
    stream_script = tmp_path / 'stream.zeek'
    stream_script.write_text(
        'module Sensor;\nevent zeek_init() { Log::create_stream(Sensor::LOG, [$columns=Sensor::Info, $path="sensor-events"]); }\n'
    )
    logstash, arkime, index, data = generate(tmp_path, [record_script, stream_script])
    assert logstash.count('if ([log_source] == "sensor_events")') == 1
    assert 'zeek.sensor_events.value=' in arkime
    assert index['template']['mappings']['properties']['zeek']['properties']['sensor_events']['properties']['value'] == {'type': 'long'}
    assert len([record for record in data['records'] if record['fields']]) == 1


def test_record_json_has_no_internal_source_metadata(tmp_path):
    zeek = zeek_file(tmp_path, 'Alpha', 'alpha')
    _, _, _, data = generate(tmp_path, [zeek])
    assert set(data['records'][0]) == {'name', 'path', 'fields'}
