"""Execute the production RFB normalization Ruby against complete and partial records."""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / 'logstash/pipelines/zeek/1300_zeek_normalize.conf'
TARGET = '[network][protocol_version]'


def version_fields(client=None, server=None):
    result = {}
    for side, parts in (('client', client), ('server', server)):
        if parts is not None:
            for name, value in zip(('major', 'minor'), parts):
                if value is not None:
                    result[f'[zeek][rfb][{side}_{name}_version]'] = value
    return result


CASES = [
    ('both', version_fields(('003', '008'), ('003', '008')), ['3.8']),
    ('different', version_fields(('003', '003'), ('003', '008')), ['3.3', '3.8']),
    ('client-only', version_fields(client=('003', '008')), ['3.8']),
    ('server-only', version_fields(server=('003', '008')), ['3.8']),
    ('missing', {}, None),
    ('partial-client', version_fields(('003', None), ('003', '008')), ['3.8']),
    ('partial-server', version_fields(('003', '008'), (None, '008')), ['3.8']),
    ('minor-only', version_fields(client=(None, '008')), None),
    ('all-zero', version_fields(('000', '000'), ('000', '000')), ['0.0']),
    ('zero-minor', version_fields(('003', '000'), ('003', '008')), ['3.0', '3.8']),
    ('unpadded', version_fields(('3', '8'), ('3', '8')), ['3.8']),
    ('placeholder', version_fields(('-', '-'), ('003', '008')), ['3.8']),
    ('empty-strings', version_fields(('', ''), ('003', '008')), ['3.8']),
    ('invalid-strings', version_fields(('3x', '8'), ('003', '008')), ['3.8']),
    ('invalid-types', version_fields((False, []), ('003', '008')), ['3.8']),
    ('existing', {**version_fields(client=('003', '008')), TARGET: ['3.3', '3.8']}, ['3.3', '3.8']),
    ('existing-string', {**version_fields(client=('003', '008')), TARGET: '3.3'}, ['3.3', '3.8']),
    ('existing-only', {TARGET: ['keep']}, ['keep']),
]

HARNESS = r"""
require 'json'
class Event
  attr_reader :fields
  def initialize(fields)
    @fields = fields
  end
  def get(field)
    @fields[field]
  end
  def set(field, value)
    @fields[field] = value
  end
end
payload = JSON.parse(STDIN.read)
results = payload['cases'].map do |name, fields, expected|
  event = Event.new(fields)
  begin
    eval(payload['code'], binding)
    {'name' => name, 'fields' => event.fields}
  rescue StandardError => e
    {'name' => name, 'error' => "#{e.class}: #{e.message}"}
  end
end
puts JSON.generate(results)
"""


@pytest.fixture(scope='module')
def processed():
    ruby = shutil.which('ruby')
    if not ruby:
        pytest.skip('Ruby is required to execute the Logstash filter code')
    match = re.search(
        r'id => "ruby_zeek_field_network_protocol_version_rfb".*?code => \'(.*?)\'',
        CONFIG.read_text(),
        re.S,
    )
    assert match, 'RFB normalization code not found'
    result = subprocess.run(
        [ruby, '-e', HARNESS],
        input=json.dumps({'code': match.group(1), 'cases': CASES}),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return {item['name']: item for item in json.loads(result.stdout)}


@pytest.mark.parametrize('name,fields,expected', CASES, ids=[item[0] for item in CASES])
def test_versions_are_normalized_without_changing_source(processed, name, fields, expected):
    result = processed[name]
    assert 'error' not in result, result
    assert result['fields'].get(TARGET) == expected
    for field, original in fields.items():
        if field != TARGET:
            assert result['fields'][field] == original
