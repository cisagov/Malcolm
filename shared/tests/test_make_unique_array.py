"""Exercise the Logstash unique-array filter with its configured aliases."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'logstash/ruby/make_unique_array.rb'

RUBY_HARNESS = """
def test(*args); end

class FakeEvent
  def initialize(fields)
    @fields = fields
  end

  def get(key)
    @fields[key]
  end

  def set(key, value)
    @fields[key] = value
  end
end

require 'json'
load ARGV[0]
cases = JSON.parse(STDIN.read)
result = cases.map do |params, fields|
  register(params)
  event = FakeEvent.new(fields)
  raise 'filter must return the input event' unless filter(event) == [event]
  event.get(params['field'])
end
puts JSON.generate(result)
"""


def test_unique_values_after_protocol_translation():
    ruby = shutil.which('ruby')
    if ruby is None:
        pytest.skip('Ruby interpreter is not installed')
    field = '[network][protocol]'
    # The aliases and prune setting match the Zeek and Suricata pipelines.
    suricata = {
        'field': field,
        'prune': 'failed',
        'translate': {'dcerpc': 'dce_rpc', 'ftp-data': 'ftp', 'krb5': 'krb'},
    }
    zeek = {
        'field': field,
        'translate': {'ftp_data': 'ftp', 'rdpeudp': 'rdp', 'tftp_data': 'tftp'},
    }
    cases = [
        (suricata, {field: ['ftp-data', 'failed', 'ftp', 'dcerpc', 'dce_rpc', 'dns', 'dns']}),
        (zeek, {field: ['ftp', 'ftp_data', 'rdpeudp', 'rdp', 'tftp_data', 'tftp']}),
        ({'field': field, 'translate': {'a': 'c', 'b': 'c'}}, {field: ['b', 'a', 'c', 'd']}),
        (suricata, {field: 'krb5'}),
        (suricata, {field: ['failed', 'failed']}),
        ({'field': field}, {field: ['dns', 'dns', 'http']}),
        ({'field': field}, {}),
    ]
    expected = [
        ['ftp', 'dce_rpc', 'dns'],
        ['ftp', 'rdp', 'tftp'],
        ['c', 'd'],
        ['krb'],
        [],
        ['dns', 'http'],
        None,
    ]
    result = subprocess.run(
        [ruby, '-e', RUBY_HARNESS, str(SCRIPT)],
        input=json.dumps(cases),
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    assert json.loads(result.stdout) == expected
