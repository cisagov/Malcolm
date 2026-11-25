"""Regression coverage for index naming when optional settings are absent."""

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / 'logstash/ruby/format_index_string.rb'

RUBY_HARNESS = """
require 'json'
load ARGV[0]

class Event
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

data = JSON.parse(STDIN.read)
register(data['params'])
event = Event.new(data['fields'])
raise 'filter must return its event' unless filter(event) == [event]
puts JSON.generate(event.get(data['params']['target']))
"""


@pytest.mark.parametrize(
    'prefix,suffix,explicit,expected',
    [
        (None, None, {}, 'arkime_sessions3-261125'),
        ('', '', {}, 'arkime_sessions3-261125'),
        (None, '%{%y%m}', {}, 'arkime_sessions3-2611'),
        ('custom-*', None, {}, 'custom-261125'),
        ('custom-*', '{{event.provider}}-%{%y%m%d}', {}, 'custom-zeek-261125'),
        ('custom-*', '%{%y%m}', {'prefix': 'explicit-*', 'suffix': '%{%y}'}, 'explicit-26'),
        ('custom-*', '%{%y%m}', {'prefix': '', 'suffix': ''}, 'arkime_sessions3-261125'),
    ],
)
def test_network_index_defaults(prefix, suffix, explicit, expected):
    ruby = shutil.which('ruby')
    if ruby is None:
        pytest.skip('Ruby interpreter is not installed')
    prefix_env = 'MALCOLM_NETWORK_INDEX_PATTERN'
    suffix_env = 'MALCOLM_NETWORK_INDEX_SUFFIX'
    env = os.environ.copy()
    for key, value in ((prefix_env, prefix), (suffix_env, suffix)):
        env.pop(key, None)
        if value is not None:
            env[key] = value
    params = {
        'prefix_env': prefix_env,
        'prefix_default': 'arkime_sessions3-*',
        'suffix_env': suffix_env,
        'suffix_default': '%{%y%m%d}',
        'target': '[@metadata][malcolm_opensearch_index]',
        **explicit,
    }
    fields = {'[@timestamp]': 1795564800, '[event][provider]': 'Zeek'}
    result = subprocess.run(
        [ruby, '-e', RUBY_HARNESS, str(SCRIPT)],
        input=json.dumps({'params': params, 'fields': fields}),
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == expected
