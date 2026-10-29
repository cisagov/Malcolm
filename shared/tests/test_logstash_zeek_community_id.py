"""Community ID v1 enrichment in logstash/ruby/zeek_community_id.rb.

The Ruby filter is run as-is under a small harness with a fake Logstash event.
Expected values come from an independent Python implementation of the
Community ID v1 spec, plus the spec's published TCP example. Also checks the
log-type transport map in logstash/maps/zeek_log_transport.yaml.
"""

import base64
import hashlib
import ipaddress
import json
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "logstash" / "ruby" / "zeek_community_id.rb"
TRANSPORT_MAP = ROOT / "logstash" / "maps" / "zeek_log_transport.yaml"

RUBY_HARNESS = r"""
require 'json'

class ZeekCommunityIdFilter
  class_eval(File.read(ARGV[0]), ARGV[0])
end

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

results = JSON.parse(STDIN.read).map do |c|
  script = ZeekCommunityIdFilter.new
  event = FakeEvent.new(c['fields'])
  returned = script.filter(event)
  unless returned.is_a?(Array) && returned.size == 1 && returned[0].equal?(event)
    raise "filter must return [event] for #{c['name']}"
  end
  event.get('[network][community_id]')
end
puts JSON.generate(results)
"""

PROTO_NUMBERS = {"tcp": 6, "udp": 17, "sctp": 132}


def reference_community_id(src_ip, dst_ip, src_port, dst_port, transport, seed=0):
    """Community ID v1, following the corelight community-id.py reference."""
    src = ipaddress.ip_address(src_ip).packed
    dst = ipaddress.ip_address(dst_ip).packed
    if not (src < dst or (src == dst and src_port < dst_port)):
        src, dst, src_port, dst_port = dst, src, dst_port, src_port
    data = (
        struct.pack("!H", seed)
        + src
        + dst
        + struct.pack("BB", PROTO_NUMBERS[transport], 0)
        + struct.pack("!HH", src_port, dst_port)
    )
    return "1:" + base64.b64encode(hashlib.sha1(data).digest()).decode()


def fields(
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    src_port=10,
    dst_port=20,
    transport="tcp",
    community_id=None,
    inferred_transport=None,
):
    return {
        "[source][ip]": src_ip,
        "[destination][ip]": dst_ip,
        "[source][port]": src_port,
        "[destination][port]": dst_port,
        "[network][transport]": transport,
        "[network][community_id]": community_id,
        "[@metadata][inferred_transport]": inferred_transport,
    }


# (name, fields, unused, expected community ID or None)
CASES = [
    ("tcp", fields(), "true", reference_community_id("10.0.0.1", "10.0.0.2", 10, 20, "tcp")),
    (
        "tcp_reversed",
        fields(src_ip="10.0.0.2", dst_ip="10.0.0.1", src_port=20, dst_port=10),
        "true",
        reference_community_id("10.0.0.1", "10.0.0.2", 10, 20, "tcp"),
    ),
    (
        "spec_example_tcp",
        fields(src_ip="128.232.110.120", dst_ip="66.35.250.204", src_port=34855, dst_port=80),
        "true",
        "1:LQU9qZlK+B5F3KDmev6m5PMibrg=",
    ),
    (
        "udp_string_ports",
        fields(src_ip="192.0.2.5", dst_ip="198.51.100.10", src_port="53000", dst_port="53", transport="udp"),
        "true",
        reference_community_id("192.0.2.5", "198.51.100.10", 53000, 53, "udp"),
    ),
    (
        "ipv6",
        fields(src_ip="2001:db8::1", dst_ip="2001:db8::2", src_port=44321, dst_port=443),
        "true",
        reference_community_id("2001:db8::1", "2001:db8::2", 44321, 443, "tcp"),
    ),
    (
        "sctp",
        fields(src_ip="10.10.0.1", dst_ip="10.10.0.2", src_port=5000, dst_port=5001, transport="sctp"),
        "true",
        reference_community_id("10.10.0.1", "10.10.0.2", 5000, 5001, "sctp"),
    ),
    (
        "ascii_singleton_arrays",
        fields(transport=["tcp"], src_port=["10"], dst_port=["20"]),
        "true",
        reference_community_id("10.0.0.1", "10.0.0.2", 10, 20, "tcp"),
    ),
    (
        "same_address_orders_by_port",
        fields(src_ip="127.0.0.1", dst_ip="127.0.0.1", src_port=1234, dst_port=80),
        "true",
        reference_community_id("127.0.0.1", "127.0.0.1", 80, 1234, "tcp"),
    ),
    (
        "inferred_transport_used_when_missing",
        fields(transport=None, inferred_transport="tcp"),
        "true",
        reference_community_id("10.0.0.1", "10.0.0.2", 10, 20, "tcp"),
    ),
    (
        "inferred_transport_used_when_empty_array",
        fields(transport=[], inferred_transport="udp"),
        "true",
        reference_community_id("10.0.0.1", "10.0.0.2", 10, 20, "udp"),
    ),
    (
        "logged_transport_wins_over_inferred",
        fields(transport="udp", inferred_transport="tcp"),
        "true",
        reference_community_id("10.0.0.1", "10.0.0.2", 10, 20, "udp"),
    ),
    ("no_transport_at_all", fields(transport=None), "true", None),
    ("existing_id_preserved", fields(community_id="1:existing"), "true", "1:existing"),
    ("icmp_skipped", fields(transport="icmp"), "true", None),
    ("ambiguous_transport", fields(transport=["tcp", "udp"]), "true", None),
    ("missing_source_ip", fields(src_ip=None), "true", None),
    ("missing_destination_port", fields(dst_port=None), "true", None),
    ("invalid_ip", fields(src_ip="not-an-ip"), "true", None),
    ("cidr_ip", fields(src_ip="10.0.0.0/8"), "true", None),
    ("mixed_ip_families", fields(dst_ip="2001:db8::1"), "true", None),
    ("dash_port", fields(src_port="-"), "true", None),
    ("negative_port", fields(src_port=-1), "true", None),
    ("port_out_of_range", fields(dst_port=65536), "true", None),
]


@pytest.fixture(scope="module")
def ruby_results():
    if shutil.which("ruby") is None:
        pytest.skip("requires ruby")
    payload = [{"name": name, "fields": f} for name, f, _, _ in CASES]
    proc = subprocess.run(
        ["ruby", "-e", RUBY_HARNESS, str(SCRIPT)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return dict(zip((c[0] for c in CASES), json.loads(proc.stdout)))


def test_reference_matches_spec_example():
    assert (
        reference_community_id("128.232.110.120", "66.35.250.204", 34855, 80, "tcp") == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
    )


@pytest.mark.parametrize(("name", "expected"), [(c[0], c[3]) for c in CASES], ids=[c[0] for c in CASES])
def test_community_id(ruby_results, name, expected):
    assert ruby_results[name] == expected


def test_transport_map_values():
    yaml = pytest.importorskip("yaml")
    mapping = yaml.safe_load(TRANSPORT_MAP.read_text(encoding="utf-8"))
    assert mapping, "transport map is empty"
    assert set(mapping.values()) <= set(PROTO_NUMBERS), "unknown transport in map"
