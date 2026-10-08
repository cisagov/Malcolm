"""Test NIC-level network ingest without requiring an OpenSearch deployment."""

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
PIPELINE = ROOT / "logstash/pipelines/beats/11_beats_logs.conf"
MAPPING = ROOT / "dashboards/templates/composable/component/miscbeat.json"
DASHBOARD = ROOT / "dashboards/dashboards/beats/Metricbeat-host-overview.json"

RUBY_TEST_HARNESS = r"""
require 'json'
class TestEvent
  attr_reader :data

  def initialize(data)
    @data = data
  end

  def keys(path)
    path.scan(/\[([^\]]+)\]/).flatten
  end

  def get(path)
    keys(path).reduce(@data) do |value, key|
      value.is_a?(Hash) ? value[key] : nil
    end
  end

  def set(path, value)
    path_keys = keys(path)
    parent = path_keys[0...-1].reduce(@data) do |hash, key|
      hash[key] ||= {}
    end
    parent[path_keys[-1]] = value
  end

  def remove(path)
    path_keys = keys(path)
    parent = path_keys[0...-1].reduce(@data) do |hash, key|
      hash.is_a?(Hash) ? hash[key] : nil
    end
    parent.delete(path_keys[-1]) if parent.is_a?(Hash)
  end

  def clone
    TestEvent.new(Marshal.load(Marshal.dump(@data)))
  end
end

event = TestEvent.new(JSON.parse(STDIN.read))
generated = []
new_event_block = lambda { |new_event| generated << new_event }
eval(ARGV.fetch(0), binding)
puts JSON.generate({'host' => event.data, 'interfaces' => generated.map(&:data)})
"""


def extract_ruby_transform():
    contents = PIPELINE.read_text()
    match = re.search(
        r'id => "ruby_miscbeat_network_details_sum"'
        r'.*?code => "(.*?)"\s+remove_field',
        contents,
        re.DOTALL,
    )
    assert match, "Network Ruby transform not found"
    return match.group(1)


def run_ruby_transform(counters):
    event = {
        "host": {"name": "sensor-01"},
        "event": {"module": "network", "hash": "old-host-hash"},
        "miscbeat": {"network": {"details": counters}},
    }
    proc = subprocess.run(
        ["ruby", "-e", RUBY_TEST_HARNESS, extract_ruby_transform()],
        input=json.dumps(event),
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode:
        raise AssertionError(proc.stderr)
    return json.loads(proc.stdout)


class TestNetworkInterfaceEvents(unittest.TestCase):
    @unittest.skipUnless(shutil.which("ruby"), "Requires Ruby to execute Logstash transform")
    def test_each_interface_has_its_own_counters_and_scope(self):
        out = run_ruby_transform(
            {
                "eth0": {
                    "rx_bytes": 4000,
                    "tx_bytes": 1000,
                    "rx_packets": 40,
                    "tx_packets": 10,
                    "rx_drop": 4,
                    "tx_errs": 2,
                },
                "eth1": {
                    "rx_bytes": 200,
                    "tx_bytes": 900,
                    "rx_packets": 2,
                    "tx_packets": 9,
                    "tx_drop": 1,
                    "rx_errs": 3,
                },
            }
        )
        nic = {e["miscbeat"]["network"]["interface"]: e for e in out["interfaces"]}
        self.assertEqual(set(nic), {"eth0", "eth1"})
        first = nic["eth0"]["miscbeat"]["network"]
        second = nic["eth1"]["miscbeat"]["network"]
        host = out["host"]["miscbeat"]["network"]

        self.assertEqual(host["scope"], "host")
        self.assertNotIn("interface", host)
        self.assertEqual(host["bytes"], {"rx": 4200, "tx": 1900, "total": 6100})
        self.assertEqual(host["packets"], {"rx": 42, "tx": 19, "total": 61})
        self.assertEqual(host["errors"], {"rx": 3, "tx": 2, "total": 5})
        self.assertEqual(host["drops"], {"rx": 4, "tx": 1, "total": 5})

        self.assertEqual(first["bytes"], {"rx": 4000, "tx": 1000, "total": 5000})
        self.assertEqual(second["bytes"], {"rx": 200, "tx": 900, "total": 1100})
        self.assertEqual(first["errors"]["tx"], 2)
        self.assertEqual(second["errors"]["rx"], 3)
        self.assertEqual(first["scope"], "interface")
        self.assertEqual(second["scope"], "interface")
        self.assertEqual(out["host"]["event"]["hash"], "old-host-hash")
        for event in out["interfaces"]:
            self.assertNotIn("hash", event["event"])
            self.assertNotIn("details", event["miscbeat"]["network"])

    @unittest.skipUnless(shutil.which("ruby"), "Requires Ruby")
    def test_zero_and_missing_values_do_not_cross_populate(self):
        out = run_ruby_transform({"eth0": {}, "eth1": {"rx_bytes": 9}})
        self.assertEqual(len(out["interfaces"]), 2)
        self.assertEqual(
            out["interfaces"][0]["miscbeat"]["network"]["bytes"],
            {"rx": 0, "tx": 0, "total": 0},
        )
        self.assertEqual(
            out["interfaces"][1]["miscbeat"]["network"]["bytes"]["rx"], 9
        )
        self.assertEqual(out["host"]["miscbeat"]["network"]["bytes"]["total"], 9)

    @unittest.skipUnless(shutil.which("ruby"), "Requires Ruby")
    def test_invalid_interface_values_are_skipped(self):
        out = run_ruby_transform({"invalid": "not-a-dict", "eth0": {"rx_bytes": "16"}})
        self.assertEqual(len(out["interfaces"]), 1)
        self.assertEqual(out["interfaces"][0]["miscbeat"]["network"]["interface"], "eth0")
        self.assertEqual(out["host"]["miscbeat"]["network"]["bytes"]["rx"], 16)

    def test_distinct_interface_fingerprints(self):
        content = PIPELINE.read_text()
        self.assertIsNotNone(
            re.search(
                r'fingerprint_malcolm_miscbeat_network".*?'
                r'"\[miscbeat\]\[network\]\[interface\]"',
                content,
                re.DOTALL,
            ),
            "Must fingerprint interface name to distinguish equal counters",
        )

    def test_scope_is_keyword_and_drops_chart_splits_per_interface(self):
        mapping = json.loads(MAPPING.read_text())
        fields = mapping["template"]["mappings"]["properties"]["miscbeat"]["properties"]["network"]["properties"]
        self.assertEqual(fields["scope"], {"type": "keyword"})
        self.assertEqual(fields["interface"], {"type": "keyword"})

        export = json.loads(DASHBOARD.read_text())
        chart = next(
            obj
            for obj in export["objects"]
            if obj["id"] == "1a357a70-ebf5-11ec-a044-713f3297b517"
        )
        state = json.loads(chart["attributes"]["visState"])
        for series in state["params"]["series"]:
            self.assertEqual(series["split_mode"], "terms")
            self.assertEqual(series["terms_field"], "miscbeat.network.interface")
        for name in ("Metricbeat-host-overview.json", "Metricbeat-system-overview.json"):
            dashboard = json.loads((DASHBOARD.parent / name).read_text())
            for obj in dashboard["objects"]:
                if obj["type"] != "visualization":
                    continue
                chart = json.loads(obj["attributes"]["visState"])
                if "miscbeat.network.interface" in json.dumps(chart):
                    self.assertEqual(
                        chart["params"]["filter"]["query"],
                        "miscbeat.network.scope:interface",
                        f"Historical host-total documents must not pollute {obj['id']}",
                    )


if __name__ == "__main__":
    unittest.main()
