"""Validate NIC-level panels in the Packet Capture Statistics dashboard."""

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
EXPORT = ROOT / "dashboards/dashboards/beats/4ca94c70-d7da-11ee-9ed3-e7afff29e59a.json"

NIC_PANELS = {
    "1a357a70-ebf5-11ec-a044-713f3297b517": "Network Traffic (Drops and Errors)",
    "99381c80-4d60-11e7-9a4c-ed99bbcaa42b": "Interfaces by Incoming traffic",
    "c5e3cf90-4d60-11e7-9a4c-ed99bbcaa42b": "Interfaces by Outgoing traffic",
}
TRAFFIC_PANELS = {
    "6b7b9a40-faa1-11e6-86b1-cd7735ff7e23": "Network Traffic (Packets)",
    "089b85d0-1b16-11e7-b09e-037021c4f8df": "Network Traffic (Bytes)",
}


class TestPacketCaptureNetworkDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.content = json.loads(EXPORT.read_text(encoding="utf-8"))
        cls.dashboard = next(
            obj for obj in cls.content["objects"] if obj["type"] == "dashboard"
        )
        cls.panels = json.loads(cls.dashboard["attributes"]["panelsJSON"])
        cls.refs = cls.dashboard["references"]
        cls.objects = {obj["id"]: obj for obj in cls.content["objects"]}

    def test_all_dashboard_panels_have_unique_refs_and_objects(self):
        ref_names = [ref["name"] for ref in self.refs]
        panel_names = [panel["panelRefName"] for panel in self.panels]
        panel_ids = [panel["panelIndex"] for panel in self.panels]
        self.assertEqual(len(self.panels), 22)
        self.assertEqual(len(self.panels), len(self.refs))
        self.assertEqual(len(ref_names), len(set(ref_names)))
        self.assertEqual(len(panel_names), len(set(panel_names)))
        self.assertEqual(len(panel_ids), len(set(panel_ids)))
        self.assertEqual(set(panel_names), set(ref_names))
        for ref in self.refs:
            with self.subTest(ref=ref["name"]):
                self.assertIn(ref["id"], self.objects)
                self.assertEqual(self.objects[ref["id"]]["type"], ref["type"])

    def test_new_network_panels_have_correct_references_and_titles(self):
        refs_by_id = {ref["id"]: ref for ref in self.refs}
        for panel_id, title in NIC_PANELS.items():
            with self.subTest(panel_id=panel_id):
                self.assertEqual(self.objects[panel_id]["attributes"]["title"], title)
                self.assertIn(panel_id, refs_by_id)
                self.assertEqual(refs_by_id[panel_id]["type"], "visualization")

    def test_each_nic_chart_uses_only_true_interface_events(self):
        for panel_id in set(NIC_PANELS) | set(TRAFFIC_PANELS):
            with self.subTest(panel=panel_id):
                vis = json.loads(self.objects[panel_id]["attributes"]["visState"])
                self.assertEqual(
                    vis["params"]["filter"],
                    {"language": "lucene", "query": "miscbeat.network.scope:interface"},
                )
                self.assertTrue(vis["params"]["series"])
                self.assertTrue(
                    any(
                        series.get("terms_field") == "miscbeat.network.interface"
                        for series in vis["params"]["series"]
                    )
                )

    def test_drops_and_errors_show_rx_tx_by_interface(self):
        panel = self.objects["1a357a70-ebf5-11ec-a044-713f3297b517"]
        chart = json.loads(panel["attributes"]["visState"])
        fields = set()
        for series in chart["params"]["series"]:
            self.assertEqual(series["split_mode"], "terms")
            self.assertEqual(series["terms_field"], "miscbeat.network.interface")
            for metric in series["metrics"]:
                if metric.get("field"):
                    fields.add(metric["field"])
        self.assertEqual(
            fields,
            {
                "miscbeat.network.drops.rx",
                "miscbeat.network.drops.tx",
                "miscbeat.network.errors.rx",
                "miscbeat.network.errors.tx",
            },
        )

    def test_new_panels_do_not_overlap_existing_and_fit_grid(self):
        new_refs = {ref["name"] for ref in self.refs if ref["id"] in NIC_PANELS}
        existing = [panel for panel in self.panels if panel["panelRefName"] not in new_refs]
        added = [panel for panel in self.panels if panel["panelRefName"] in new_refs]
        self.assertEqual(len(added), 3)

        def overlaps(a, b):
            a, b = a["gridData"], b["gridData"]
            return (
                a["x"] < b["x"] + b["w"]
                and b["x"] < a["x"] + a["w"]
                and a["y"] < b["y"] + b["h"]
                and b["y"] < a["y"] + a["h"]
            )

        for panel in added:
            grid = panel["gridData"]
            self.assertGreaterEqual(grid["x"], 0)
            self.assertGreaterEqual(grid["y"], 155)
            self.assertLessEqual(grid["x"] + grid["w"], 48)
            self.assertFalse(any(overlaps(panel, other) for other in existing))
        self.assertFalse(any(overlaps(added[i], added[j]) for i in range(3) for j in range(i + 1, 3)))


if __name__ == "__main__":
    unittest.main()
