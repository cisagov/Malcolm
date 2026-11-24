# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""Offline regression tests for the enrichment snapshot tool."""

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts import benchmark_enrichment as bench


def fake_stats(duration=500, count=1000):
    return json.dumps(
        {
            "pipelines": {
                "log-enrichment": {
                    "events": {"in": count, "out": count},
                    "plugins": {
                        "filters": [
                            {
                                "id": "ruby_netbox_enrich",
                                "events": {
                                    "in": count,
                                    "out": count,
                                    "duration_in_millis": duration,
                                },
                            }
                        ]
                    },
                },
                "zeek-parse": {
                    "events": {"in": count, "out": count},
                    "plugins": {"filters": []},
                },
            }
        }
    )


class ParseStatisticsTests(unittest.TestCase):
    def test_du_kibibytes_converted_to_allocated_bytes(self):
        self.assertEqual(
            2048 * 1024, bench.parse_storage_bytes("2048\t/usr/share/opensearch/data\n")
        )

    def test_invalid_du_response_rejected(self):
        for output in ("", "oops", "-1\t/data", "12", "7\t/data\n8\t/other"):
            with self.subTest(output=output), self.assertRaises(bench.BenchmarkError):
                bench.parse_storage_bytes(output)

    def test_filter_stats_and_pipeline_events_extracted(self):
        filters, pipelines = bench.parse_logstash_stats(fake_stats())
        self.assertEqual(1, len(filters))
        self.assertEqual("ruby_netbox_enrich", filters[0]["id"])
        self.assertEqual(500, filters[0]["duration_ms"])
        self.assertEqual(1000, filters[0]["in"])
        self.assertEqual(2, len(pipelines))
        self.assertEqual("log-enrichment", pipelines[0]["name"])

    def test_bad_json_and_counters_rejected(self):
        for payload in (
            "not json",
            "{}",
            '{"pipelines": {"a": {"plugins": {"filters": []}, "events": {"in": -1}}}}',
            '{"pipelines": {"a": {"plugins": {"filters": [{"id": "f", "events": {"in": true}}]}}}}',
            '{"pipelines": {"a": {"plugins": {"filters": ["broken"]}}}}',
        ):
            with self.subTest(payload=payload), self.assertRaises(bench.BenchmarkError):
                bench.parse_logstash_stats(payload)

    def test_missing_duration_and_zero_events_no_rate(self):
        filters, _ = bench.parse_logstash_stats(
            '{"pipelines": {"a": {"plugins": {"filters": [{"id": "f", "events": {}}]}}}}'
        )
        self.assertEqual(0, filters[0]["duration_ms"])
        self.assertIsNone(bench.per_thousand_events(filters[0]))

    def test_duration_rate(self):
        self.assertAlmostEqual(
            250.0, bench.per_thousand_events({"in": 2000, "duration_ms": 500})
        )


class CaptureTests(unittest.TestCase):
    @mock.patch.object(bench.subprocess, "run")
    def test_snapshot_reads_only_two_running_services(self, run):
        run.side_effect = [
            SimpleNamespace(stdout="2048\t/usr/share/opensearch/data\n"),
            SimpleNamespace(stdout=fake_stats()),
        ]
        result = bench.take_snapshot(Path("/example"), "default")
        self.assertEqual("default", result["label"])
        self.assertEqual(2 * 1024 * 1024, result["opensearch_disk_bytes"])
        self.assertEqual(1, result["schema_version"])
        self.assertEqual(2, run.call_count)
        first = run.call_args_list[0]
        second = run.call_args_list[1]
        self.assertEqual(
            [
                "docker",
                "compose",
                "exec",
                "-T",
                "opensearch",
                "du",
                "-sk",
                "/usr/share/opensearch/data",
            ],
            first.args[0],
        )
        self.assertEqual(
            [
                "docker",
                "compose",
                "exec",
                "-T",
                "logstash",
                "curl",
                "-fsS",
                "http://localhost:9600/_node/stats/pipelines",
            ],
            second.args[0],
        )
        self.assertEqual(Path("/example"), first.kwargs["cwd"])
        self.assertTrue(first.kwargs["check"])
        self.assertNotIn("shell", first.kwargs)

    @mock.patch.object(bench.subprocess, "run")
    def test_compose_failure_is_actionable(self, run):
        run.side_effect = subprocess.CalledProcessError(
            1, ["docker", "compose"], stderr="container not running"
        )
        with self.assertRaisesRegex(bench.BenchmarkError, "container not running"):
            bench.run_compose(Path("/x"), "opensearch", "du", "-sk", "/data")

    @mock.patch.object(bench.subprocess, "run")
    def test_missing_docker_executable(self, run):
        run.side_effect = FileNotFoundError()
        with self.assertRaisesRegex(bench.BenchmarkError, "Docker Compose"):
            bench.run_compose(Path("/x"), "opensearch", "du", "-sk", "/data")


class CompareTests(unittest.TestCase):
    def sample(self, label, disk_bytes, duration, count=1000):
        filters, pipelines = bench.parse_logstash_stats(fake_stats(duration, count))
        return {
            "schema_version": bench.SCHEMA_VERSION,
            "label": label,
            "opensearch_disk_bytes": disk_bytes,
            "filters": filters,
            "pipelines": pipelines,
        }

    def test_compare_shows_disk_and_normalized_filter_delta(self):
        base = self.sample("default", 1024, 500)
        candidate = self.sample("all", 1536, 750)
        report = bench.compare_snapshots(base, candidate, "netbox")
        self.assertIn("+512, +50.00%", report)
        self.assertIn("ruby_netbox_enrich | 500.00 | 750.00 | +250.00", report)
        self.assertIn("log-enrichment: 1000 -> 1000", report)
        self.assertIn("Counters are cumulative", report)

    def test_compare_missing_filter_and_zero_baseline(self):
        base = self.sample("empty", 0, 0, count=0)
        base["filters"] = []
        candidate = self.sample("variant", 2048, 750)
        report = bench.compare_snapshots(base, candidate)
        self.assertIn("(+2,048, n/a)", report)
        self.assertIn("ruby_netbox_enrich | n/a | 750.00 | n/a", report)

    def test_compare_filter_selection(self):
        report = bench.compare_snapshots(
            self.sample("default", 1, 5),
            self.sample("variant", 1, 6),
            "does_not_exist",
        )
        self.assertIn("(No matching filter metrics.)", report)

    def test_load_snapshot_validates_schema_and_types(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filename = Path(tmpdir) / "snapshot.json"
            filename.write_text('{"schema_version": 1000}', encoding="utf-8")
            with self.assertRaises(bench.BenchmarkError):
                bench.load_snapshot(filename)
            good = self.sample("baseline", 123, 456)
            filename.write_text(json.dumps(good), encoding="utf-8")
            self.assertEqual(good, bench.load_snapshot(filename))

    def test_compare_cli_reads_snapshot_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            left = Path(tmpdir) / "before.json"
            right = Path(tmpdir) / "after.json"
            left.write_text(
                json.dumps(self.sample("before", 1024, 1)), encoding="utf-8"
            )
            right.write_text(
                json.dumps(self.sample("after", 2048, 2)), encoding="utf-8"
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = bench.main(
                    ["compare", str(left), str(right), "--filter", "netbox"]
                )
            self.assertEqual(0, status)
            self.assertIn("ruby_netbox_enrich", output.getvalue())


if __name__ == "__main__":
    unittest.main()
