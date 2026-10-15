# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""Offline tests for the Malcolm capacity estimator."""

import contextlib
import io
import json
import math
import unittest

from scripts.estimate_resources import (
    MIN_CPU_CORES,
    MIN_RAM_GIB,
    RECOMMENDED_CPU_CORES,
    RECOMMENDED_RAM_GIB,
    SizingInputs,
    estimate,
    main,
    render_text,
)


class TestResourceEstimator(unittest.TestCase):
    def test_full_rate_is_decimal_megabits_not_mebibits(self):
        # 8 Mbps is 1,000,000 bytes per second, not 1 MiB per second.
        result = estimate(SizingInputs(traffic_mbps=8, pcap_days=1, headroom_percent=0))
        self.assertAlmostEqual(86_400_000_000 / 1024**3, result.pcap_gib_per_day)
        self.assertAlmostEqual(result.pcap_gib_per_day, result.pcap_capacity_gib)

    def test_capture_fraction_and_retention(self):
        result = estimate(
            SizingInputs(
                traffic_mbps=80, capture_percent=25, pcap_days=10, headroom_percent=0
            )
        )
        daily = 20 * 1_000_000 * 86400 / 8 / (1024**3)
        self.assertAlmostEqual(daily, result.pcap_gib_per_day)
        self.assertAlmostEqual(daily * 10, result.pcap_used_gib)

    def test_reserve_is_percent_of_capacity(self):
        result = estimate(
            SizingInputs(traffic_mbps=8, pcap_days=1, headroom_percent=20)
        )
        self.assertAlmostEqual(
            result.pcap_used_gib / 0.8,
            result.pcap_capacity_gib,
        )

    def test_measured_index_size_and_replicas(self):
        inputs = SizingInputs(
            traffic_mbps=0,
            pcap_days=5,
            indexed_gib_per_day=10,
            index_days=7,
            index_replicas=1,
            headroom_percent=20,
        )
        result = estimate(inputs)
        self.assertEqual(140, result.index_used_gib)
        self.assertAlmostEqual(175, result.index_capacity_gib)
        self.assertAlmostEqual(175, result.total_capacity_gib)

    def test_index_ratio_uses_captured_bytes(self):
        inputs = SizingInputs(
            traffic_mbps=12,
            capture_percent=50,
            pcap_days=2,
            indexed_to_pcap_ratio=0.4,
            index_days=2,
            index_replicas=0,
            headroom_percent=0,
        )
        result = estimate(inputs)
        self.assertAlmostEqual(
            0.4 * result.pcap_gib_per_day,
            result.index_gib_per_day,
        )
        self.assertAlmostEqual(
            result.pcap_used_gib * 1.4,
            result.total_capacity_gib,
        )

    def test_unknown_index_volume_is_not_invented(self):
        inputs = SizingInputs(traffic_mbps=100)
        result = estimate(inputs)
        self.assertIsNone(result.index_gib_per_day)
        self.assertIsNone(result.index_capacity_gib)
        self.assertIsNone(result.total_capacity_gib)
        self.assertIn("OpenSearch estimate omitted", render_text(inputs, result))

    def test_zero_capture_and_zero_retention(self):
        result = estimate(
            SizingInputs(
                traffic_mbps=10, capture_percent=0, pcap_days=0, indexed_to_pcap_ratio=0
            )
        )
        self.assertEqual(0, result.pcap_used_gib)
        self.assertEqual(0, result.total_capacity_gib)

    def test_invalid_fractions_and_storage_inputs(self):
        invalid = [
            {"traffic_mbps": -1},
            {"traffic_mbps": math.nan},
            {"traffic_mbps": math.inf},
            {"capture_percent": -1},
            {"capture_percent": 101},
            {"capture_percent": math.nan},
            {"headroom_percent": -0.01},
            {"headroom_percent": 100},
            {"headroom_percent": math.inf},
            {"indexed_gib_per_day": -1},
            {"indexed_to_pcap_ratio": -1},
            {"indexed_gib_per_day": math.nan},
            {"indexed_gib_per_day": 1, "indexed_to_pcap_ratio": 1},
        ]
        for override in invalid:
            with self.subTest(override=override), self.assertRaises(ValueError):
                estimate(SizingInputs(**({"traffic_mbps": 100} | override)))

    def test_invalid_retention_and_replicas(self):
        for field in ("pcap_days", "index_days", "index_replicas"):
            for value in (-1, 1.5, True):
                with self.subTest(field=field, value=value), self.assertRaises(
                    ValueError
                ):
                    estimate(SizingInputs(traffic_mbps=1, **{field: value}))

    def test_hardware_baseline_matches_published_requirements(self):
        self.assertEqual(
            (8, 24, 16, 32),
            (
                MIN_CPU_CORES,
                MIN_RAM_GIB,
                RECOMMENDED_CPU_CORES,
                RECOMMENDED_RAM_GIB,
            ),
        )

    def test_json_output_and_missing_index(self):
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            status = main(["--traffic-mbps", "8", "--pcap-days", "2", "--json"])
        self.assertEqual(0, status)
        payload = json.loads(capture.getvalue())
        self.assertEqual(2, payload["inputs"]["pcap_days"])
        self.assertIsNone(payload["storage_gib"]["index_capacity_gib"])
        self.assertEqual(24, payload["hardware_baseline"]["minimum_ram_gib"])

    def test_cli_reports_combined_disk(self):
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            status = main(
                [
                    "--traffic-mbps",
                    "10",
                    "--indexed-gib-per-day",
                    "5",
                    "--index-days",
                    "7",
                ]
            )
        self.assertEqual(0, status)
        self.assertIn("Combined data-disk target", capture.getvalue())

    def test_cli_refuses_conflicting_index_volumes(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(
                [
                    "--traffic-mbps",
                    "10",
                    "--indexed-gib-per-day",
                    "5",
                    "--indexed-to-pcap-ratio",
                    "0.3",
                ]
            )

    def test_cli_refuses_invalid_rate(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["--traffic-mbps", "nan"])


if __name__ == "__main__":
    unittest.main()
