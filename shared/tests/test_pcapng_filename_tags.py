"""Ensure capture format extensions do not become analyst-supplied tags."""

import pytest

from pcap_utils import tags_from_filename


@pytest.mark.parametrize(
    "filename, expected",
    [
        ("captures/Factory-2026-10-15.pcapng", ["captures", "Factory"]),
        ("sensor.PCAPNG", ["sensor"]),
        ("node_x/Traffic.PcApNg", ["node", "x", "Traffic"]),
        ("node/capture.pcap", ["node", "capture"]),
        ("pcapng", []),
        ("pcapng_sample.pcapng", ["sample"]),
    ],
)
def test_pcapng_format_tokens_are_not_tags(filename, expected):
    assert tags_from_filename(filename) == expected


@pytest.mark.parametrize(
    "filename, expected",
    [
        ("sensor.pcapnglab", ["sensor", "pcapnglab"]),
        ("pcapng-analysis.pcap", ["analysis"]),
        ("north-plant.pcapng", ["north", "plant"]),
    ],
)
def test_only_exact_format_tokens_are_suppressed(filename, expected):
    assert tags_from_filename(filename) == expected


def test_extension_filter_does_not_change_unrelated_tags():
    assert tags_from_filename("plant-ALPHA,Zeek_suricata.pcapng") == ["plant", "ALPHA"]
