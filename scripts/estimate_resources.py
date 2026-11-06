#!/usr/bin/env python3
# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""Estimate Malcolm PCAP and OpenSearch disk capacity from measured workload inputs.

These calculations are planning estimates, not performance benchmarks.
"""

import argparse
import json
import math
from dataclasses import asdict, dataclass

BITS_PER_BYTE = 8
SECONDS_PER_DAY = 86_400
BYTES_PER_GIB = 1024**3

# See docs/system-requirements.md. These are published starting points,
# not workload-specific CPU/memory sizing rules.
MIN_CPU_CORES = 8
MIN_RAM_GIB = 24
RECOMMENDED_CPU_CORES = 16
RECOMMENDED_RAM_GIB = 32


@dataclass(frozen=True)
class SizingInputs:
    traffic_mbps: float
    capture_percent: float = 100.0
    pcap_days: int = 7
    indexed_gib_per_day: float | None = None
    indexed_to_pcap_ratio: float | None = None
    index_days: int = 30
    index_replicas: int = 0
    headroom_percent: float = 25.0


@dataclass(frozen=True)
class SizingResult:
    pcap_gib_per_day: float
    pcap_used_gib: float
    pcap_capacity_gib: float
    index_gib_per_day: float | None
    index_used_gib: float | None
    index_capacity_gib: float | None
    total_capacity_gib: float | None


def require_nonnegative_finite(value: float, name: str) -> None:
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"{name} must be a finite, nonnegative number.")


def estimate(inputs: SizingInputs) -> SizingResult:
    """Estimate capacity, reserving headroom as a fraction of *total* disk."""
    require_nonnegative_finite(inputs.traffic_mbps, "Traffic rate")
    require_nonnegative_finite(inputs.capture_percent, "Capture percentage")
    require_nonnegative_finite(inputs.headroom_percent, "Headroom percentage")
    if inputs.capture_percent > 100:
        raise ValueError("Capture percentage must not exceed 100.")
    if inputs.headroom_percent >= 100:
        raise ValueError("Headroom percentage must be less than 100.")
    for name, value in (
        ("PCAP retention days", inputs.pcap_days),
        ("Index retention days", inputs.index_days),
        ("Index replica count", inputs.index_replicas),
    ):
        if type(value) is not int or value < 0:
            raise ValueError(f"{name} must be a nonnegative integer.")

    if inputs.indexed_gib_per_day is not None:
        require_nonnegative_finite(inputs.indexed_gib_per_day, "Index daily volume")
    if inputs.indexed_to_pcap_ratio is not None:
        require_nonnegative_finite(inputs.indexed_to_pcap_ratio, "Index-to-PCAP ratio")
    if (
        inputs.indexed_gib_per_day is not None
        and inputs.indexed_to_pcap_ratio is not None
    ):
        raise ValueError("Specify either index daily volume or index-to-PCAP ratio.")

    pcap_per_day = (
        inputs.traffic_mbps
        * 1_000_000
        * SECONDS_PER_DAY
        / BITS_PER_BYTE
        / BYTES_PER_GIB
        * inputs.capture_percent
        / 100
    )
    pcap_used = pcap_per_day * inputs.pcap_days
    reserve_factor = 1 / (1 - inputs.headroom_percent / 100)
    index_per_day = inputs.indexed_gib_per_day
    if inputs.indexed_to_pcap_ratio is not None:
        index_per_day = pcap_per_day * inputs.indexed_to_pcap_ratio
    if index_per_day is None:
        return SizingResult(
            pcap_per_day,
            pcap_used,
            pcap_used * reserve_factor,
            None,
            None,
            None,
            None,
        )
    index_used = index_per_day * inputs.index_days * (inputs.index_replicas + 1)
    return SizingResult(
        pcap_per_day,
        pcap_used,
        pcap_used * reserve_factor,
        index_per_day,
        index_used,
        index_used * reserve_factor,
        (pcap_used + index_used) * reserve_factor,
    )


def gib_text(value: float) -> str:
    if value >= 1024:
        return f"{value / 1024:,.2f} TiB"
    return f"{value:,.2f} GiB"


def render_text(inputs: SizingInputs, result: SizingResult) -> str:
    lines = [
        "Malcolm resource capacity estimate",
        f"Captured PCAP volume: {gib_text(result.pcap_gib_per_day)} per day",
        f"PCAP retention: {inputs.pcap_days} days",
        (
            f"PCAP disk target with {inputs.headroom_percent:g}% free-space reserve: "
            f"{gib_text(result.pcap_capacity_gib)}"
        ),
    ]
    if result.index_capacity_gib is not None:
        lines.extend(
            (
                f"Indexed data volume: {gib_text(result.index_gib_per_day or 0)} per day",
                (
                    f"Index retention: {inputs.index_days} days; "
                    f"replicas: {inputs.index_replicas}"
                ),
                f"OpenSearch disk target: {gib_text(result.index_capacity_gib)}",
                f"Combined data-disk target: {gib_text(result.total_capacity_gib or 0)}",
            )
        )
    else:
        lines.append(
            "OpenSearch estimate omitted: supply --indexed-gib-per-day or "
            "--indexed-to-pcap-ratio based on observed indexing."
        )
    lines.extend(
        (
            (
                f"Malcolm published minimum: {MIN_CPU_CORES} CPU cores, "
                f"{MIN_RAM_GIB} GiB RAM"
            ),
            (
                f"Malcolm published recommendation: {RECOMMENDED_CPU_CORES}+ CPU cores, "
                f"{RECOMMENDED_RAM_GIB}+ GiB RAM"
            ),
            "CPU and RAM guidance is a baseline, not sized to the supplied traffic rate.",
            (
                "Storage excludes the operating system, temporary data, backups, "
                "and additional processing overhead."
            ),
        )
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--traffic-mbps",
        type=float,
        required=True,
        help="Average traffic rate in decimal megabits per second",
    )
    parser.add_argument(
        "--capture-percent",
        type=float,
        default=100,
        help="Percentage of that traffic retained as PCAP (default: 100)",
    )
    parser.add_argument(
        "--pcap-days", type=int, default=7, help="Days of PCAP retention (default: 7)"
    )
    index = parser.add_mutually_exclusive_group()
    index.add_argument(
        "--indexed-gib-per-day",
        type=float,
        help="Measured daily OpenSearch index growth in GiB",
    )
    index.add_argument(
        "--indexed-to-pcap-ratio",
        type=float,
        help="Measured indexed GiB divided by captured PCAP GiB",
    )
    parser.add_argument(
        "--index-days",
        type=int,
        default=30,
        help="Days of OpenSearch retention (default: 30)",
    )
    parser.add_argument(
        "--index-replicas",
        type=int,
        default=0,
        help="Additional copies of indexed data (default: 0)",
    )
    parser.add_argument(
        "--headroom-percent",
        type=float,
        default=25,
        help="Free-space reserve as percent of capacity (default: 25)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit inputs, estimates and hardware baseline as JSON",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    inputs = SizingInputs(
        traffic_mbps=args.traffic_mbps,
        capture_percent=args.capture_percent,
        pcap_days=args.pcap_days,
        indexed_gib_per_day=args.indexed_gib_per_day,
        indexed_to_pcap_ratio=args.indexed_to_pcap_ratio,
        index_days=args.index_days,
        index_replicas=args.index_replicas,
        headroom_percent=args.headroom_percent,
    )
    try:
        result = estimate(inputs)
    except ValueError as exc:
        parser.error(str(exc))
    if args.json:
        print(
            json.dumps(
                {
                    "inputs": asdict(inputs),
                    "storage_gib": asdict(result),
                    "hardware_baseline": {
                        "minimum_cpu_cores": MIN_CPU_CORES,
                        "minimum_ram_gib": MIN_RAM_GIB,
                        "recommended_cpu_cores": RECOMMENDED_CPU_CORES,
                        "recommended_ram_gib": RECOMMENDED_RAM_GIB,
                    },
                },
                indent=2,
            )
        )
    else:
        print(render_text(inputs, result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
