# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""Read-only snapshot and comparison tool for Malcolm enrichment benchmarks."""

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INDEX_DATA_DIR = "/usr/share/opensearch/data"
LOGSTASH_STATS_URL = "http://localhost:9600/_node/stats/pipelines"
SCHEMA_VERSION = 1


class BenchmarkError(Exception):
    """The benchmark snapshot could not be collected or interpreted."""


def run_compose(project_dir: Path, service: str, *command: str) -> str:
    """Execute a read-only command in an already running Malcolm service."""
    argv = ["docker", "compose", "exec", "-T", service, *command]
    try:
        result = subprocess.run(
            argv,
            cwd=project_dir,
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        )
    except FileNotFoundError as exc:
        raise BenchmarkError("Docker Compose executable was not found.") from exc
    except subprocess.TimeoutExpired as exc:
        raise BenchmarkError(f"Timed out reading {service} statistics.") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip() or str(exc)
        raise BenchmarkError(f"Could not read {service} statistics: {detail}") from exc
    return result.stdout


def parse_storage_bytes(output: str) -> int:
    """Convert 'du -sk' output to allocated bytes, rejecting bad responses."""
    match = re.fullmatch(r"\s*(\d+)\s+\S.*", output.strip())
    if not match:
        raise BenchmarkError("Unexpected OpenSearch du output.")
    return int(match.group(1)) * 1024


def nonnegative_counter(value: object) -> int:
    """Read one integral Logstash counter without hiding invalid responses."""
    if isinstance(value, bool) or not (
        isinstance(value, int) or (isinstance(value, str) and value.isdecimal())
    ):
        raise BenchmarkError(f"Invalid Logstash counter: {value!r}")
    count = int(value)
    if count < 0:
        raise BenchmarkError(f"Negative Logstash counter: {count}")
    return count


def parse_logstash_stats(text: str) -> tuple[list[dict], list[dict]]:
    """Extract per-filter duration and per-pipeline event counts."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BenchmarkError("Logstash returned invalid JSON.") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("pipelines"), dict):
        raise BenchmarkError("Missing pipelines in Logstash stats response.")

    filters = []
    pipelines = []
    for pipeline_name, info in sorted(payload["pipelines"].items()):
        if not isinstance(info, dict):
            raise BenchmarkError(f"Invalid pipeline statistics for {pipeline_name}.")
        counters = info.get("events", {})
        plugins = info.get("plugins", {})
        if not isinstance(counters, dict) or not isinstance(plugins, dict):
            raise BenchmarkError(f"Invalid counters for {pipeline_name}.")
        rows = plugins.get("filters", [])
        if not isinstance(rows, list):
            raise BenchmarkError(f"Invalid filter list for {pipeline_name}.")
        pipelines.append(
            {
                "name": pipeline_name,
                "in": nonnegative_counter(counters.get("in", 0)),
                "out": nonnegative_counter(counters.get("out", 0)),
            }
        )
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("events"), dict):
                raise BenchmarkError(f"Invalid filter statistics for {pipeline_name}.")
            identifier = row.get("id") or row.get("name")
            if not isinstance(identifier, str) or not identifier:
                raise BenchmarkError(f"Unnamed filter in pipeline {pipeline_name}.")
            events = row["events"]
            filters.append(
                {
                    "pipeline": pipeline_name,
                    "id": identifier,
                    "in": nonnegative_counter(events.get("in", 0)),
                    "out": nonnegative_counter(events.get("out", 0)),
                    "duration_ms": nonnegative_counter(
                        events.get("duration_in_millis", 0)
                    ),
                }
            )
    return filters, pipelines


def take_snapshot(project_dir: Path, label: str) -> dict:
    """Capture observed disk allocation and cumulative filter performance."""
    usage = run_compose(project_dir, "opensearch", "du", "-sk", INDEX_DATA_DIR)
    stats = run_compose(
        project_dir,
        "logstash",
        "curl",
        "-fsS",
        LOGSTASH_STATS_URL,
    )
    filters, pipelines = parse_logstash_stats(stats)
    return {
        "schema_version": SCHEMA_VERSION,
        "label": label,
        "captured_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "opensearch_disk_bytes": parse_storage_bytes(usage),
        "filters": filters,
        "pipelines": pipelines,
    }


def load_snapshot(path: Path) -> dict:
    """Read a compatible snapshot and verify its mandatory fields."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkError(f"Could not read snapshot {path}: {exc}") from exc
    if (
        not isinstance(data, dict)
        or data.get("schema_version") != SCHEMA_VERSION
        or not isinstance(data.get("opensearch_disk_bytes"), int)
        or data["opensearch_disk_bytes"] < 0
        or not isinstance(data.get("filters"), list)
        or not isinstance(data.get("pipelines"), list)
        or not isinstance(data.get("label"), str)
    ):
        raise BenchmarkError(f"Incompatible snapshot format: {path}")
    return data


def per_thousand_events(row: dict | None) -> float | None:
    """Milliseconds of filter time for 1,000 input events."""
    if row is None or not row["in"]:
        return None
    return 1000.0 * row["duration_ms"] / row["in"]


def compare_snapshots(baseline: dict, candidate: dict, match: str = "") -> str:
    """Create a human-readable report without equating different workloads."""
    baseline_bytes = baseline["opensearch_disk_bytes"]
    candidate_bytes = candidate["opensearch_disk_bytes"]
    byte_delta = candidate_bytes - baseline_bytes
    pct = f"{byte_delta / baseline_bytes * 100:+.2f}%" if baseline_bytes else "n/a"

    lines = [
        f"Baseline: {baseline['label']}",
        f"Candidate: {candidate['label']}",
        (
            f"OpenSearch allocated bytes: {baseline_bytes:,} -> {candidate_bytes:,} "
            f"({byte_delta:+,}, {pct})"
        ),
        "",
        "Pipeline event counts (baseline -> candidate):",
    ]
    baseline_pipelines = {row["name"]: row for row in baseline["pipelines"]}
    candidate_pipelines = {row["name"]: row for row in candidate["pipelines"]}
    for name in sorted(baseline_pipelines.keys() | candidate_pipelines.keys()):
        left = baseline_pipelines.get(name)
        right = candidate_pipelines.get(name)
        lines.append(
            f"  {name}: "
            f"{left['in'] if left else 'n/a'} -> {right['in'] if right else 'n/a'}"
        )

    baseline_filters = {
        (row["pipeline"], row["id"]): row for row in baseline["filters"]
    }
    candidate_filters = {
        (row["pipeline"], row["id"]): row for row in candidate["filters"]
    }
    comparisons = []
    for key in baseline_filters.keys() | candidate_filters.keys():
        if match.lower() not in " / ".join(key).lower():
            continue
        left = baseline_filters.get(key)
        right = candidate_filters.get(key)
        before = per_thousand_events(left)
        after = per_thousand_events(right)
        change = (
            (after - before) if (before is not None and after is not None) else None
        )
        comparisons.append((key, before, after, change))
    comparisons.sort(key=lambda row: (-abs(row[3] or 0), row[0]))

    def fmt(rate: float | None) -> str:
        return f"{rate:.2f}" if rate is not None else "n/a"

    lines += [
        "",
        "Logstash filter runtime (ms per 1,000 filter input events):",
        "Pipeline / filter | Baseline | Candidate | Delta",
        "--- | ---: | ---: | ---:",
    ]
    for (pipeline, identifier), before, after, change in comparisons:
        lines.append(
            f"{pipeline} / {identifier} | {fmt(before)} | {fmt(after)} | "
            f"{f'{change:+.2f}' if change is not None else 'n/a'}"
        )
    if not comparisons:
        lines.append("(No matching filter metrics.)")
    lines += [
        "",
        (
            "Counters are cumulative since Logstash started. Compare only runs with "
            "the same input data, fresh indexes and freshly restarted Logstash."
        ),
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    snapshot_parser = commands.add_parser(
        "snapshot", help="Capture a running Malcolm instance"
    )
    snapshot_parser.add_argument("--label", required=True)
    snapshot_parser.add_argument("--output", required=True, type=Path)
    snapshot_parser.add_argument("--project-dir", type=Path, default=PROJECT_ROOT)
    compare_parser = commands.add_parser("compare", help="Compare two saved snapshots")
    compare_parser.add_argument("baseline", type=Path)
    compare_parser.add_argument("candidate", type=Path)
    compare_parser.add_argument("--filter", default="", help="Filter name substring")
    args = parser.parse_args(argv)

    try:
        if args.command == "snapshot":
            snapshot = take_snapshot(args.project_dir.resolve(), args.label)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(snapshot, indent=2) + "\n", encoding="utf-8"
            )
            print(f"Saved {args.output}")
        else:
            print(
                compare_snapshots(
                    load_snapshot(args.baseline),
                    load_snapshot(args.candidate),
                    args.filter,
                )
            )
    except (BenchmarkError, OSError) as exc:
        print(f"Benchmark error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
