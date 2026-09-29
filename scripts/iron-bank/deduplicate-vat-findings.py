#!/usr/bin/env python3
"""Combine and deduplicate VAT findings from one or more JSON files."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

IDENTITY_FIELDS = ("identifier", "package", "packagePath")

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low")
SEVERITY_RANK = {
    "Unknown": 0,
    "Informational": 1,
    "Info": 1,
    "Low": 2,
    "Medium": 3,
    "High": 4,
    "Critical": 5,
}

STATUS_ORDER = ("Justified", "Needs Justification", "Verified")
STATUS_RANK = {
    "Verified": 1,
    "Justified": 2,
    "Needs Justification": 3,
}


class InputError(ValueError):
    """Raised when an input file does not have the expected structure."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Combine findings_detail records from VAT JSON files, deduplicate them, " "and recalculate findings counts."
        )
    )
    parser.add_argument(
        "files",
        nargs="+",
        type=Path,
        metavar="JSON_FILE",
        help="one or more VAT JSON files",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="write JSON to this file instead of standard output",
    )
    return parser.parse_args()


def load_records(paths: Iterable[Path]) -> Iterable[dict[str, Any]]:
    for path in paths:
        try:
            with path.open(encoding="utf-8") as input_file:
                document = json.load(input_file)
        except OSError as exc:
            raise InputError(f"{path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise InputError(f"{path}: invalid JSON: {exc}") from exc

        if not isinstance(document, dict):
            raise InputError(f"{path}: top-level JSON value must be an object")

        for image_name, image in document.items():
            location = f"{path}: image {image_name!r}"
            if not isinstance(image, dict):
                raise InputError(f"{location} must be an object")

            details = image.get("findings_detail")
            if details is None:
                continue
            if not isinstance(details, list):
                raise InputError(f"{location}: findings_detail must be an array")

            for index, record in enumerate(details):
                record_location = f"{location}: findings_detail[{index}]"
                if not isinstance(record, dict):
                    raise InputError(f"{record_location} must be an object")
                for required_field in ("identifier", "severity", "status"):
                    if not record.get(required_field):
                        raise InputError(f"{record_location}: missing non-empty {required_field!r}")
                yield record


def identity(record: dict[str, Any]) -> tuple[Any, ...]:
    """Identify the same vulnerability in the same installed package/location."""
    return tuple(record.get(field) for field in IDENTITY_FIELDS)


def rank(value: Any, rankings: dict[str, int]) -> int:
    return rankings.get(value, -1)


def longer_value(first: Any, second: Any) -> Any:
    """Prefer a non-empty value, using the longer string when both are strings."""
    if first in (None, ""):
        return second
    if second in (None, ""):
        return first
    if isinstance(first, str) and isinstance(second, str) and len(second) > len(first):
        return second
    return first


def merge_duplicate(current: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    """Conservatively combine two records representing the same finding."""
    current_priority = (
        rank(current.get("severity"), SEVERITY_RANK),
        rank(current.get("status"), STATUS_RANK),
        len(current.get("description") or ""),
        len(current.get("justification") or ""),
    )
    candidate_priority = (
        rank(candidate.get("severity"), SEVERITY_RANK),
        rank(candidate.get("status"), STATUS_RANK),
        len(candidate.get("description") or ""),
        len(candidate.get("justification") or ""),
    )

    winner, other = (candidate, current) if candidate_priority > current_priority else (current, candidate)
    merged = dict(winner)

    if rank(other.get("severity"), SEVERITY_RANK) > rank(merged.get("severity"), SEVERITY_RANK):
        merged["severity"] = other["severity"]
    if rank(other.get("status"), STATUS_RANK) > rank(merged.get("status"), STATUS_RANK):
        merged["status"] = other["status"]

    for field in ("description", "justification"):
        if field in merged or field in other:
            merged[field] = longer_value(merged.get(field), other.get(field))

    return merged


def deduplicate(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for record in records:
        key = identity(record)
        if key in unique:
            unique[key] = merge_duplicate(unique[key], record)
        else:
            unique[key] = dict(record)
    return list(unique.values())


def ordered_labels(values: Iterable[str], preferred: tuple[str, ...]) -> list[str]:
    encountered = list(dict.fromkeys(values))
    return [value for value in preferred if value in encountered] + [
        value for value in encountered if value not in preferred
    ]


def calculate_findings(records: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    counts = Counter((record["severity"], record["status"]) for record in records)
    severities = ordered_labels((record["severity"] for record in records), SEVERITY_ORDER)
    statuses = ordered_labels((record["status"] for record in records), STATUS_ORDER)

    return {
        severity: {status: counts[severity, status] for status in statuses if counts[severity, status]}
        for severity in severities
    }


def main() -> int:
    args = parse_args()

    if args.output is not None:
        output_path = args.output.resolve()
        input_paths = {path.resolve() for path in args.files}
        if output_path in input_paths:
            print("error: output path must differ from every input path", file=sys.stderr)
            return 2

    try:
        all_records = list(load_records(args.files))
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    unique_records = deduplicate(all_records)
    result = {
        "findings": calculate_findings(all_records),
        "unique_findings": calculate_findings(unique_records),
        "findings_detail": unique_records,
    }
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"

    if args.output is None:
        sys.stdout.write(rendered)
    else:
        try:
            args.output.write_text(rendered, encoding="utf-8")
        except OSError as exc:
            print(f"error: {args.output}: {exc}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
