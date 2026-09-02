#!/usr/bin/env python3
"""Regression checks for Zeek -> Arkime Modbus field normalization."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FUNC_MAP = ROOT / "logstash/maps/modbus_zeek_func_to_funccode.yaml"
EXC_MAP = ROOT / "logstash/maps/modbus_zeek_exception_to_exccode.yaml"
ARKIME_TEMPLATE = ROOT / "dashboards/templates/composable/component/arkime.json"
MODBUS_DASHBOARD = ROOT / "dashboards/dashboards/152f29dc-51a2-4f53-93e9-6e92765567b8.json"
NORMALIZE_CONF = ROOT / "logstash/pipelines/zeek/1300_zeek_normalize.conf"
MUTATE_CONF = ROOT / "logstash/pipelines/zeek/1200_zeek_mutate.conf"


def load_yaml(path: Path) -> dict[str, str]:
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise AssertionError(f"{path} did not load as a mapping")
    return {str(key): str(value) for key, value in data.items()}


def assert_numeric_map(path: Path, mapping: dict[str, str]) -> None:
    for key, value in mapping.items():
        if not value.isdigit():
            raise AssertionError(f"{path}: {key} maps to non-numeric value {value!r}")


def strip_exception_suffix(func_name: str) -> str:
    return re.sub(r"_?EXCEPTION$", "", func_name)


def translate_func(func_name: str, mapping: dict[str, str]) -> int | None:
    lookup = strip_exception_suffix(func_name)
    translated = mapping.get(lookup)
    return int(translated) if translated is not None else None


def translate_exception(exception: str, mapping: dict[str, str]) -> int | None:
    if re.fullmatch(r"\d+", exception):
        return int(exception)
    translated = mapping.get(exception)
    return int(translated) if translated is not None else None


def check_arkime_template() -> None:
    template = json.loads(ARKIME_TEMPLATE.read_text(encoding="utf-8"))
    modbus = template["template"]["mappings"]["properties"]["modbus"]["properties"]
    for field in ("funccode", "exccode", "transactionid", "unitid"):
        field_type = modbus[field]["type"]
        if field_type != "long":
            raise AssertionError(f"arkime.json modbus.{field} expected long, got {field_type}")


def check_no_raw_modbus_merges() -> None:
    patterns = [
        r'\[modbus\]\[funccode\].*\[zeek\]\[modbus\]\[func\]',
        r'\[modbus\]\[exccode\].*\[zeek\]\[modbus\]\[exception\]',
    ]
    text = MUTATE_CONF.read_text(encoding="utf-8")
    for pattern in patterns:
        if re.search(pattern, text):
            raise AssertionError(f"1200_zeek_mutate.conf still contains raw merge: {pattern}")


def check_normalize_block() -> None:
    text = NORMALIZE_CONF.read_text(encoding="utf-8")
    required_ids = [
        "translate_zeek_modbus_func_to_funccode",
        "translate_zeek_modbus_exception_to_exccode",
        "mutate_convert_zeek_modbus_transactionid",
        "mutate_convert_zeek_modbus_unitid",
    ]
    for required_id in required_ids:
        if required_id not in text:
            raise AssertionError(f"1300_zeek_normalize.conf missing filter id {required_id}")


def check_dashboard_json() -> None:
    json.loads(MODBUS_DASHBOARD.read_text(encoding="utf-8"))


def main() -> int:
    func_map = load_yaml(FUNC_MAP)
    exc_map = load_yaml(EXC_MAP)
    assert_numeric_map(FUNC_MAP, func_map)
    assert_numeric_map(EXC_MAP, exc_map)

    samples = [
        ("WRITE_SINGLE_REGISTER", 6),
        ("READ_COILS_EXCEPTION", 1),
        ("MASK_WRITE_REGISTER", 22),
    ]
    for func_name, expected in samples:
        actual = translate_func(func_name, func_map)
        if actual != expected:
            raise AssertionError(f"func {func_name}: expected {expected}, got {actual}")

    exception_samples = [
        ("ILLEGAL_DATA_ADDRESS", 2),
        ("3", 3),
    ]
    for exception, expected in exception_samples:
        actual = translate_exception(exception, exc_map)
        if actual != expected:
            raise AssertionError(f"exception {exception}: expected {expected}, got {actual}")

    unknown = translate_func("UNKNOWN_FUTURE_FUNC", func_map)
    if unknown is not None:
        raise AssertionError("unknown function should not translate")

    check_arkime_template()
    check_no_raw_modbus_merges()
    check_normalize_block()
    check_dashboard_json()

    print("modbus arkime normalization regression checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
