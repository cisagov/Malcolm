#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import tempfile
import unittest

from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.installer.utils.exceptions import ConfigValueValidationError


class TestEnvFullRoundtripPerItem(unittest.TestCase):
    """Round‑trip coverage for all mapped ConfigItems via authoritative env vars.

    We iterate env-variable groups and mutate their authoritative items together
    so multi-conditional transforms (e.g., tcpdump vs netsniff) remain consistent.
    After writing and reloading .env, we assert the authoritative items match.
    """

    def setUp(self):
        self.cfg = MalcolmConfig()
        self.mapper = self.cfg.get_env_mapper()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        for root, dirs, files in os.walk(self.temp_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.temp_dir)

    def _first_working_value(self, key, item):
        """Return a valid alternate value for the item or None if not found.

        Tries a small set of candidates based on current value, choices, and
        common types. Uses MalcolmConfig.set_value which normalizes and validates.
        """
        current = item.get_value()

        # 1) Respect choices when present
        if getattr(item, "choices", None):
            for c in item.choices:
                if c != current:
                    try:
                        self.cfg.set_value(key, c)
                        return c
                    except ConfigValueValidationError:
                        continue

        # 2) Typical alternates by inferred type
        candidates = []
        if isinstance(current, bool):
            candidates.append(not current)
        elif isinstance(current, int):
            # avoid 0 for port-like values; add simple offsets
            base = current if current is not None else 1
            for delta in (1, 2, 5):
                candidates.append(max(1, base + delta))
        elif isinstance(current, str):
            if current:
                candidates.append(f"{current}-x")
            # fallbacks for empty/None
            candidates.extend(
                [
                    "test-value",
                    "https://example.invalid",
                    "docker",
                    "podman",
                    "local",
                    "remote",
                ]
            )
        else:
            # Unknown/None -> try a small probe set
            candidates.extend([True, False, 1, 2, "test-value", "docker", "remote"])

        for cand in candidates:
            try:
                self.cfg.set_value(key, cand)
                return cand
            except ConfigValueValidationError:
                continue
            except Exception:
                # If normalization fails, keep trying others
                continue

        return None

    def test_all_items_env_roundtrip(self):
        covered_items = set()
        envs = list(self.mapper.env_var_by_map_key.values())
        self.assertGreater(len(envs), 0)

        for ev in envs:
            # Identify authoritative targets for this env var
            targets = [k for k in ev.config_items if ev.is_authoritative_for(k)]
            if not targets:
                continue

            # Mutate at least one target to a valid alternate
            mutated_any = False
            # fresh config per group to avoid cross-group interference
            group_cfg = MalcolmConfig()
            group_items = group_cfg.get_all_config_items()
            for key in targets:
                base = group_cfg.get_value(key)
                alt = None
                try:
                    alt = self._first_working_value(key, group_items[key])
                except Exception:
                    alt = None
                if alt is not None and alt != base:
                    mutated_any = True

            if not mutated_any:
                # Nothing changed — skip this group
                continue

            # Write and reload
            with tempfile.TemporaryDirectory() as td:
                group_cfg.generate_env_files(td)
                cfg2 = MalcolmConfig()
                cfg2.load_from_env_files(td)

            # Assert authoritative items for this env var survived roundtrip
            for key in targets:
                self.assertEqual(
                    group_cfg.get_value(key),
                    cfg2.get_value(key),
                    f"Roundtrip mismatch for {key} via {ev.variable_name}",
                )
                covered_items.add(key)

        # Ensure we covered all items that have at least one authoritative env var
        expected = set()
        for ev in self.mapper.env_var_by_map_key.values():
            for k in ev.config_items:
                if ev.is_authoritative_for(k):
                    expected.add(k)

        self.assertTrue(expected.issubset(covered_items) or expected == covered_items)


if __name__ == "__main__":
    unittest.main()
