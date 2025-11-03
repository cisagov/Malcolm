#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import random
import string
import tempfile
import unittest

from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.malcolm_constants import OrchestrationFramework
from scripts.installer.core.config_item import ConfigItem
from scripts.installer.configs.constants.enums import ContainerRuntime
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
    KEY_CONFIG_ITEM_LIVE_ARKIME,
    KEY_CONFIG_ITEM_MALCOLM_PROFILE,
    KEY_CONFIG_ITEM_NETBOX_MODE,
    KEY_CONFIG_ITEM_NETBOX_URL,
    KEY_CONFIG_ITEM_PCAP_NETSNIFF,
    KEY_CONFIG_ITEM_PCAP_TCPDUMP,
    KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
    KEY_CONFIG_ITEM_RUNTIME_BIN,
)


def _cleanup_dir(path: str):
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            try:
                os.remove(os.path.join(root, name))
            except FileNotFoundError:
                pass
        for name in dirs:
            try:
                os.rmdir(os.path.join(root, name))
            except FileNotFoundError:
                pass
    try:
        os.rmdir(path)
    except FileNotFoundError:
        pass


def _random_string(n: int = 10) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))


def _pick_valid_value(item: ConfigItem, current_value):
    """Attempt to pick a different, valid value for a ConfigItem.

    Strategy:
    - If choices exist, pick an alternative choice.
    - Try common candidates by type and validate using the item's validator.
    - Fall back to returning the current value if no valid alternative found.
    """

    choices = list(getattr(item, "choices", []) or [])
    if choices and (item.key != 'dockerOrchestrationMode'):
        # Normalize enum-like choices to their literal value
        alt_choices = [c for c in choices if c != current_value]
        if alt_choices:
            return random.choice(alt_choices)
        return current_value

    validator = getattr(item, "validator", None)

    def is_valid(val) -> bool:
        if validator is None:
            return True
        res = validator(val)
        if isinstance(res, tuple):
            return bool(res[0])
        return bool(res)

    # Memory fields must be of the form \d+(g|m)
    if item.key in {"osMemory", "lsMemory"}:
        mem_opts = [
            "1g",
            "2g",
            "4g",
            "8g",
            "16g",
            "2500m",
            "9500m",
        ]
        mem_alts = [m for m in mem_opts if m != current_value]
        if mem_alts:
            return random.choice(mem_alts)

    # Port-like items: avoid zero (treated as unset) and pick typical ports
    if item.key in {"syslogTcpPort", "syslogUdpPort"}:
        port_opts = [514, 5514, 10514, 1514]
        port_alts = [p for p in port_opts if p != current_value]
        if port_alts:
            return random.choice(port_alts)

    # Items where '0' is a sentinel for empty (avoid "0")
    if item.key in {"vtotApiKey", "indexPruneThreshold"}:
        opts = [
            _random_string(12),
            "abc123DEF456",
            "250G",
            "60%",
        ]
        alts = [o for o in opts if o != current_value]
        if alts:
            return random.choice(alts)

    if item.key == 'dockerOrchestrationMode':
        return random.choice([OrchestrationFramework.DOCKER_COMPOSE, OrchestrationFramework.KUBERNETES])

    candidates = []

    # Boolean toggle
    if isinstance(current_value, bool):
        candidates.extend([not current_value, True, False])

    # Numeric candidates
    candidates.extend([0, 1, 2, 42, 123, 456, 1024, 65535])

    # String candidates: include URLs, sizes, generic text, sentinel values
    candidates.extend(
        [
            _random_string(8),
            "test",
            "example",
            "http://localhost",
            "https://example.com",
            "10g",
            "250G",
            "60%",
            "0",
            "1",
        ]
    )

    # Ensure current value is not first in list
    candidates = [c for c in candidates if c != current_value]

    for cand in candidates:
        try:
            if is_valid(cand):
                return cand
        except Exception:
            continue

    # If nothing worked, return current as no-op
    return current_value


class TestEnvFullRoundtrip(unittest.TestCase):
    """Full-config .env roundtrip tests: defaults and randomized values."""

    def test_defaults_full_config_roundtrip(self):
        cfg1 = MalcolmConfig()
        mapper = cfg1.get_env_mapper()
        with tempfile.TemporaryDirectory(delete=False) as td:
            # Write defaults
            cfg1.generate_env_files(td)
            # Read into fresh instance
            cfg2 = MalcolmConfig()
            cfg2.load_from_env_files(td)

            # Compare values for all items that map to env vars and are not reverse-noop only
            item_to_envs = mapper.get_item_to_env_mapping()
            for key, envs in item_to_envs.items():
                # Skip items where all mapped env vars are reverse-noop or derived-only with no authoritative var
                has_authoritative = any(env.is_authoritative_for(key) for env in envs)
                can_reverse = any(not getattr(env, "reverse_noop", False) for env in envs)
                if not has_authoritative and not can_reverse:
                    continue
                self.assertEqual(
                    cfg1.get_value(key),
                    cfg2.get_value(key),
                    f"Default roundtrip mismatch for {key}",
                )

    def test_randomized_full_config_roundtrip(self):
        # Seed deterministically for reproducibility if failures occur
        random.seed(17)

        cfg1 = MalcolmConfig()
        mapper = cfg1.get_env_mapper()

        # Mutate all env-mapped items to valid, randomized values
        changed_keys = []
        for key, envs in mapper.get_item_to_env_mapping().items():
            # Only consider items that can be expressed via at least one authoritative env var
            if not any(env.is_authoritative_for(key) and not env.reverse_noop for env in envs):
                continue
            item = cfg1.get_item(key)
            if not isinstance(item, ConfigItem):
                continue
            cur = item.get_value()
            new_val = _pick_valid_value(item, cur)
            # Skip if no-op
            if new_val == cur:
                continue

            cfg1.set_value(key, new_val, ignore_errors=True)
            changed_keys.append(key)

        self.assertGreater(len(changed_keys), 0, "No keys were changed for randomized roundtrip test")

        # Write mutated config to env and load into fresh instance
        with tempfile.TemporaryDirectory() as td:

            # Normalize mutually-exclusive capture engine flags to avoid impossible roundtrips
            try:
                if cfg1.get_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE) != "hedgehog":
                    cfg1.set_value(KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC, True, ignore_errors=True)
                    cfg1.set_value(KEY_CONFIG_ITEM_LIVE_ARKIME, True, ignore_errors=True)
                    cfg1.set_value(KEY_CONFIG_ITEM_PCAP_NETSNIFF, False, ignore_errors=True)
                    cfg1.set_value(KEY_CONFIG_ITEM_PCAP_TCPDUMP, False, ignore_errors=True)

                elif (
                    sum(
                        [
                            bool(cfg1.get_value(KEY_CONFIG_ITEM_PCAP_TCPDUMP)),
                            bool(cfg1.get_value(KEY_CONFIG_ITEM_PCAP_NETSNIFF)),
                            bool(cfg1.get_value(KEY_CONFIG_ITEM_LIVE_ARKIME)),
                        ]
                    )
                    > 1
                ):
                    cfg1.set_value(KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC, True, ignore_errors=True)
                    cfg1.set_value(KEY_CONFIG_ITEM_PCAP_NETSNIFF, True, ignore_errors=True)
                    cfg1.set_value(KEY_CONFIG_ITEM_LIVE_ARKIME, False, ignore_errors=True)
                    cfg1.set_value(KEY_CONFIG_ITEM_PCAP_TCPDUMP, False, ignore_errors=True)

                # makesure orchestration mode and runtime bin match
                if cfg1.get_value(KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE) == OrchestrationFramework.KUBERNETES:
                    cfg1.set_value(KEY_CONFIG_ITEM_RUNTIME_BIN, "kubernetes", ignore_errors=True)
                else:
                    cfg1.set_value(
                        KEY_CONFIG_ITEM_RUNTIME_BIN,
                        random.choice([ContainerRuntime.DOCKER.value, ContainerRuntime.PODMAN.value]),
                        ignore_errors=True,
                    )

                # Ensure NetBox URL is emitted: require remote mode when URL is non-empty
                nb_url = cfg1.get_value(KEY_CONFIG_ITEM_NETBOX_URL)
                if isinstance(nb_url, str) and nb_url.strip():
                    cfg1.set_value(KEY_CONFIG_ITEM_NETBOX_MODE, "remote", ignore_errors=True)

            except Exception as e:
                print(e, file=sys.stderr)
                pass

            cfg1.generate_env_files(td)
            cfg2 = MalcolmConfig()
            cfg2.load_from_env_files(td)

            for key in changed_keys:
                self.assertEqual(
                    cfg1.get_value(key),
                    cfg2.get_value(key),
                    f"Randomized roundtrip mismatch for {key}",
                )


if __name__ == "__main__":
    unittest.main()
