#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for Traefik label injection into docker-compose files.

Validates that ancillary.update_docker_compose_files applies or clears
Traefik labels on the nginx-proxy service based on MalcolmConfig values,
matching the original install.py behavior.
"""

import os
import shutil
import tempfile
import unittest
from ruamel.yaml import YAML

from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.installer.actions.shared import update_ancillary as update_docker_compose_files
from scripts.installer.utils.logger_utils import InstallerLogger
from scripts.installer.tests.mock.test_framework import MockPlatform
from scripts.installer.core.install_context import InstallContext
from scripts.installer.utils.logger_utils import InstallerLogger
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_BEHIND_REVERSE_PROXY,
    KEY_CONFIG_ITEM_TRAEFIK_LABELS,
    KEY_CONFIG_ITEM_TRAEFIK_HOST,
    KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST,
    KEY_CONFIG_ITEM_TRAEFIK_ENTRYPOINT,
    KEY_CONFIG_ITEM_TRAEFIK_RESOLVER,
    KEY_CONFIG_ITEM_EXPOSE_OPENSEARCH,
    KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
)
from scripts.malcolm_constants import DatabaseMode, DATABASE_MODE_LABELS


def _write_compose(path, data):
    yaml = YAML()
    yaml.default_flow_style = False
    with open(path, "w") as f:
        yaml.dump(data, f)


def _read_compose(path):
    yaml = YAML(typ="safe", pure=True)
    with open(path, "r") as f:
        return yaml.load(f)


class TestTraefikLabels(unittest.TestCase):
    def setUp(self):
        self.cfg = MalcolmConfig()
        self.tmpdir = tempfile.mkdtemp()
        self.compose_path = os.path.join(self.tmpdir, "docker-compose.yml")
        # minimal compose with nginx-proxy service
        base = {
            "version": "3.7",
            "services": {"nginx-proxy": {"image": "nginx:latest", "labels": {}}},
        }
        _write_compose(self.compose_path, base)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_labels_enabled_with_required_fields(self):
        # arrange
        self.cfg.set_value(KEY_CONFIG_ITEM_BEHIND_REVERSE_PROXY, True)
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_LABELS, True)
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_HOST, "malcolm.example.org")
        self.cfg.set_value(
            KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST, "os.malcolm.example.org"
        )
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_ENTRYPOINT, "websecure")
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_RESOLVER, "myresolver")
        self.cfg.set_value(KEY_CONFIG_ITEM_EXPOSE_OPENSEARCH, True)
        self.cfg.set_value(
            KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            DATABASE_MODE_LABELS[DatabaseMode.OpenSearchLocal],
        )

        # act
        ok = update_docker_compose_files(
            self.cfg, self.tmpdir, MockPlatform(), InstallContext(), InstallerLogger
        )
        self.assertTrue(ok)

        data = _read_compose(self.compose_path)
        labels = data["services"]["nginx-proxy"].get("labels", {})

        # assert: traefik enabled and label keys present
        self.assertTrue(labels.get("traefik.enable", False))
        self.assertEqual(
            labels.get("traefik.http.routers.malcolm.rule"),
            "Host(`malcolm.example.org`)",
        )
        self.assertEqual(
            labels.get("traefik.http.routers.malcolm.entrypoints"), "websecure"
        )
        self.assertEqual(
            labels.get("traefik.http.routers.malcolm.tls.certresolver"), "myresolver"
        )
        self.assertEqual(labels.get("traefik.http.routers.malcolm.service"), "malcolm")
        self.assertEqual(
            labels.get("traefik.http.services.malcolm.loadbalancer.server.port"), "443"
        )

        # opensearch labels present when local and exposed
        self.assertEqual(
            labels.get("traefik.http.routers.osmalcolm.rule"),
            "Host(`os.malcolm.example.org`)",
        )
        self.assertEqual(
            labels.get("traefik.http.routers.osmalcolm.entrypoints"), "websecure"
        )
        self.assertEqual(
            labels.get("traefik.http.routers.osmalcolm.tls.certresolver"), "myresolver"
        )
        self.assertEqual(
            labels.get("traefik.http.routers.osmalcolm.service"), "osmalcolm"
        )
        self.assertEqual(
            labels.get("traefik.http.services.osmalcolm.loadbalancer.server.port"),
            "9200",
        )

    def test_labels_disabled_clears_known_keys(self):
        # arrange existing labels that should be cleared
        pre_labels = {
            "traefik.http.routers.malcolm.rule": "Host(`old.example`)",
            "traefik.http.services.malcolm.loadbalancer.server.port": "443",
            "traefik.http.routers.osmalcolm.rule": "Host(`oldos.example`)",
        }
        data = _read_compose(self.compose_path)
        data["services"]["nginx-proxy"]["labels"] = dict(pre_labels)
        _write_compose(self.compose_path, data)

        self.cfg.set_value(KEY_CONFIG_ITEM_BEHIND_REVERSE_PROXY, True)
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_LABELS, False)

        # act
        ok = update_docker_compose_files(
            self.cfg, self.tmpdir, MockPlatform(), InstallContext(), InstallerLogger
        )
        self.assertTrue(ok)

        updated = _read_compose(self.compose_path)
        labels = updated["services"]["nginx-proxy"].get("labels", {})

        # assert: disabled and keys cleared
        self.assertFalse(labels.get("traefik.enable", True))
        for k in pre_labels.keys():
            self.assertNotIn(k, labels)

    def test_opensearch_labels_absent_when_remote_or_not_exposed(self):
        # arrange: labels enabled but remote primary
        self.cfg.set_value(KEY_CONFIG_ITEM_BEHIND_REVERSE_PROXY, True)
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_LABELS, True)
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_HOST, "malcolm.example.org")
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_ENTRYPOINT, "websecure")
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_RESOLVER, "myresolver")
        self.cfg.set_value(
            KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            DATABASE_MODE_LABELS[DatabaseMode.OpenSearchRemote],
        )
        self.cfg.set_value(KEY_CONFIG_ITEM_EXPOSE_OPENSEARCH, True)

        # act
        ok = update_docker_compose_files(
            self.cfg, self.tmpdir, MockPlatform(), InstallContext(), InstallerLogger
        )
        self.assertTrue(ok)

        data = _read_compose(self.compose_path)
        labels = data["services"]["nginx-proxy"].get("labels", {})

        # assert: malcolm labels present, osmalcolm absent
        self.assertTrue(labels.get("traefik.enable", False))
        self.assertIn("traefik.http.routers.malcolm.rule", labels)
        self.assertNotIn("traefik.http.routers.osmalcolm.rule", labels)

    def test_opensearch_labels_absent_when_local_but_not_exposed(self):
        # arrange: primary local, not exposed
        self.cfg.set_value(KEY_CONFIG_ITEM_BEHIND_REVERSE_PROXY, True)
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_LABELS, True)
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_HOST, "malcolm.example.org")
        self.cfg.set_value(
            KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST, "os.malcolm.example.org"
        )
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_ENTRYPOINT, "websecure")
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_RESOLVER, "myresolver")
        self.cfg.set_value(
            KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            DATABASE_MODE_LABELS[DatabaseMode.OpenSearchLocal],
        )
        self.cfg.set_value(KEY_CONFIG_ITEM_EXPOSE_OPENSEARCH, False)

        # act
        ok = update_docker_compose_files(
            self.cfg, self.tmpdir, MockPlatform(), InstallContext(), InstallerLogger
        )
        self.assertTrue(ok)

        data = _read_compose(self.compose_path)
        labels = data["services"]["nginx-proxy"].get("labels", {})

        # assert: malcolm labels present, osmalcolm absent when not exposed
        self.assertTrue(labels.get("traefik.enable", False))
        self.assertIn("traefik.http.routers.malcolm.rule", labels)
        self.assertNotIn("traefik.http.routers.osmalcolm.rule", labels)


if __name__ == "__main__":
    unittest.main()
