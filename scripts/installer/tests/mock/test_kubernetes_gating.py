#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Integration test: Kubernetes orchestration gates install steps and only generates .env files."""

import os
import sys
import tempfile
import shutil
import types
import unittest
from unittest.mock import patch

# Ensure project root is importable
_script_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.abspath(os.path.join(_script_dir, "..", "..", ".."))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)


class TestKubernetesGating(unittest.TestCase):
    """Verify Kubernetes mode skips docker/compose steps and only writes env files."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.output_dir = os.path.join(self.test_dir, "out-config")
        os.makedirs(self.output_dir, exist_ok=True)

        # Create a minimal kubeconfig-like YAML so DetermineYamlFileFormat detects Kubernetes
        self.kubeconfig_path = os.path.join(self.test_dir, "kubeconfig.yaml")
        with open(self.kubeconfig_path, "w", encoding="utf-8") as f:
            f.write(
                """
apiVersion: v1
kind: Config
clusters: []
contexts: []
current-context: ""
users: []
"""
            )

        # Provide a minimal fake kubernetes module to satisfy import in install
        fake_kube_config_mod = types.ModuleType("kubernetes.config")

        def _fake_load_kube_config(_):
            return True

        fake_kube_config_mod.load_kube_config = _fake_load_kube_config

        fake_kube_mod = types.ModuleType("kubernetes")
        fake_kube_mod.config = fake_kube_config_mod

        self.kube_patch = patch.dict(sys.modules, {"kubernetes": fake_kube_mod})
        self.kube_patch.start()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
        self.kube_patch.stop()

    def test_kubernetes_mode_generates_only_env_files(self):
        # Prepare argv for non-interactive defaults in Kubernetes mode
        from scripts import install

        argv = [
            "install.py",
            "--non-interactive",
            "--defaults",
            "--silent",
            "--environment-dir-output",
            self.output_dir,
            "-f",
            self.kubeconfig_path,
        ]

        with patch.object(sys, "argv", argv), patch("os.geteuid", return_value=0):
            # Run installer main; it should not sys.exit on success
            try:
                install.main()
            except SystemExit as e:
                self.fail(f"Installer exited unexpectedly with code {e.code}")

        # Validate .env files exist in output_dir (at least one) and no docker-compose.yml
        written_files = os.listdir(self.output_dir)
        env_files = [f for f in written_files if f.endswith(".env")]

        self.assertGreater(
            len(env_files),
            0,
            f"Expected .env files in {self.output_dir}, found: {written_files}",
        )
        self.assertFalse(
            os.path.isfile(os.path.join(self.output_dir, "docker-compose.yml")),
            "docker-compose.yml should not be written in Kubernetes mode",
        )


if __name__ == "__main__":
    unittest.main()
