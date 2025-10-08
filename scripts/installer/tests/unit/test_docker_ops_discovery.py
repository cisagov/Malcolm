#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""unit tests for compose command discovery (docker vs podman).

keeps 1:1 parity with legacy order:
- docker: try "docker compose" then fallback to "docker-compose"
- podman: try "podman compose" then fallback to "podman-compose"
"""

import unittest

from scripts.installer.actions.shared import discover_compose_command as _discover_compose_command


class _MiniPlatform:
    """minimal platform stub implementing run_process"""

    def __init__(self, results):
        # map command string -> (return_code, output_lines)
        self.results = results or {}

    def run_process(
        self,
        command,
        privileged=False,
        stdin=None,
        retry=1,
        retry_sleep_sec=5,
        stderr=True,
    ):
        key = " ".join(command)
        return self.results.get(key, (1, []))


class TestComposeDiscovery(unittest.TestCase):
    def test_docker_primary_succeeds(self):
        # docker compose works
        platform = _MiniPlatform(
            {"docker compose --version": (0, ["Docker Compose version v2.24.0"])}
        )
        cmd = _discover_compose_command("docker", platform)
        self.assertEqual(cmd, ["docker", "compose"])

    def test_docker_fallback_to_standalone(self):
        # docker compose fails, docker-compose works
        platform = _MiniPlatform(
            {
                "docker compose --version": (1, ["not found"]),
                "docker-compose --version": (0, ["docker-compose version 1.29.2"]),
            }
        )
        cmd = _discover_compose_command("docker", platform)
        self.assertEqual(cmd, ["docker-compose"])

    def test_podman_primary_succeeds(self):
        # podman compose works
        platform = _MiniPlatform(
            {"podman compose --version": (0, ["podman-compose version 1.0"])}
        )
        cmd = _discover_compose_command("podman", platform)
        self.assertEqual(cmd, ["podman", "compose"])

    def test_podman_fallback_to_podman_compose(self):
        # podman compose fails, podman-compose works
        platform = _MiniPlatform(
            {
                "podman compose --version": (1, ["not found"]),
                "podman-compose --version": (0, ["podman-compose version 1.0"]),
            }
        )
        cmd = _discover_compose_command("podman", platform)
        self.assertEqual(cmd, ["podman-compose"])

    def test_unknown_runtime_attempts_compose_only(self):
        # unknown runtime: try "<bin> compose" then give up
        platform = _MiniPlatform(
            {"nerdctl compose --version": (0, ["compose v2 shim"])}
        )
        cmd = _discover_compose_command("nerdctl", platform)
        self.assertEqual(cmd, ["nerdctl", "compose"])

        platform2 = _MiniPlatform({"nerdctl compose --version": (1, ["not found"])})
        cmd2 = _discover_compose_command("nerdctl", platform2)
        self.assertIsNone(cmd2)


if __name__ == "__main__":
    unittest.main()
