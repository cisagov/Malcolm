"""Tests for installer handling of local SELinux mounts and the OpenSearch keystore."""

import os
from pathlib import Path
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scripts.installer.configs.constants.enums import InstallerResult
from scripts.installer.platforms.utils import linux_tweaks
from scripts.malcolm_constants import OrchestrationFramework


KEYSTORE_TARGET = "/usr/share/opensearch/config/persist/opensearch.keystore"


class TestSelinuxKeystoreTweaks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "config").mkdir()
        (self.root / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
        (self.root / "opensearch").mkdir()
        self.config_dir = str(self.root / "config")
        self.keystore = self.root / "opensearch/opensearch.keystore"
        self.platform = SimpleNamespace(
            is_dry_run=Mock(return_value=False),
            orchestration_mode=OrchestrationFramework.DOCKER_COMPOSE,
            run_process=Mock(return_value=(0, [])),
        )
        self.ctx = SimpleNamespace(auto_tweaks=True)
        self.config = SimpleNamespace(get_value=Mock(side_effect=lambda key: {
            "processUserId": 1000, "processGroupId": 1000,
        }.get(key)))

    def _compose(self, volumes):
        return {"services": {"opensearch": {"volumes": volumes}}}

    def _keystore_mount(self):
        return {"type": "bind", "source": "./opensearch/opensearch.keystore", "target": KEYSTORE_TARGET,
                "bind": {"create_host_path": False}}

    def test_keystore_placeholder_created_without_replacing_existing_keystore(self):
        with patch("scripts.malcolm_common.LoadYaml", return_value=self._compose([self._keystore_mount()])):
            with patch("os.geteuid", return_value=1000):
                result, _ = linux_tweaks.prepare_opensearch_keystore(self.config, self.config_dir, self.platform)
                self.assertEqual(result, InstallerResult.SUCCESS)
                self.assertEqual(self.keystore.stat().st_size, 0)
                self.assertEqual(stat.S_IMODE(self.keystore.stat().st_mode), 0o600)
                self.keystore.write_bytes(b"existing-keystore-data")
                result, _ = linux_tweaks.prepare_opensearch_keystore(self.config, self.config_dir, self.platform)
        self.assertEqual(result, InstallerResult.SUCCESS)
        self.assertEqual(self.keystore.read_bytes(), b"existing-keystore-data")

    def test_placeholder_uses_configured_uid_gid_when_installed_as_root(self):
        with patch("scripts.malcolm_common.LoadYaml", return_value=self._compose([self._keystore_mount()])):
            with patch("os.geteuid", return_value=0), patch("os.chown") as chown:
                result, _ = linux_tweaks.prepare_opensearch_keystore(self.config, self.config_dir, self.platform)
        self.assertEqual(result, InstallerResult.SUCCESS)
        chown.assert_called_once_with(str(self.keystore), 1000, 1000)

    def test_keystore_is_not_created_during_dry_run(self):
        self.platform.is_dry_run.return_value = True
        result, _ = linux_tweaks.prepare_opensearch_keystore(self.config, self.config_dir, self.platform)
        self.assertEqual(result, InstallerResult.SKIPPED)
        self.assertFalse(self.keystore.exists())

    def test_wrong_type_existing_bind_is_rejected(self):
        self.keystore.mkdir()
        with patch("scripts.malcolm_common.LoadYaml", return_value=self._compose([self._keystore_mount()])):
            result, _ = linux_tweaks.prepare_opensearch_keystore(self.config, self.config_dir, self.platform)
        self.assertEqual(result, InstallerResult.FAILURE)

    def test_compose_sources_skip_external_paths_symlinks_and_install_root(self):
        (self.root / "shared").mkdir()
        (self.root / "external-link").symlink_to(self.root / "shared", target_is_directory=True)
        volumes = [
            {"type": "bind", "source": "./shared", "target": "/shared"},
            {"type": "bind", "source": "../outside", "target": "/outside"},
            {"type": "bind", "source": "./", "target": "/root"},
            {"type": "bind", "source": "./external-link", "target": "/link"},
            {"type": "volume", "source": "named", "target": "/named"},
            "named-other:/named-other",
        ]
        with patch("scripts.malcolm_common.LoadYaml", return_value=self._compose(volumes)):
            mounts = linux_tweaks._compose_bind_sources(self.config_dir)
        self.assertEqual(mounts, [("opensearch", "/shared", str(self.root / "shared"))])

    def test_selinux_relabels_only_local_existing_bind_sources(self):
        (self.root / "shared").mkdir()
        (self.root / "shared" / "test.crt").write_text("test", encoding="utf-8")
        self.keystore.touch()
        other_service = {"volumes": [
            {"type": "bind", "source": "./shared", "target": "/ca-trust"},
            {"type": "bind", "source": "/var/lib/external-data", "target": "/external"},
        ]}
        compose = self._compose([
            {"type": "bind", "source": "./shared", "target": "/ca-trust"},
            self._keystore_mount(),
        ])
        compose["services"]["filebeat"] = other_service
        with patch("scripts.malcolm_common.LoadYaml", return_value=compose), patch.object(
            linux_tweaks, "which", return_value="/usr/bin/tool"
        ):
            result, _ = linux_tweaks.apply_selinux_volume_contexts(
                self.config, self.config_dir, self.platform, self.ctx
            )
        self.assertEqual(result, InstallerResult.SUCCESS)
        calls = [call.args[0] for call in self.platform.run_process.call_args_list]
        self.assertEqual(calls[0], ["selinuxenabled"])
        self.assertEqual(
            set(tuple(cmd) for cmd in calls[1:]),
            {
                ("chcon", "-R", "-t", "container_file_t", str(self.root / "shared")),
                ("chcon", "-R", "-t", "container_file_t", str(self.keystore)),
            },
        )

    def test_selinux_disabled_or_tweak_not_selected(self):
        with patch.object(linux_tweaks, "which", return_value="/usr/bin/tool"):
            self.platform.run_process.return_value = (1, [])
            result, _ = linux_tweaks.apply_selinux_volume_contexts(
                self.config, self.config_dir, self.platform, self.ctx
            )
            self.assertEqual(result, InstallerResult.SKIPPED)
            self.ctx.auto_tweaks = False
            result, _ = linux_tweaks.apply_selinux_volume_contexts(
                self.config, self.config_dir, self.platform, self.ctx
            )
            self.assertEqual(result, InstallerResult.SKIPPED)

    def test_failed_relabel_does_not_silently_succeed(self):
        self.keystore.touch()
        with patch("scripts.malcolm_common.LoadYaml", return_value=self._compose([self._keystore_mount()])), patch.object(
            linux_tweaks, "which", return_value="/usr/bin/tool"
        ):
            self.platform.run_process.side_effect = [(0, []), (1, ["permission denied"])]
            result, _ = linux_tweaks.apply_selinux_volume_contexts(
                self.config, self.config_dir, self.platform, self.ctx
            )
        self.assertEqual(result, InstallerResult.FAILURE)


if __name__ == "__main__":
    unittest.main()
