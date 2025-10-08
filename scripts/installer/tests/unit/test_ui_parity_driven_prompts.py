#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
UI parity tests that drive TUI and DUI prompt paths via monkeypatching
and assert identical MalcolmConfig state and generated .env outputs.

This test purposefully exercises the shared prompt layer used by both UIs
without introducing new test-only hooks in production code.
"""

import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from scripts.malcolm_common import UserInterfaceMode
from scripts.malcolm_constants import OrchestrationFramework
from scripts.installer.configs.constants.enums import ControlFlow

from scripts.installer.configs.constants.constants import MAIN_MENU_KEYS
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_BEHIND_REVERSE_PROXY,
    KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME,
    KEY_CONFIG_ITEM_DOCKER_EXTRA_USERS,
    KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
    KEY_CONFIG_ITEM_LS_WORKERS,
    KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY,
    KEY_CONFIG_ITEM_PROCESS_GROUP_ID,
    KEY_CONFIG_ITEM_PROCESS_USER_ID,
    KEY_CONFIG_ITEM_RUNTIME_BIN,
)
from scripts.installer.configs.constants.installation_item_keys import (
    KEY_INSTALLATION_ITEM_AUTO_TWEAKS,
    KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING,
    KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY,
    KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT,
    KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES,
    KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES,
)

from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.installer.core.install_context import InstallContext

from scripts.installer.ui.tui.configuration_menu import ConfigurationMenu
from scripts.installer.ui.tui.installation_menu import InstallationMenu
from scripts.installer.ui.dui.dialog_configuration_menu import DialogConfigurationMenu

from scripts.installer.platforms.linux import LinuxInstaller


class TestUIParityDrivenPrompts(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        # Answers for configuration items (covering bool, string, int, list, enum-like choice)
        self.config_answers = {
            KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE: OrchestrationFramework.DOCKER_COMPOSE,
            KEY_CONFIG_ITEM_RUNTIME_BIN: "docker",
            KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY: "unless-stopped",
            KEY_CONFIG_ITEM_BEHIND_REVERSE_PROXY: True,
            KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME: "custom_net",
            KEY_CONFIG_ITEM_DOCKER_EXTRA_USERS: ["alice", "bob"],
            KEY_CONFIG_ITEM_PROCESS_USER_ID: 1001,
            KEY_CONFIG_ITEM_PROCESS_GROUP_ID: 1001,
            KEY_CONFIG_ITEM_LS_WORKERS: 4,
        }

        # Answers for installation items (booleans with simple dependencies)
        self.install_answers = {
            KEY_INSTALLATION_ITEM_AUTO_TWEAKS: True,
            KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING: True,
            KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY: True,
            KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT: False,
            # image source exclusivity: pick one
            KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES: True,
            KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES: False,
        }

        # Fresh state for each UI path
        self.mc_tui = MalcolmConfig()
        self.ctx_tui = InstallContext()
        self.ctx_tui.initialize_for_platform("linux")

        self.mc_dui = MalcolmConfig()
        self.ctx_dui = InstallContext()
        self.ctx_dui.initialize_for_platform("linux")

        # Platform installer (used by TUI InstallationMenu)
        self.platform = LinuxInstaller(
            OrchestrationFramework.DOCKER_COMPOSE,
            ui=None,
            debug=False,
            control_flow=ControlFlow.DRYRUN,
        )

        # temp dirs for env output
        self.tmpdir_tui = tempfile.mkdtemp(prefix="malc_tui_")
        self.tmpdir_dui = tempfile.mkdtemp(prefix="malc_dui_")

    def tearDown(self):
        shutil.rmtree(self.tmpdir_tui, ignore_errors=True)
        shutil.rmtree(self.tmpdir_dui, ignore_errors=True)

    def _scripted_prompt(
        self, ui_mode, config_item, back_label=None, show_preamble=True
    ):
        # Return preselected answers by key when present; otherwise keep current value
        key = getattr(config_item, "key", None)
        if key in self.config_answers:
            return self.config_answers[key]
        if key in self.install_answers:
            return self.install_answers[key]
        return config_item.get_value()

    def _apply_config_answers_via_tui(self):
        # apply in deterministic order so dependency rules behave consistently across UIs
        def ordered_keys():
            preferred = [
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
                KEY_CONFIG_ITEM_RUNTIME_BIN,
            ]
            rest = [k for k in self.config_answers.keys() if k not in preferred]
            return preferred + rest

        menu = ConfigurationMenu(
            self.mc_tui,
            self.ctx_tui,
            main_menu_keys=MAIN_MENU_KEYS,
            ui_mode=UserInterfaceMode.InteractionInput,
        )
        for key in ordered_keys():
            menu.build_menu()
            if key in menu.displayed_keys:
                idx = menu.displayed_keys.index(key)
                menu._handle_item_selection(idx)

    def _apply_install_answers_via_tui(self):
        inst_menu = InstallationMenu(
            self.platform,
            self.mc_tui,
            self.ctx_tui,
            ui_mode=UserInterfaceMode.InteractionInput,
        )
        inst_menu.build_menu()
        # Try to set any answers that appear in the current display set
        key_to_index = {
            e.get("key"): i
            for i, e in enumerate(inst_menu.displayed_entries)
            if e.get("kind") == "config"
        }
        for e in inst_menu.displayed_entries:
            k = e.get("key")
            if e.get("kind") == "config" and k in self.install_answers:
                inst_menu._handle_item_selection(key_to_index[k])

    def _apply_config_answers_via_dui(self):
        menu = DialogConfigurationMenu(
            self.mc_dui,
            self.ctx_dui,
            MAIN_MENU_KEYS,
            ui_mode=UserInterfaceMode.InteractionDialog,
        )

        # apply in the same deterministic order as TUI; prompt regardless of current visibility
        def ordered_keys():
            preferred = [
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
                KEY_CONFIG_ITEM_RUNTIME_BIN,
            ]
            rest = [k for k in self.config_answers.keys() if k not in preferred]
            return preferred + rest

        for key in ordered_keys():
            item = self.mc_dui.get_item(key)
            if item and self.mc_dui.is_item_visible(key):
                menu._prompt_for_item_value(key)

    def _apply_install_answers_via_dui(self):
        # For installation items, directly prompt/set using the shared prompt helper
        from scripts.installer.ui.shared.prompt_utils import prompt_config_item_value

        for key, item in self.ctx_dui.items.items():
            if key in self.install_answers:
                # simulate a DUI prompt for this item and apply the returned value
                val = prompt_config_item_value(
                    ui_mode=UserInterfaceMode.InteractionDialog,
                    config_item=item,
                    back_label="Back",
                    show_preamble=True,
                )
                if val is not None:
                    self.ctx_dui.set_item_value(key, val)

    def _compare_env_dirs(self, dir_a: str, dir_b: str):
        files_a = sorted([f for f in os.listdir(dir_a) if f.endswith(".env")])
        files_b = sorted([f for f in os.listdir(dir_b) if f.endswith(".env")])
        self.assertListEqual(
            files_a, files_b, "Generated env file names differ between UIs"
        )
        for name in files_a:
            path_a = os.path.join(dir_a, name)
            path_b = os.path.join(dir_b, name)
            with open(path_a, "r", encoding="utf-8") as fa, open(
                path_b, "r", encoding="utf-8"
            ) as fb:
                la = [ln for ln in fa.read().splitlines() if not ln.startswith("#")]
                lb = [ln for ln in fb.read().splitlines() if not ln.startswith("#")]
                self.assertEqual(
                    la,
                    lb,
                    f"Contents differ in {name} between UIs (ignoring header comments)",
                )

    def test_tui_dui_parity_env_and_state(self):
        self._run_parity_assertions()

    def _run_parity_assertions(self):
        # Monkeypatch the shared prompt to return our scripted answers by key
        with patch(
            "scripts.installer.ui.shared.prompt_utils.prompt_config_item_value",
            side_effect=self._scripted_prompt,
        ), patch(
            "scripts.installer.ui.tui.base_menu.prompt_config_item_value",
            side_effect=self._scripted_prompt,
        ), patch(
            "scripts.installer.ui.dui.dialog_configuration_menu.prompt_config_item_value",
            side_effect=self._scripted_prompt,
        ), patch(
            "scripts.installer.ui.dui.dialog_installation_menu.prompt_config_item_value",
            side_effect=self._scripted_prompt,
        ):
            # Apply answers through TUI prompt paths
            self._apply_config_answers_via_tui()
            self._apply_install_answers_via_tui()

            # Apply answers through DUI prompt paths
            self._apply_config_answers_via_dui()
            self._apply_install_answers_via_dui()

        # Parity: MalcolmConfig values should match
        self.assertEqual(
            self.mc_tui.to_dict_values_only(),
            self.mc_dui.to_dict_values_only(),
            "MalcolmConfig values differ between TUI and DUI",
        )

        # Parity: InstallContext item values should match for keys we touched (and generally)
        for key in self.ctx_tui.items.keys():
            self.assertEqual(
                self.ctx_tui.get_item_value(key),
                self.ctx_dui.get_item_value(key),
                f"InstallContext value for {key} differs between UIs",
            )

        # Generate .env outputs and assert identical results
        self.mc_tui.generate_env_files(self.tmpdir_tui)
        self.mc_dui.generate_env_files(self.tmpdir_dui)
        self._compare_env_dirs(self.tmpdir_tui, self.tmpdir_dui)

    def test_tui_dui_parity_podman_env_and_state(self):
        # Reset state for podman scenario
        shutil.rmtree(self.tmpdir_tui, ignore_errors=True)
        shutil.rmtree(self.tmpdir_dui, ignore_errors=True)
        self.tmpdir_tui = tempfile.mkdtemp(prefix="malc_tui_")
        self.tmpdir_dui = tempfile.mkdtemp(prefix="malc_dui_")
        self.mc_tui = MalcolmConfig()
        self.ctx_tui = InstallContext()
        self.ctx_tui.initialize_for_platform("linux")
        self.mc_dui = MalcolmConfig()
        self.ctx_dui = InstallContext()
        self.ctx_dui.initialize_for_platform("linux")
        self.platform = LinuxInstaller(
            OrchestrationFramework.DOCKER_COMPOSE,
            ui=None,
            debug=False,
            control_flow=ControlFlow.DRYRUN,
        )

        # Update answers for podman runtime
        self.config_answers.update(
            {
                KEY_CONFIG_ITEM_RUNTIME_BIN: "podman",
                KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY: "always",
            }
        )
        # Installation answers remain meaningful but not env-affecting
        self.install_answers.update(
            {
                KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY: False,
                KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT: False,
                KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES: False,
                KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES: False,
            }
        )

        self._run_parity_assertions()

    def test_tui_dui_parity_kubernetes_env_and_state(self):
        # Reset state for Kubernetes scenario
        shutil.rmtree(self.tmpdir_tui, ignore_errors=True)
        shutil.rmtree(self.tmpdir_dui, ignore_errors=True)
        self.tmpdir_tui = tempfile.mkdtemp(prefix="malc_tui_")
        self.tmpdir_dui = tempfile.mkdtemp(prefix="malc_dui_")
        self.mc_tui = MalcolmConfig()
        self.ctx_tui = InstallContext()
        self.ctx_tui.initialize_for_platform("linux")
        self.mc_dui = MalcolmConfig()
        self.ctx_dui = InstallContext()
        self.ctx_dui.initialize_for_platform("linux")
        self.platform = LinuxInstaller(
            OrchestrationFramework.KUBERNETES,
            ui=None,
            debug=False,
            control_flow=ControlFlow.DRYRUN,
        )

        # Minimal Kubernetes answers: switch orchestration; keep runtime docker (irrelevant to env)
        # Set orchestration directly on both configs to avoid menu/reachability divergence
        self.mc_tui.set_value(
            KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE, OrchestrationFramework.KUBERNETES
        )
        self.mc_dui.set_value(
            KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE, OrchestrationFramework.KUBERNETES
        )
        # Ensure prompt layer does not attempt to set this key asymmetrically
        self.config_answers.pop(KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE, None)
        # Keep runtime for completeness (has no effect under K8s for env generation)
        self.config_answers.update(
            {
                KEY_CONFIG_ITEM_RUNTIME_BIN: "docker",
            }
        )
        # Avoid manually setting values that dependency rules override under Kubernetes
        self.config_answers.pop(KEY_CONFIG_ITEM_LS_WORKERS, None)
        # Installation answers: minimal
        self.install_answers.update(
            {
                KEY_INSTALLATION_ITEM_AUTO_TWEAKS: True,
                KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING: False,
            }
        )

        self._run_parity_assertions()


if __name__ == "__main__":
    unittest.main()
