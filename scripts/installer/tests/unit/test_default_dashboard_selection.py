"""Tests for choosing the OpenSearch Dashboards landing dashboard (issue #465)."""

import tempfile
import unittest
from pathlib import Path

from dotenv import dotenv_values

from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_DASHBOARDS_DEFAULT_DASHBOARD,
    KEY_CONFIG_ITEM_MALCOLM_PROFILE,
    KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
)
from scripts.installer.configs.constants.enums import SearchEngineMode
from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.malcolm_constants import PROFILE_HEDGEHOG, PROFILE_MALCOLM


class TestDefaultDashboardSelection(unittest.TestCase):
    OVERVIEW = "0ad3d7c2-3441-485e-9dfe-dbb22e84e576"
    SECURITY = "95479950-41f2-11ea-88fa-7151df485405"
    ICS = "4a4bde20-4760-11ea-949c-bbb5a9feecbf"
    SEVERITY = "d2dd0180-06b1-11ec-8c6b-353266ade330"

    def test_defaults_and_choices_match_bundled_dashboards(self):
        config = MalcolmConfig()
        item = config.get_item(KEY_CONFIG_ITEM_DASHBOARDS_DEFAULT_DASHBOARD)
        self.assertEqual(item.default_value, self.OVERVIEW)
        self.assertEqual(
            {choice[0] for choice in item.choices},
            {self.OVERVIEW, self.SECURITY, self.ICS, self.SEVERITY},
        )
        dashboards_dir = Path(__file__).resolve().parents[4] / "dashboards/dashboards"
        for dashboard_id in (self.OVERVIEW, self.SECURITY, self.ICS, self.SEVERITY):
            with self.subTest(dashboard_id=dashboard_id):
                self.assertTrue((dashboards_dir / f"{dashboard_id}.json").is_file())

    def test_dashboard_selection_roundtrips_into_generated_environment(self):
        for dashboard_id in (self.OVERVIEW, self.SECURITY, self.ICS, self.SEVERITY):
            with self.subTest(dashboard_id=dashboard_id), tempfile.TemporaryDirectory() as temp_dir:
                config = MalcolmConfig()
                config.set_value(KEY_CONFIG_ITEM_DASHBOARDS_DEFAULT_DASHBOARD, dashboard_id)
                config.generate_env_files(temp_dir)
                env = dotenv_values(Path(temp_dir) / "dashboards-helper.env")
                self.assertEqual(env["OPENSEARCH_DEFAULT_DASHBOARD"], dashboard_id)

                imported = MalcolmConfig()
                imported.load_from_env_files(temp_dir)
                self.assertEqual(
                    imported.get_value(KEY_CONFIG_ITEM_DASHBOARDS_DEFAULT_DASHBOARD),
                    dashboard_id,
                )

    def test_custom_dashboard_id_survives_environment_import(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / "dashboards-helper.env"
            env_file.write_text("OPENSEARCH_DEFAULT_DASHBOARD=custom-user-dashboard\n")
            config = MalcolmConfig()
            config.load_from_env_files(temp_dir)
            self.assertEqual(
                config.get_value(KEY_CONFIG_ITEM_DASHBOARDS_DEFAULT_DASHBOARD),
                "custom-user-dashboard",
            )
            config.generate_env_files(temp_dir)
            self.assertEqual(
                dotenv_values(env_file)["OPENSEARCH_DEFAULT_DASHBOARD"],
                "custom-user-dashboard",
            )

    def test_only_visible_with_malcolm_dashboards(self):
        config = MalcolmConfig()
        key = KEY_CONFIG_ITEM_DASHBOARDS_DEFAULT_DASHBOARD
        self.assertTrue(config.is_item_visible(key))
        config.set_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE, PROFILE_HEDGEHOG)
        self.assertFalse(config.is_item_visible(key))
        config.set_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE, PROFILE_MALCOLM)
        self.assertTrue(config.is_item_visible(key))
        config.set_value(
            KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            SearchEngineMode.ELASTICSEARCH_REMOTE.value,
        )
        self.assertFalse(config.is_item_visible(key))


if __name__ == "__main__":
    unittest.main()
