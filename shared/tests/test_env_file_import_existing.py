import os
import tempfile
import unittest

from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.installer.configs.constants.config_env_var_keys import (
    KEY_ENV_FREQ_LOOKUP,
    KEY_ENV_ARKIME_MANAGE_PCAP_FILES,
)
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_AUTO_FREQ,
    KEY_CONFIG_ITEM_ARKIME_MANAGE_PCAP,
    KEY_CONFIG_ITEM_MALCOLM_PROFILE,
    KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
    KEY_CONFIG_ITEM_LIVE_ARKIME,
    KEY_CONFIG_ITEM_PCAP_NETSNIFF,
    KEY_CONFIG_ITEM_PCAP_TCPDUMP,
)


class TestEnvFileImportExisting(unittest.TestCase):
    """Validate that loading existing/legacy .env files with string boolean values works"""

    def setUp(self):
        # create a temporary directory mimicking the config dir containing .env files
        self.temp_dir = tempfile.mkdtemp()

        # Prepare a MalcolmConfig solely to query the EnvMapper for file locations & variable names
        self.reference_config = MalcolmConfig()
        mapper = self.reference_config.get_env_mapper()

        # Helper to write a single env variable to its correct file
        def _write_env_var(map_key: str, raw_value: str):
            env_var = mapper.env_var_by_map_key[map_key]
            file_path = os.path.join(self.temp_dir, env_var.file_name)
            with open(file_path, "a") as fp:
                fp.write(f"{env_var.variable_name}={raw_value}\n")

        # Simulate legacy boolean strings for several variables
        _write_env_var(KEY_ENV_FREQ_LOOKUP, "true")
        _write_env_var(KEY_ENV_ARKIME_MANAGE_PCAP_FILES, "false")

    def tearDown(self):
        # Clean up the temporary directory tree
        for root, dirs, files in os.walk(self.temp_dir, topdown=False):
            for fname in files:
                os.remove(os.path.join(root, fname))
            for dname in dirs:
                os.rmdir(os.path.join(root, dname))
        os.rmdir(self.temp_dir)

    def test_import_legacy_env_files(self):
        cfg = MalcolmConfig()

        # Loading should not raise and should correctly convert the values
        try:
            cfg.load_from_env_files(self.temp_dir)
        except Exception as e:
            self.fail(f"load_from_env_files raised an exception: {e}")

        self.assertTrue(cfg.get_value(KEY_CONFIG_ITEM_AUTO_FREQ))
        # "false" for MANAGE_PCAP_FILES translates to False boolean
        self.assertFalse(cfg.get_value(KEY_CONFIG_ITEM_ARKIME_MANAGE_PCAP))


    def test_saved_disabled_arkime_remains_disabled_after_reload(self):
        """Loading a full Hedgehog config must not re-enable live Arkime."""
        from scripts.malcolm_constants import PROFILE_HEDGEHOG

        previous = MalcolmConfig()
        previous.set_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE, PROFILE_HEDGEHOG)
        previous.set_value(KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC, True)
        previous.set_value(KEY_CONFIG_ITEM_LIVE_ARKIME, False)
        previous.set_value(KEY_CONFIG_ITEM_PCAP_NETSNIFF, False)
        previous.set_value(KEY_CONFIG_ITEM_PCAP_TCPDUMP, False)
        self.assertFalse(previous.get_value(KEY_CONFIG_ITEM_LIVE_ARKIME))

        with tempfile.TemporaryDirectory() as config_dir:
            previous.generate_env_files(config_dir)
            restored = MalcolmConfig()
            restored.load_from_env_files(config_dir)

        self.assertTrue(restored.get_value(KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC))
        self.assertFalse(restored.get_value(KEY_CONFIG_ITEM_LIVE_ARKIME))
        self.assertFalse(restored.get_value(KEY_CONFIG_ITEM_PCAP_NETSNIFF))
        self.assertFalse(restored.get_value(KEY_CONFIG_ITEM_PCAP_TCPDUMP))
        self.assertFalse(restored._suspend_dependency_value_updates)

    def test_value_dependencies_resume_after_import(self):
        """User-driven edits still update derived live-capture settings."""
        cfg = MalcolmConfig()
        with tempfile.TemporaryDirectory() as config_dir:
            self.reference_config.generate_env_files(config_dir)
            cfg.load_from_env_files(config_dir)

        cfg.set_value(KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC, True)
        self.assertTrue(cfg.get_value(KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC))
        self.assertTrue(cfg.get_value(KEY_CONFIG_ITEM_PCAP_NETSNIFF))


if __name__ == "__main__":
    unittest.main()
