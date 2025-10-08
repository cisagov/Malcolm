import os
import tempfile
import unittest

from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.installer.configs.constants.config_env_var_keys import (
    KEY_ENV_FREQ_LOOKUP,
    KEY_ENV_PCAP_PIPELINE_POLLING,
    KEY_ENV_ARKIME_MANAGE_PCAP_FILES,
)
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_AUTO_FREQ,
    KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
    KEY_CONFIG_ITEM_ARKIME_MANAGE_PCAP,
)
from scripts.malcolm_constants import OrchestrationFramework


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
        _write_env_var(KEY_ENV_PCAP_PIPELINE_POLLING, "true")
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
        # "true" for PCAP_PIPELINE_POLLING translates to orchestrator mode OrchestrationFramework.KUBERNETES
        self.assertEqual(
            cfg.get_value(KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE),
            OrchestrationFramework.KUBERNETES,
        )
        # "false" for MANAGE_PCAP_FILES translates to False boolean
        self.assertFalse(cfg.get_value(KEY_CONFIG_ITEM_ARKIME_MANAGE_PCAP))


if __name__ == "__main__":
    unittest.main()
