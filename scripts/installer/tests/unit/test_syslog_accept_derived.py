import os
import tempfile
import unittest

from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES,
    KEY_CONFIG_ITEM_SYSLOG_TCP_PORT,
    KEY_CONFIG_ITEM_SYSLOG_UDP_PORT,
)
from scripts.installer.configs.constants.config_env_var_keys import (
    KEY_ENV_FILEBEAT_SYSLOG_TCP_PORT,
    KEY_ENV_FILEBEAT_SYSLOG_UDP_PORT,
    KEY_ENV_FILEBEAT_SYSLOG_TCP_LISTEN,
    KEY_ENV_FILEBEAT_SYSLOG_UDP_LISTEN,
)
from scripts.installer.core.malcolm_config import MalcolmConfig


class TestSyslogAcceptDerived(unittest.TestCase):
    """Test that ACCEPT_STANDARD_SYSLOG_MESSAGES is properly derived from port values."""

    def setUp(self):
        self.config = MalcolmConfig()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        # clean up the temporary directory
        for root, dirs, files in os.walk(self.temp_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.temp_dir)

    def _roundtrip_and_load(self, config: MalcolmConfig):
        # write env files from config and load them into a fresh config instance
        config.generate_env_files(self.temp_dir)
        new_config = MalcolmConfig()
        new_config.load_from_env_files(self.temp_dir)
        return new_config

    def test_accept_syslog_false_when_ports_unset(self):
        """When ports are None, accept_syslog should remain False."""
        # Default config has no ports set
        self.assertIsNone(self.config.get_value(KEY_CONFIG_ITEM_SYSLOG_TCP_PORT))
        self.assertIsNone(self.config.get_value(KEY_CONFIG_ITEM_SYSLOG_UDP_PORT))
        self.assertFalse(self.config.get_value(KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES))

        # Roundtrip and verify
        cfg2 = self._roundtrip_and_load(self.config)
        self.assertIsNone(cfg2.get_value(KEY_CONFIG_ITEM_SYSLOG_TCP_PORT))
        self.assertIsNone(cfg2.get_value(KEY_CONFIG_ITEM_SYSLOG_UDP_PORT))
        self.assertFalse(cfg2.get_value(KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES))

    def test_accept_syslog_true_when_tcp_port_set(self):
        """When TCP port is set to non-zero, accept_syslog should become True."""
        # Set TCP port
        self.config.set_value(KEY_CONFIG_ITEM_SYSLOG_TCP_PORT, 514)
        self.config.set_value(KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES, True)

        # Roundtrip and verify both port and accept flag are restored
        cfg2 = self._roundtrip_and_load(self.config)
        self.assertEqual(514, cfg2.get_value(KEY_CONFIG_ITEM_SYSLOG_TCP_PORT))
        self.assertTrue(cfg2.get_value(KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES))

    def test_accept_syslog_true_when_udp_port_set(self):
        """When UDP port is set to non-zero, accept_syslog should become True."""
        # Set UDP port
        self.config.set_value(KEY_CONFIG_ITEM_SYSLOG_UDP_PORT, 514)
        self.config.set_value(KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES, True)

        # Roundtrip and verify both port and accept flag are restored
        cfg2 = self._roundtrip_and_load(self.config)
        self.assertEqual(514, cfg2.get_value(KEY_CONFIG_ITEM_SYSLOG_UDP_PORT))
        self.assertTrue(cfg2.get_value(KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES))

    def test_accept_syslog_true_when_both_ports_set(self):
        """When both ports are set, accept_syslog should be True."""
        # Set both ports
        self.config.set_value(KEY_CONFIG_ITEM_SYSLOG_TCP_PORT, 514)
        self.config.set_value(KEY_CONFIG_ITEM_SYSLOG_UDP_PORT, 514)
        self.config.set_value(KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES, True)

        # Roundtrip and verify
        cfg2 = self._roundtrip_and_load(self.config)
        self.assertEqual(514, cfg2.get_value(KEY_CONFIG_ITEM_SYSLOG_TCP_PORT))
        self.assertEqual(514, cfg2.get_value(KEY_CONFIG_ITEM_SYSLOG_UDP_PORT))
        self.assertTrue(cfg2.get_value(KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES))

    def test_direct_env_import_with_tcp_port(self):
        """Test loading directly from env file with TCP port set."""
        # Manually write env file with TCP port
        mapper = self.config.get_env_mapper()
        tcp_env = mapper.env_var_by_map_key[KEY_ENV_FILEBEAT_SYSLOG_TCP_PORT]

        env_file_path = os.path.join(self.temp_dir, tcp_env.file_name)
        with open(env_file_path, "w") as f:
            f.write(f"{tcp_env.variable_name}=514\n")

        # Load and verify
        cfg2 = MalcolmConfig()
        cfg2.load_from_env_files(self.temp_dir)

        self.assertEqual(514, cfg2.get_value(KEY_CONFIG_ITEM_SYSLOG_TCP_PORT))
        self.assertTrue(cfg2.get_value(KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES))

    def test_direct_env_import_with_udp_port(self):
        """Test loading directly from env file with UDP port set."""
        # Manually write env file with UDP port
        mapper = self.config.get_env_mapper()
        udp_env = mapper.env_var_by_map_key[KEY_ENV_FILEBEAT_SYSLOG_UDP_PORT]

        env_file_path = os.path.join(self.temp_dir, udp_env.file_name)
        with open(env_file_path, "w") as f:
            f.write(f"{udp_env.variable_name}=514\n")

        # Load and verify
        cfg2 = MalcolmConfig()
        cfg2.load_from_env_files(self.temp_dir)

        self.assertEqual(514, cfg2.get_value(KEY_CONFIG_ITEM_SYSLOG_UDP_PORT))
        self.assertTrue(cfg2.get_value(KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES))

    def test_direct_env_import_with_zero_port(self):
        """Test that port=0 in env file results in accept_syslog=False."""
        # Manually write env file with port=0
        mapper = self.config.get_env_mapper()
        tcp_env = mapper.env_var_by_map_key[KEY_ENV_FILEBEAT_SYSLOG_TCP_PORT]

        env_file_path = os.path.join(self.temp_dir, tcp_env.file_name)
        with open(env_file_path, "w") as f:
            f.write(f"{tcp_env.variable_name}=0\n")

        # Load and verify
        cfg2 = MalcolmConfig()
        cfg2.load_from_env_files(self.temp_dir)

        # Port=0 should be treated as None/unset
        self.assertIsNone(cfg2.get_value(KEY_CONFIG_ITEM_SYSLOG_TCP_PORT))
        self.assertFalse(cfg2.get_value(KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES))

    def test_listen_env_vars_are_written_correctly(self):
        """Verify that listen env vars are derived and written correctly."""
        # Set TCP and UDP ports
        self.config.set_value(KEY_CONFIG_ITEM_SYSLOG_TCP_PORT, 514)
        self.config.set_value(KEY_CONFIG_ITEM_SYSLOG_UDP_PORT, 514)
        self.config.set_value(KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES, True)

        # Generate env files
        self.config.generate_env_files(self.temp_dir)

        # Read the env file and verify listen flags are written as "true"
        mapper = self.config.get_env_mapper()
        tcp_env = mapper.env_var_by_map_key[KEY_ENV_FILEBEAT_SYSLOG_TCP_PORT]
        tcp_listen_env = mapper.env_var_by_map_key[KEY_ENV_FILEBEAT_SYSLOG_TCP_LISTEN]
        udp_listen_env = mapper.env_var_by_map_key[KEY_ENV_FILEBEAT_SYSLOG_UDP_LISTEN]

        env_file_path = os.path.join(self.temp_dir, tcp_env.file_name)
        with open(env_file_path, "r") as f:
            content = f.read()

        self.assertIn(f"{tcp_env.variable_name}=514", content)
        self.assertIn(f"{tcp_listen_env.variable_name}=true", content)
        self.assertIn(f"{udp_listen_env.variable_name}=true", content)

    def test_listen_env_vars_written_false_when_ports_unset(self):
        """Verify that listen env vars are false when ports are unset."""
        # Leave ports as None (default)
        self.assertIsNone(self.config.get_value(KEY_CONFIG_ITEM_SYSLOG_TCP_PORT))
        self.assertIsNone(self.config.get_value(KEY_CONFIG_ITEM_SYSLOG_UDP_PORT))

        # Generate env files
        self.config.generate_env_files(self.temp_dir)

        # Read the env file and verify listen flags are written as "false"
        mapper = self.config.get_env_mapper()
        tcp_env = mapper.env_var_by_map_key[KEY_ENV_FILEBEAT_SYSLOG_TCP_PORT]
        tcp_listen_env = mapper.env_var_by_map_key[KEY_ENV_FILEBEAT_SYSLOG_TCP_LISTEN]
        udp_listen_env = mapper.env_var_by_map_key[KEY_ENV_FILEBEAT_SYSLOG_UDP_LISTEN]

        env_file_path = os.path.join(self.temp_dir, tcp_env.file_name)
        with open(env_file_path, "r") as f:
            content = f.read()

        self.assertIn(f"{tcp_env.variable_name}=0", content)
        self.assertIn(f"{tcp_listen_env.variable_name}=false", content)
        self.assertIn(f"{udp_listen_env.variable_name}=false", content)

    def test_custom_port_values(self):
        """Test that non-standard port values work correctly."""
        # Set custom ports
        self.config.set_value(KEY_CONFIG_ITEM_SYSLOG_TCP_PORT, 5514)
        self.config.set_value(KEY_CONFIG_ITEM_SYSLOG_UDP_PORT, 5515)
        self.config.set_value(KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES, True)

        # Roundtrip and verify
        cfg2 = self._roundtrip_and_load(self.config)
        self.assertEqual(5514, cfg2.get_value(KEY_CONFIG_ITEM_SYSLOG_TCP_PORT))
        self.assertEqual(5515, cfg2.get_value(KEY_CONFIG_ITEM_SYSLOG_UDP_PORT))
        self.assertTrue(cfg2.get_value(KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES))


if __name__ == "__main__":
    unittest.main()
