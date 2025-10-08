import unittest
import os
import sys

# Add the project root directory to the Python path
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
)

from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
    KEY_CONFIG_ITEM_LIVE_ARKIME,
    KEY_CONFIG_ITEM_PCAP_NET_SNIFF,
    KEY_CONFIG_ITEM_LIVE_ZEEK,
    KEY_CONFIG_ITEM_LIVE_SURICATA,
    KEY_CONFIG_ITEM_TWEAK_IFACE,
    KEY_CONFIG_ITEM_CAPTURE_STATS,
    KEY_CONFIG_ITEM_MALCOLM_PROFILE,
    KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES,
    KEY_CONFIG_ITEM_SYSLOG_TCP_PORT,
    KEY_CONFIG_ITEM_SYSLOG_UDP_PORT,
    KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_SOURCE_FIELD,
    KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_TARGET_FIELD,
    KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_DROP_FIELD,
    KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT,
    KEY_CONFIG_ITEM_OPEN_PORTS,
    KEY_CONFIG_ITEM_EXPOSE_LOGSTASH,
    KEY_CONFIG_ITEM_EXPOSE_FILEBEAT_TCP,
    KEY_CONFIG_ITEM_EXPOSE_OPENSEARCH,
)
from scripts.malcolm_constants import PROFILE_HEDGEHOG, PROFILE_MALCOLM


class TestLiveCaptureDependencies(unittest.TestCase):
    """Verify that enabling live capture sets sensible default values for related options."""

    def _assert_live_capture_defaults(self, cfg, *, expect_arkime: bool):
        """Helper to assert post-conditions after live-capture is enabled."""
        self.assertEqual(cfg.get_value(KEY_CONFIG_ITEM_LIVE_ARKIME), expect_arkime)
        self.assertEqual(
            cfg.get_value(KEY_CONFIG_ITEM_PCAP_NET_SNIFF), not expect_arkime
        )
        # The following should always flip to True when live capture is enabled
        self.assertTrue(cfg.get_value(KEY_CONFIG_ITEM_LIVE_ZEEK))
        self.assertTrue(cfg.get_value(KEY_CONFIG_ITEM_LIVE_SURICATA))
        self.assertTrue(cfg.get_value(KEY_CONFIG_ITEM_TWEAK_IFACE))
        self.assertTrue(cfg.get_value(KEY_CONFIG_ITEM_CAPTURE_STATS))

    def test_live_capture_defaults_for_malcolm_profile(self):
        cfg = MalcolmConfig()  # defaults to PROFILE_MALCOLM + local OpenSearch
        # Pre-conditions
        self.assertFalse(cfg.get_value(KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC))

        cfg.set_value(KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC, True)
        self._assert_live_capture_defaults(cfg, expect_arkime=False)

    def test_live_capture_defaults_for_hedgehog_profile(self):
        cfg = MalcolmConfig()
        # Switch profile first to ensure dependency logic sees the new value
        cfg.set_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE, PROFILE_HEDGEHOG)
        cfg.set_value(KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC, True)
        self._assert_live_capture_defaults(cfg, expect_arkime=True)


class TestSyslogDependency(unittest.TestCase):
    """Ensure that opting into standard Syslog automatically assigns default ports."""

    def test_syslog_ports_default(self):
        cfg = MalcolmConfig()
        # Ports should be unset initially
        self.assertIsNone(cfg.get_value(KEY_CONFIG_ITEM_SYSLOG_TCP_PORT))
        self.assertIsNone(cfg.get_value(KEY_CONFIG_ITEM_SYSLOG_UDP_PORT))

        cfg.set_value(KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES, True)
        self.assertEqual(cfg.get_value(KEY_CONFIG_ITEM_SYSLOG_TCP_PORT), 514)
        self.assertEqual(cfg.get_value(KEY_CONFIG_ITEM_SYSLOG_UDP_PORT), 514)


class TestFilebeatJsonDefaults(unittest.TestCase):
    """Verify JSON log-format chooses sensible default source/target/drop fields."""

    def test_filebeat_json_defaults(self):
        cfg = MalcolmConfig()
        # With default log format "json", the following should be auto-populated
        self.assertEqual(cfg.get_value(KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT), "json")
        self.assertEqual(
            cfg.get_value(KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_SOURCE_FIELD), "message"
        )
        self.assertEqual(
            cfg.get_value(KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_TARGET_FIELD), "miscbeat"
        )
        self.assertEqual(
            cfg.get_value(KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_DROP_FIELD), "message"
        )


class TestOpenPortsDependency(unittest.TestCase):
    """Verify that selecting `yes` for open-ports enables related exposures by default."""

    def test_open_ports_yes_defaults(self):
        cfg = MalcolmConfig()
        cfg.set_value(KEY_CONFIG_ITEM_OPEN_PORTS, "yes")

        self.assertTrue(cfg.get_value(KEY_CONFIG_ITEM_EXPOSE_LOGSTASH))
        self.assertTrue(cfg.get_value(KEY_CONFIG_ITEM_EXPOSE_FILEBEAT_TCP))
        # For Malcolm profile + local OpenSearch we expect OpenSearch exposure as well
        self.assertTrue(cfg.get_value(KEY_CONFIG_ITEM_EXPOSE_OPENSEARCH))


if __name__ == "__main__":
    unittest.main(verbosity=2)
