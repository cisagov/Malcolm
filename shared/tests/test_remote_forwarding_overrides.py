"""One Malcolm host should populate sensor endpoints without losing overrides."""

import unittest
from unittest.mock import patch

from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_ARKIME_WISE_URL,
    KEY_CONFIG_ITEM_LOGSTASH_HOST,
    KEY_CONFIG_ITEM_MALCOLM_PROFILE,
    KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL,
    KEY_CONFIG_ITEM_REACHBACK_REQUEST_ACL,
    KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST,
)
from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.malcolm_common import SYSTEM_INFO
from scripts.malcolm_constants import PROFILE_HEDGEHOG, PROFILE_MALCOLM

FORWARDING = (
    KEY_CONFIG_ITEM_LOGSTASH_HOST,
    KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL,
    KEY_CONFIG_ITEM_ARKIME_WISE_URL,
)


class TestForwardingOverrides(unittest.TestCase):
    def setUp(self):
        self.cfg = MalcolmConfig()
        self.cfg.set_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE, PROFILE_HEDGEHOG)
        self.cfg.set_value(KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST, "192.0.2.10")

    def assert_endpoints(self, expected):
        self.assertEqual(tuple(self.cfg.get_value(k) for k in FORWARDING), expected)

    def test_one_host_populates_all_three_forwarding_targets(self):
        self.assert_endpoints(
            (
                "192.0.2.10:5044",
                "https://192.0.2.10:9200",
                "https://192.0.2.10/wise/",
            )
        )
        self.cfg.set_value(KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST, "192.0.2.20")
        self.assert_endpoints(
            (
                "192.0.2.20:5044",
                "https://192.0.2.20:9200",
                "https://192.0.2.20/wise/",
            )
        )

    def test_override_one_endpoint_keeps_other_two_host_derived(self):
        self.cfg.set_value(KEY_CONFIG_ITEM_LOGSTASH_HOST, "logs.example:6044")
        self.cfg.set_value(KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST, "192.0.2.30")
        self.assert_endpoints(
            (
                "logs.example:6044",
                "https://192.0.2.30:9200",
                "https://192.0.2.30/wise/",
            )
        )

    def test_explicit_overrides_for_all_services_are_preserved(self):
        manual = (
            "logs.example:6044",
            "https://search.example:9201",
            "https://wise.example/custom/",
        )
        for key, value in zip(FORWARDING, manual):
            self.cfg.set_value(key, value)

        self.cfg.set_value(KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST, "192.0.2.30")
        self.assert_endpoints(manual)

    def test_explicit_disabled_endpoints_remain_disabled(self):
        self.cfg.set_value(KEY_CONFIG_ITEM_LOGSTASH_HOST, "disabled")
        self.cfg.set_value(KEY_CONFIG_ITEM_ARKIME_WISE_URL, "disabled")
        self.cfg.set_value(KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST, "192.0.2.40")
        self.assertEqual(self.cfg.get_value(KEY_CONFIG_ITEM_LOGSTASH_HOST), "disabled")
        self.assertEqual(
            self.cfg.get_value(KEY_CONFIG_ITEM_ARKIME_WISE_URL), "disabled"
        )
        self.assertEqual(
            self.cfg.get_value(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL),
            "https://192.0.2.40:9200",
        )

    def test_manual_reachback_acl_is_not_overwritten(self):
        self.cfg.set_value(KEY_CONFIG_ITEM_REACHBACK_REQUEST_ACL, ["198.51.100.7"])
        self.cfg.set_value(KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST, "192.0.2.50")
        self.assertEqual(
            self.cfg.get_value(KEY_CONFIG_ITEM_REACHBACK_REQUEST_ACL),
            ["198.51.100.7"],
        )

    def test_derived_reachback_acl_tracks_host_when_not_modified(self):
        # Reachback ACL auto-population is enabled only for ISO installations.
        with patch.dict(SYSTEM_INFO, {"malcolm_iso_install": True}):
            cfg = MalcolmConfig()
            cfg.set_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE, PROFILE_HEDGEHOG)
            cfg.set_value(KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST, "192.0.2.10")
            self.assertEqual(
                cfg.get_value(KEY_CONFIG_ITEM_REACHBACK_REQUEST_ACL),
                ["192.0.2.10"],
            )
            cfg.set_value(KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST, "192.0.2.11")
            self.assertEqual(
                cfg.get_value(KEY_CONFIG_ITEM_REACHBACK_REQUEST_ACL),
                ["192.0.2.11"],
            )

    def test_returning_to_malcolm_resets_local_connection_defaults(self):
        self.cfg.set_value(KEY_CONFIG_ITEM_LOGSTASH_HOST, "logs.example:6044")
        self.cfg.set_value(
            KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL, "https://search.example:9201"
        )
        self.cfg.set_value(
            KEY_CONFIG_ITEM_ARKIME_WISE_URL, "https://wise.example/custom/"
        )
        self.cfg.set_value(KEY_CONFIG_ITEM_REACHBACK_REQUEST_ACL, ["198.51.100.8"])

        self.cfg.set_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE, PROFILE_MALCOLM)
        self.assert_endpoints(
            (
                "logstash:5044",
                "https://opensearch:9200",
                "http://arkime:8081",
            )
        )
        self.assertEqual(self.cfg.get_value(KEY_CONFIG_ITEM_REACHBACK_REQUEST_ACL), [])

    def test_new_profile_switch_can_reconfigure_unmodified_targets(self):
        self.cfg.set_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE, PROFILE_MALCOLM)
        self.cfg.set_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE, PROFILE_HEDGEHOG)
        self.cfg.set_value(KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST, "192.0.2.99")
        self.assert_endpoints(
            (
                "192.0.2.99:5044",
                "https://192.0.2.99:9200",
                "https://192.0.2.99/wise/",
            )
        )


if __name__ == "__main__":
    unittest.main()
