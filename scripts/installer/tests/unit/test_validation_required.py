#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for dependency-aware validation of required configuration fields.

These tests ensure that rules enforced by scripts/installer/core/validation.py
stay in sync with dependency relationships and defaults.
"""

import unittest

from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.installer.core.validation import validate_required
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
    KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL,
    KEY_CONFIG_ITEM_DASHBOARDS_URL,
    KEY_CONFIG_ITEM_SECONDARY_DOCUMENT_STORE,
    KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_MODE,
    KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_URL,
    KEY_CONFIG_ITEM_TRAEFIK_LABELS,
    KEY_CONFIG_ITEM_EXPOSE_OPENSEARCH,
    KEY_CONFIG_ITEM_TRAEFIK_HOST,
    KEY_CONFIG_ITEM_TRAEFIK_ENTRYPOINT,
    KEY_CONFIG_ITEM_TRAEFIK_RESOLVER,
    KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST,
    KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
    KEY_CONFIG_ITEM_PCAP_IFACE,
    KEY_CONFIG_ITEM_NETBOX_MODE,
    KEY_CONFIG_ITEM_NETBOX_URL,
    KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME,
    KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS,
    KEY_CONFIG_ITEM_PCAP_DIR,
    KEY_CONFIG_ITEM_ZEEK_LOG_DIR,
    KEY_CONFIG_ITEM_SURICATA_LOG_DIR,
    KEY_CONFIG_ITEM_INDEX_DIR,
    KEY_CONFIG_ITEM_INDEX_SNAPSHOT_DIR,
    KEY_CONFIG_ITEM_MALCOLM_PROFILE,
    KEY_CONFIG_ITEM_LOGSTASH_HOST,
)
from scripts.installer.configs.constants.enums import SearchEngineMode, NetboxMode


def _issue_keys(issues):
    return {i.key for i in issues}


class TestValidationRequired(unittest.TestCase):
    def setUp(self):
        self.cfg = MalcolmConfig()

    # ---------------------- OpenSearch (primary) ----------------------
    def test_primary_remote_requires_primary_url(self):
        # Set primary mode to remote OpenSearch
        self.cfg.set_value(
            KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            SearchEngineMode.OPENSEARCH_REMOTE.value,
        )
        issues = validate_required(self.cfg)
        keys = _issue_keys(issues)
        self.assertIn(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL, keys)
        # When opensearch-remote, dashboards URL should not be required
        self.assertNotIn(KEY_CONFIG_ITEM_DASHBOARDS_URL, keys)
        # Visibility of required item
        self.assertTrue(self.cfg.is_item_visible(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL))

        # Provide primary URL -> clear related issue
        self.cfg.set_value(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL, "https://os:9200")
        issues = validate_required(self.cfg)
        self.assertNotIn(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL, _issue_keys(issues))

    def test_elasticsearch_remote_requires_dashboards_url(self):
        # Set maintain flag first so the primary-mode value rule doesn't clobber our explicit choice
        # Order matters due to dependency observers.

        # Set primary mode to Elasticsearch remote explicitly
        self.cfg.set_value(
            KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            SearchEngineMode.ELASTICSEARCH_REMOTE.value,
        )
        issues = validate_required(self.cfg)
        keys = _issue_keys(issues)
        self.assertIn(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL, keys)
        self.assertIn(KEY_CONFIG_ITEM_DASHBOARDS_URL, keys)
        # Both items should be visible for user correction
        self.assertTrue(self.cfg.is_item_visible(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL))
        self.assertTrue(self.cfg.is_item_visible(KEY_CONFIG_ITEM_DASHBOARDS_URL))

        # Provide only primary URL -> dashboards still required
        self.cfg.set_value(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL, "https://es:9200")
        issues = validate_required(self.cfg)
        keys = _issue_keys(issues)
        self.assertNotIn(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL, keys)
        self.assertIn(KEY_CONFIG_ITEM_DASHBOARDS_URL, keys)
        # Dashboards should remain visible
        self.assertTrue(self.cfg.is_item_visible(KEY_CONFIG_ITEM_DASHBOARDS_URL))

        # Provide dashboards URL -> both clear
        self.cfg.set_value(KEY_CONFIG_ITEM_DASHBOARDS_URL, "https://kibana:5601")
        issues = validate_required(self.cfg)
        keys = _issue_keys(issues)
        self.assertNotIn(KEY_CONFIG_ITEM_DASHBOARDS_URL, keys)

    # ---------------------- OpenSearch (secondary) ----------------------
    def test_secondary_remote_requires_secondary_url(self):
        # Enable secondary forwarding and select remote mode
        self.cfg.set_value(KEY_CONFIG_ITEM_SECONDARY_DOCUMENT_STORE, True)
        self.cfg.set_value(
            KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_MODE,
            SearchEngineMode.OPENSEARCH_REMOTE.value,
        )
        issues = validate_required(self.cfg)
        keys = _issue_keys(issues)
        self.assertIn(KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_URL, keys)
        # Should be visible for correction
        self.assertTrue(self.cfg.is_item_visible(KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_URL))

        # Provide URL -> issue cleared
        self.cfg.set_value(
            KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_URL,
            "https://remote-secondary:9200",
        )
        issues = validate_required(self.cfg)
        self.assertNotIn(KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_URL, _issue_keys(issues))

    # ---------------------- Traefik labels ----------------------
    def test_traefik_labels_require_host_and_resolver(self):
        # Enable Traefik labels
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_LABELS, True)
        # Defaults: host="", resolver="", entrypoint="websecure"
        issues = validate_required(self.cfg)
        keys = _issue_keys(issues)
        self.assertIn(KEY_CONFIG_ITEM_TRAEFIK_HOST, keys)
        self.assertIn(KEY_CONFIG_ITEM_TRAEFIK_RESOLVER, keys)
        # entrypoint has a non-empty default; should not be flagged
        self.assertNotIn(KEY_CONFIG_ITEM_TRAEFIK_ENTRYPOINT, keys)
        # Required fields should be visible
        self.assertTrue(self.cfg.is_item_visible(KEY_CONFIG_ITEM_TRAEFIK_HOST))
        self.assertTrue(self.cfg.is_item_visible(KEY_CONFIG_ITEM_TRAEFIK_RESOLVER))

    def test_traefik_opensearch_host_required_when_local_primary(self):
        # traefik labels + local OpenSearch primary
        self.cfg.set_value(KEY_CONFIG_ITEM_EXPOSE_OPENSEARCH, True)
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_LABELS, True)
        self.cfg.set_value(
            KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            SearchEngineMode.OPENSEARCH_LOCAL.value,
        )
        # Also set Malcolm host so we can test distinctness
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_HOST, "malcolm.example.org")
        # Missing os host: should be required and visible
        issues = validate_required(self.cfg)
        keys = _issue_keys(issues)
        self.assertIn(KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST, keys)
        self.assertTrue(self.cfg.is_item_visible(KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST))
        # Setting same value as Malcolm host should still be flagged
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST, "malcolm.example.org")
        keys = _issue_keys(validate_required(self.cfg))
        self.assertIn(KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST, keys)
        # Provide a distinct host clears the issue
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST, "opensearch.example.org")
        keys = _issue_keys(validate_required(self.cfg))
        self.assertNotIn(KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST, keys)

        # Provide missing fields -> clear
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_HOST, "malcolm.example.org")
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_RESOLVER, "myresolver")
        issues = validate_required(self.cfg)
        keys = _issue_keys(issues)
        self.assertFalse({KEY_CONFIG_ITEM_TRAEFIK_HOST, KEY_CONFIG_ITEM_TRAEFIK_RESOLVER} & keys)

        # Disable labels -> no issues even if values empty
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_HOST, "")
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_RESOLVER, "")
        self.cfg.set_value(KEY_CONFIG_ITEM_TRAEFIK_LABELS, False)
        issues = validate_required(self.cfg)
        keys = _issue_keys(issues)
        self.assertNotIn(KEY_CONFIG_ITEM_TRAEFIK_HOST, keys)
        self.assertNotIn(KEY_CONFIG_ITEM_TRAEFIK_RESOLVER, keys)

    # ---------------------- Live capture ----------------------
    def test_live_capture_requires_interface_when_method_enabled(self):
        # Enabling live capture auto-enables Zeek/Suricata via dependency defaults
        self.cfg.set_value(KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC, True)
        issues = validate_required(self.cfg)
        self.assertIn(KEY_CONFIG_ITEM_PCAP_IFACE, _issue_keys(issues))
        # Ensure interface is visible when required
        self.assertTrue(self.cfg.is_item_visible(KEY_CONFIG_ITEM_PCAP_IFACE))

        # Provide interface -> clear
        self.cfg.set_value(KEY_CONFIG_ITEM_PCAP_IFACE, "eth0")
        issues = validate_required(self.cfg)
        self.assertNotIn(KEY_CONFIG_ITEM_PCAP_IFACE, _issue_keys(issues))

    # ---------------------- NetBox ----------------------
    def test_netbox_remote_requires_url(self):
        self.cfg.set_value(KEY_CONFIG_ITEM_NETBOX_MODE, NetboxMode.REMOTE.value)
        issues = validate_required(self.cfg)
        self.assertIn(KEY_CONFIG_ITEM_NETBOX_URL, _issue_keys(issues))
        # NetBox URL should be visible when required
        self.assertTrue(self.cfg.is_item_visible(KEY_CONFIG_ITEM_NETBOX_URL))

        self.cfg.set_value(KEY_CONFIG_ITEM_NETBOX_URL, "https://netbox.example.org")
        issues = validate_required(self.cfg)
        self.assertNotIn(KEY_CONFIG_ITEM_NETBOX_URL, _issue_keys(issues))

    # ---------------------- Optional fields ----------------------
    def test_container_network_name_is_optional(self):
        # Explicitly set to empty and verify not flagged
        self.cfg.set_value(KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME, "")
        issues = validate_required(self.cfg)
        self.assertNotIn(KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME, _issue_keys(issues))

    # ---------------------- Storage directories ----------------------
    def test_storage_dirs_required_when_not_using_defaults(self):
        # Flip off default storage locations
        self.cfg.set_value(KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS, False)
        issues = validate_required(self.cfg)
        keys = _issue_keys(issues)
        # All three directories should be required and visible
        self.assertIn(KEY_CONFIG_ITEM_PCAP_DIR, keys)
        self.assertIn(KEY_CONFIG_ITEM_ZEEK_LOG_DIR, keys)
        self.assertIn(KEY_CONFIG_ITEM_SURICATA_LOG_DIR, keys)
        self.assertTrue(self.cfg.is_item_visible(KEY_CONFIG_ITEM_PCAP_DIR))
        self.assertTrue(self.cfg.is_item_visible(KEY_CONFIG_ITEM_ZEEK_LOG_DIR))
        self.assertTrue(self.cfg.is_item_visible(KEY_CONFIG_ITEM_SURICATA_LOG_DIR))

        # Setting values via set_value satisfies the is_modified requirement
        self.cfg.set_value(KEY_CONFIG_ITEM_PCAP_DIR, "/data/pcap")
        self.cfg.set_value(KEY_CONFIG_ITEM_ZEEK_LOG_DIR, "/data/zeek")
        self.cfg.set_value(KEY_CONFIG_ITEM_SURICATA_LOG_DIR, "/data/suricata")
        issues = validate_required(self.cfg)
        keys = _issue_keys(issues)
        self.assertNotIn(KEY_CONFIG_ITEM_PCAP_DIR, keys)
        self.assertNotIn(KEY_CONFIG_ITEM_ZEEK_LOG_DIR, keys)
        self.assertNotIn(KEY_CONFIG_ITEM_SURICATA_LOG_DIR, keys)

    # ---------------------- Index/Snapshot directories ----------------------
    def test_index_dirs_required_when_not_using_defaults_for_malcolm_local(self):
        # Not using defaults; defaults are profile=malcolm and primary=opensearch-local
        self.cfg.set_value(KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS, False)
        issues = validate_required(self.cfg)
        keys = _issue_keys(issues)
        # Both index dir and snapshot dir should be required and visible
        self.assertIn(KEY_CONFIG_ITEM_INDEX_DIR, keys)
        self.assertIn(KEY_CONFIG_ITEM_INDEX_SNAPSHOT_DIR, keys)
        self.assertTrue(self.cfg.is_item_visible(KEY_CONFIG_ITEM_INDEX_DIR))
        self.assertTrue(self.cfg.is_item_visible(KEY_CONFIG_ITEM_INDEX_SNAPSHOT_DIR))
        # Setting values clears issues
        self.cfg.set_value(KEY_CONFIG_ITEM_INDEX_DIR, "/data/index")
        self.cfg.set_value(KEY_CONFIG_ITEM_INDEX_SNAPSHOT_DIR, "/data/snapshot")
        issues = validate_required(self.cfg)
        keys = _issue_keys(issues)
        self.assertNotIn(KEY_CONFIG_ITEM_INDEX_DIR, keys)
        self.assertNotIn(KEY_CONFIG_ITEM_INDEX_SNAPSHOT_DIR, keys)

    def test_index_dirs_not_required_when_using_defaults(self):
        # Using defaults; even malcolm/local should not require explicit index paths
        self.cfg.set_value(KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS, True)
        issues = validate_required(self.cfg)
        keys = _issue_keys(issues)
        self.assertNotIn(KEY_CONFIG_ITEM_INDEX_DIR, keys)
        self.assertNotIn(KEY_CONFIG_ITEM_INDEX_SNAPSHOT_DIR, keys)

    def test_index_dirs_not_required_when_not_malcolm_or_remote_primary(self):
        # Not using defaults but profile is hedgehog -> not required
        self.cfg.set_value(KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS, False)
        self.cfg.set_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE, "hedgehog")
        keys = _issue_keys(validate_required(self.cfg))
        self.assertNotIn(KEY_CONFIG_ITEM_INDEX_DIR, keys)
        self.assertNotIn(KEY_CONFIG_ITEM_INDEX_SNAPSHOT_DIR, keys)

        # Switch back to malcolm but set primary to remote -> not required
        from scripts.installer.configs.constants.enums import SearchEngineMode

        self.cfg.set_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE, "malcolm")
        self.cfg.set_value(
            KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            SearchEngineMode.OPENSEARCH_REMOTE.value,
        )
        keys = _issue_keys(validate_required(self.cfg))
        self.assertNotIn(KEY_CONFIG_ITEM_INDEX_DIR, keys)
        self.assertNotIn(KEY_CONFIG_ITEM_INDEX_SNAPSHOT_DIR, keys)

    # ---------------------- Hedgehog profile ----------------------
    def test_hedgehog_profile_requires_logstash_host(self):
        self.cfg.set_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE, "hedgehog")
        keys = _issue_keys(validate_required(self.cfg))
        self.assertIn(KEY_CONFIG_ITEM_LOGSTASH_HOST, keys)
        # Visible for correction
        self.assertTrue(self.cfg.is_item_visible(KEY_CONFIG_ITEM_LOGSTASH_HOST))
        # Provide host:port clears the issue
        self.cfg.set_value(KEY_CONFIG_ITEM_LOGSTASH_HOST, "192.0.2.1:5044")
        keys = _issue_keys(validate_required(self.cfg))
        self.assertNotIn(KEY_CONFIG_ITEM_LOGSTASH_HOST, keys)


if __name__ == "__main__":
    unittest.main()
