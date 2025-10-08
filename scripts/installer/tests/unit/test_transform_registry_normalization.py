#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest

from scripts.installer.core.transform_registry import apply_inbound, apply_outbound
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_OPEN_PORTS,
    KEY_CONFIG_ITEM_FILE_CARVE_MODE,
    KEY_CONFIG_ITEM_FILE_PRESERVE_MODE,
)
from scripts.installer.configs.constants.enums import (
    OpenPortsChoices,
    FileExtractionMode,
    FilePreservationMode,
)


class TestTransformRegistryNormalization(unittest.TestCase):
    def test_open_ports_inbound_outbound(self):
        # inbound accepts enum instance
        self.assertEqual(
            apply_inbound(KEY_CONFIG_ITEM_OPEN_PORTS, OpenPortsChoices.YES),
            OpenPortsChoices.YES.value,
        )
        # inbound accepts value string
        self.assertEqual(
            apply_inbound(KEY_CONFIG_ITEM_OPEN_PORTS, "customize"),
            OpenPortsChoices.CUSTOMIZE.value,
        )
        # outbound returns user-friendly string (use enum label)
        self.assertEqual(
            apply_outbound(KEY_CONFIG_ITEM_OPEN_PORTS, OpenPortsChoices.NO),
            OpenPortsChoices.NO.value if isinstance(OpenPortsChoices.NO.value, str) else OpenPortsChoices.NO.name,
        )

    def test_file_carve_modes_inbound(self):
        self.assertEqual(
            apply_inbound(KEY_CONFIG_ITEM_FILE_CARVE_MODE, FileExtractionMode.ALL),
            FileExtractionMode.ALL.value,
        )
        self.assertEqual(
            apply_inbound(KEY_CONFIG_ITEM_FILE_CARVE_MODE, "mapped"),
            FileExtractionMode.MAPPED.value,
        )

    def test_file_preservation_modes_inbound(self):
        self.assertEqual(
            apply_inbound(
                KEY_CONFIG_ITEM_FILE_PRESERVE_MODE, FilePreservationMode.QUARANTINED
            ),
            FilePreservationMode.QUARANTINED.value,
        )
        self.assertEqual(
            apply_inbound(KEY_CONFIG_ITEM_FILE_PRESERVE_MODE, "none"),
            FilePreservationMode.NONE.value,
        )


if __name__ == "__main__":
    unittest.main()
