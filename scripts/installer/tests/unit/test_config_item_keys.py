import unittest
from scripts.installer.configs.constants import configuration_item_keys
from scripts.installer.configs.configuration_items import ALL_CONFIG_ITEMS_DICT


class TestConfigItemKeyCoverage(unittest.TestCase):
    def test_config_item_keys_coverage(self):
        all_defined_keys = configuration_item_keys.get_set_of_configuration_item_keys()
        all_configitem_keys = set(ALL_CONFIG_ITEMS_DICT.keys())

        missing_in_configitems = all_defined_keys - all_configitem_keys
        extra_in_configitems = all_configitem_keys - all_defined_keys

        if missing_in_configitems:
            print("\n==============================")
            print("MISSING ConfigItems for conceptual keys:")
            print("------------------------------")
            for key in sorted(missing_in_configitems):
                print(f"  - {key}")
            print("==============================\n")
        if extra_in_configitems:
            print("\n==============================")
            print("ConfigItems with keys NOT defined in configuration_item_keys.py:")
            print("------------------------------")
            for key in sorted(extra_in_configitems):
                print(f"  - {key}")
            print("==============================\n")

        self.assertFalse(missing_in_configitems, f"Missing ConfigItem for keys")
        self.assertFalse(
            extra_in_configitems,
            f"ConfigItem(s) with keys not defined in configuration_item_keys.py",
        )


if __name__ == "__main__":
    unittest.main()
