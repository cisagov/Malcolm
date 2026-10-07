"""Regression tests for installer memory defaults on small hosts (issue #483)."""

import unittest

from scripts.installer.utils.custom_transforms import (
    custom_transform_logstash_java_opts,
    custom_transform_opensearch_java_opts,
)
from scripts.malcolm_common import suggest_ls_memory, suggest_os_memory


class LowMemoryHeapRecommendationsTests(unittest.TestCase):
    def test_small_hosts_get_reduced_java_heaps(self):
        # The old minima (4g OpenSearch and 2500m Logstash) overcommitted
        # memory on an 8 GiB host without swap.
        expected = {
            4: ("1g", "512m"),
            6: ("1g", "768m"),
            8: ("2g", "1024m"),
            10: ("2g", "1024m"),
            11: ("2g", "1024m"),
        }
        for memory_gb, heaps in expected.items():
            with self.subTest(memory_gb=memory_gb):
                self.assertEqual(
                    (suggest_os_memory(memory_gb), suggest_ls_memory(memory_gb)), heaps
                )

    def test_small_heaps_leave_room_for_other_services(self):
        for physical_gb in range(4, 12):
            with self.subTest(physical_gb=physical_gb):
                os_heap = int(suggest_os_memory(physical_gb).rstrip("g")) * 1024
                ls_heap = int(suggest_ls_memory(physical_gb).rstrip("m"))
                self.assertLessEqual(os_heap + ls_heap, physical_gb * 512)

    def test_larger_hosts_keep_previous_recommendations(self):
        expected = {
            12: ("6g", "2500m"),
            16: ("8g", "2500m"),
            24: ("12g", "3072m"),
            32: ("16g", "3072m"),
            64: ("31g", "3072m"),
        }
        for memory_gb, heaps in expected.items():
            with self.subTest(memory_gb=memory_gb):
                self.assertEqual(
                    (suggest_os_memory(memory_gb), suggest_ls_memory(memory_gb)), heaps
                )

    def test_java_options_use_both_recommended_heap_sizes(self):
        os_opts = custom_transform_opensearch_java_opts(suggest_os_memory(8))
        ls_opts = custom_transform_logstash_java_opts(suggest_ls_memory(8))
        self.assertIn("-Xms2g", os_opts)
        self.assertIn("-Xmx2g", os_opts)
        self.assertIn("-Xms1024m", ls_opts)
        self.assertIn("-Xmx1024m", ls_opts)


if __name__ == "__main__":
    unittest.main()
