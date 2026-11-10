import os
import tempfile
import unittest
from unittest.mock import patch

from scripts.installer.utils.file_utils import (
    detect_malcolm_and_image_files,
)


class TestFileUtilsDetection(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _touch(self, path: str):
        with open(path, "w") as f:
            f.write("test")

    def test_detect_explicit_args(self):
        malc = "/tmp/malcolm_foo.tar.gz"
        imgs = "/tmp/malcolm_foo_images.tar.xz"
        with patch("os.path.isfile", return_value=True):
            m, i = detect_malcolm_and_image_files(malc, imgs)
        self.assertEqual(m, [malc])
        self.assertEqual(i, [imgs])

    def test_detect_auto_discovery_underscore(self):
        base = os.path.join(self.temp_dir.name, "malcolm_20250101_000000_deadbee")
        malc = base + ".tar.gz"
        imgs = base + "_images.tar.xz"
        self._touch(malc)
        self._touch(imgs)
        with patch("os.getcwd", return_value=self.temp_dir.name):
            m, i = detect_malcolm_and_image_files()
        self.assertEqual(m, [malc])
        self.assertEqual(i, [imgs])

    def test_detect_auto_discovery_hyphen(self):
        base = os.path.join(self.temp_dir.name, "malcolm-20250101-000000-deadbee")
        malc = base + ".tar.gz"
        imgs = base + "_images.tar.xz"
        self._touch(malc)
        self._touch(imgs)
        with patch("os.getcwd", return_value=self.temp_dir.name):
            m, i = detect_malcolm_and_image_files()
        self.assertEqual(m, [malc])
        self.assertEqual(i, [imgs])

    def test_malcolm_list_excludes_images_archives(self):
        # Ensure _images.tar.xz does not appear in the malcolm tarball list
        malc = os.path.join(self.temp_dir.name, "malcolm_test.tar.gz")
        imgs = os.path.join(self.temp_dir.name, "malcolm_test_images.tar.xz")
        self._touch(malc)
        self._touch(imgs)
        with patch("os.getcwd", return_value=self.temp_dir.name):
            m, i = detect_malcolm_and_image_files()
        self.assertIn(malc, m)
        self.assertNotIn(imgs, m)
        self.assertIn(imgs, i)


if __name__ == "__main__":
    unittest.main()
