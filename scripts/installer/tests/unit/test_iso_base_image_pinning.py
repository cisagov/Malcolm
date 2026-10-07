"""Guard the QEMU ISO wrapper Dockerfiles against mutable base tags."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
DOCKERFILES = (
    ROOT / "malcolm-iso" / "Dockerfile",
    ROOT / "hedgehog-raspi" / "Dockerfile",
)
IMAGE = "ghcr.io/mmguero/qemu-live-iso"
IMMUTABLE_IMAGE = re.compile(rf"^{re.escape(IMAGE)}@sha256:[0-9a-f]{{64}}$")


class IsoBaseImagePinningTests(unittest.TestCase):
    def test_qemu_wrapper_images_use_identical_immutable_digest(self):
        parents = []
        for path in DOCKERFILES:
            source = path.read_text(encoding="utf-8")
            from_lines = [
                line.split(maxsplit=1)[1]
                for line in source.splitlines()
                if line.startswith("FROM ")
            ]
            self.assertEqual(len(from_lines), 1, str(path))
            self.assertRegex(from_lines[0], IMMUTABLE_IMAGE)
            parents.extend(from_lines)
        self.assertEqual(parents[0], parents[1])

    def test_image_reference_has_no_mutable_latest_tag(self):
        for path in DOCKERFILES:
            source = path.read_text(encoding="utf-8")
            self.assertNotIn(f"FROM {IMAGE}:latest", source)
