"""Net/downloaded build assets must be pinned and verified before use."""

import hashlib
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
FREQ = ROOT / "Dockerfiles/freq.Dockerfile"
NGINX = ROOT / "Dockerfiles/nginx.Dockerfile"


def arg_value(source, name):
    match = re.search(
        "^ARG " + re.escape(name) + "=([0-9a-f]+)$",
        source,
        re.MULTILINE,
    )
    if match is None:
        raise AssertionError(f"Missing immutable pinned argument: {name}")
    return match.group(1)


class TestExternalBuildAssetPins(unittest.TestCase):
    def test_freq_source_is_immutable_and_has_valid_checksum(self):
        source = FREQ.read_text()
        self.assertRegex(arg_value(source, "FREQ_SOURCE_COMMIT"), r"^[0-9a-f]{40}$")
        self.assertRegex(arg_value(source, "FREQ_SOURCE_SHA256"), r"^[0-9a-f]{64}$")
        self.assertIn(
            "codeload.github.com/markbaggett/freq/tar.gz/"
            + chr(36)
            + "{FREQ_SOURCE_COMMIT}",
            source,
        )
        self.assertNotIn("codeload.github.com/markbaggett/freq/tar.gz/master", source)

    def test_freq_download_is_verified_before_extraction(self):
        source = FREQ.read_text()
        download = source.index("curl -fLsS --retry 3 -o /tmp/freq-source.tar.gz")
        expected = source.index('"$FREQ_SOURCE_SHA256" /tmp/freq-source.tar.gz')
        verified = source.index("sha256sum -c -", expected)
        extract = source.index("tar xzvf /tmp/freq-source.tar.gz")
        cleanup = source.index("rm /tmp/freq-source.tar.gz")
        self.assertLess(download, expected)
        self.assertLess(expected, verified)
        self.assertLess(verified, extract)
        self.assertLess(extract, cleanup)

    def test_pinned_icon_sources_match_expected_repositories(self):
        source = NGINX.read_text()
        lines = [
            line.strip()
            for line in source.splitlines()
            if line.startswith("ADD ") and "raw.githubusercontent.com/" in line
        ]
        self.assertEqual(len(lines), 2)
        for line, repo, name in (
            (lines[0], "gchq/CyberChef", "cyberchef.svg"),
            (lines[1], "netbox-community/netbox", "netbox_icon.svg"),
        ):
            with self.subTest(repo=repo):
                match = re.fullmatch(
                    r"ADD --checksum=sha256:([a-f0-9]{64}) "
                    r"https://raw\.githubusercontent\.com/"
                    + re.escape(repo)
                    + r"/([0-9a-f]{40})/\S+ "
                    r"/usr/share/nginx/html/assets/img/",
                    line,
                )
                self.assertIsNotNone(match, line)
                self.assertTrue(line.split(" /usr/share/")[0].endswith(name))
        self.assertNotIn("CyberChef/master/", source)
        self.assertNotIn(
            "netbox/main/netbox/project-static/img/netbox_icon.svg", source
        )

    def test_sha256_check_rejects_changed_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "archive.tgz"
            path.write_bytes(b"intended release")
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            for payload, valid in (
                (b"intended release", True),
                (b"changed content", False),
            ):
                path.write_bytes(payload)
                result = subprocess.run(
                    [
                        "sh",
                        "-c",
                        'printf "%s  %s\n" "$1" "$2" | sha256sum -c -',
                        "sh",
                        expected,
                        str(path),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, valid)


if __name__ == "__main__":
    unittest.main()
