"""Isolated regression tests for repository-pinned AWS installer downloads."""

import hashlib
import io
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
INSTALLERS = [
    ROOT / "scripts/third-party-environments/aws/ami/scripts/Malcolm_AMI_Setup.sh",
    ROOT / "scripts/third-party-environments/aws/amazonlinux-2023/amazon_linux_2023_malcolm_demo_setup.sh",
]
TOOLS = ["schollz/croc", "mikefarah/yq", "boringproxy/boringproxy", "sharkdp/bat", "eza-community/eza"]


def functions(path):
    text = path.read_text()
    start = text.index("function _PinnedToolReleaseAndSha256 {")
    end = text.index("function _InstallCroc {", start)
    block = text[start:end]
    block = block.replace('  dest_dir="/usr/bin"', '  dest_dir="$BIN_DIR"')
    block = block.replace('  dest_dir="${LOCAL_BIN_PATH:-/usr/local/bin}"', '  dest_dir="$BIN_DIR"')
    assert '  dest_dir="$BIN_DIR"' in block
    return block


# These wrappers are defined only inside an isolated test shell.
MOCKS = r'''
SUDO_CMD=""
uname() { echo x86_64; }
chown() { :; }
curl() {
    if [[ "$CURL_FAIL" == 1 ]]; then return 22; fi
    local path="" url=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o) path="$2"; shift 2 ;;
            *) url="$1"; shift ;;
        esac
    done
    printf '%s\n' "$url" > "$CAPTURE_URL"
    cp "$FIXTURE" "$path"
}
'''


def run_fixture(script, directory, fixture, digest, command, fail_curl=False):
    overrides = '_PinnedToolReleaseAndSha256() { printf "v1.0 %s\\n" "$EXPECTED_HASH"; }\n'
    return subprocess.run(
        ["/bin/bash", "-c", MOCKS + functions(script) + overrides + command],
        env={
            **os.environ,
            "BIN_DIR": str(directory / "bin"),
            "FIXTURE": str(fixture),
            "CAPTURE_URL": str(directory / "url"),
            "EXPECTED_HASH": digest,
            "CURL_FAIL": "1" if fail_curl else "0",
        },
        capture_output=True,
        text=True,
        check=False,
    )


class TestAwsToolVerification(unittest.TestCase):
    def test_all_ten_pinned_digests_match_between_standalone_scripts(self):
        tables = []
        for script in INSTALLERS:
            table = {}
            for repo in TOOLS:
                for arch in ("amd64", "arm64"):
                    result = subprocess.run(
                        ["/bin/bash", "-c", functions(script) + '_PinnedToolReleaseAndSha256 "$1" "$2"', "_", repo, arch],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    version, digest = result.stdout.strip().split()
                    self.assertRegex(version, r"^v[0-9]")
                    self.assertRegex(digest, r"^[0-9a-f]{64}$")
                    table[(repo, arch)] = (version, digest)
            self.assertEqual(len(table), 10)
            self.assertNotIn('_GitLatestRelease "$repo"', functions(script))
            self.assertNotIn('find "$temp_dir"', functions(script))
            tables.append(table)
        self.assertEqual(tables[0], tables[1])

    def test_verified_direct_binary_installation(self):
        for script in INSTALLERS:
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as root:
                directory = Path(root)
                fixture = directory / "valid"
                fixture.write_bytes(b"trusted fixture binary")
                digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
                result = run_fixture(
                    script, directory, fixture, digest,
                    "_InstallTool mikefarah/yq yq yq_linux_amd64 yq_linux_arm64",
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((directory / "bin/yq").read_bytes(), fixture.read_bytes())
                self.assertIn("/v1.0/yq_linux_amd64", (directory / "url").read_text())

    def test_archive_must_contain_exact_executable_even_if_decoy_exists(self):
        for expected in (True, False):
            for script in INSTALLERS:
                with self.subTest(script=script.name, expected=expected), tempfile.TemporaryDirectory() as root:
                    directory = Path(root)
                    fixture = directory / "bat.tar.gz"
                    with tarfile.open(fixture, "w:gz") as tar:
                        files = {"release/000-decoy": b"decoy"}
                        if expected:
                            files["release/bat"] = b"correct executable"
                        for name, body in files.items():
                            info = tarfile.TarInfo(name)
                            info.mode = 0o755
                            info.size = len(body)
                            tar.addfile(info, io.BytesIO(body))
                    digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
                    result = run_fixture(
                        script, directory, fixture, digest,
                        '_InstallTool sharkdp/bat bat "bat-{ver}-amd64.tar.gz" other --strip 1',
                    )
                    self.assertEqual(result.returncode == 0, expected, result.stderr)
                    if expected:
                        self.assertEqual((directory / "bin/bat").read_bytes(), b"correct executable")
                        self.assertIn("bat-v1.0-amd64.tar.gz", (directory / "url").read_text())
                    else:
                        self.assertFalse((directory / "bin/bat").exists())

    def test_corrupted_download_fails_closed(self):
        for script in INSTALLERS:
            for fail_curl in (False, True):
                with self.subTest(script=script.name, fail_curl=fail_curl), tempfile.TemporaryDirectory() as root:
                    directory = Path(root)
                    fixture = directory / "invalid"
                    fixture.write_bytes(b"corrupted download")
                    result = run_fixture(
                        script, directory, fixture, "0" * 64,
                        "_InstallTool mikefarah/yq yq yq_linux_amd64 yq_linux_arm64",
                        fail_curl=fail_curl,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse((directory / "bin/yq").exists())

    def test_ami_uses_correct_eza_binary_name(self):
        content = INSTALLERS[0].read_text()
        self.assertIn("[[ -f /usr/bin/eza ]] || _InstallEza || return 1", content)
        self.assertNotIn("[[ ! -f /usr/bin/exa ]]", content)


if __name__ == "__main__":
    unittest.main()
