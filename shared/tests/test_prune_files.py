"""prune_files.sh, run for real against temporary directories.

No tools are stubbed: the script uses the real df, du, find, sort, numfmt and
date. Size limits are exercised with sparse files, which du -sb counts at their
apparent size without using real disk space. Percentage limits are set relative
to the filesystem's current df Use% so the tests don't depend on how full the
test machine's disk is.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "shared" / "bin" / "prune_files.sh"

GB = 1000 * 1000 * 1000  # the script uses decimal gigabytes


def current_use_pct(path):
    """The same Use% value the script reads with df -k."""
    out = subprocess.run(["df", "-k", str(path)], capture_output=True, text=True, check=True).stdout
    return int(out.strip().splitlines()[-1].split()[4].rstrip("%"))


@unittest.skipUnless(
    sys.platform.startswith("linux") and shutil.which("bash"),
    "requires Linux (GNU find/df/du/numfmt) and bash",
)
class PruneFilesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def make_dir(self, name, sizes):
        """Create a directory of files, oldest first, each with the given apparent size."""
        directory = self.root / name
        directory.mkdir()
        files = []
        now = time.time()
        for index, size in enumerate(sizes):
            path = directory / f"capture{index}.pcap"
            with open(path, "wb") as handle:
                handle.truncate(size)  # sparse: apparent size only
            os.utime(path, (now - 3600 + index, now - 3600 + index))
            files.append(path)
        return directory, files

    def run_prune(self, directory, *args):
        return subprocess.run(
            ["bash", str(SCRIPT), "-p", str(directory), *args],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def test_path_with_spaces(self):
        pct = current_use_pct(self.root)
        if pct < 2:
            self.skipTest(f"filesystem is at {pct}%; need at least 2% to stay clear of the threshold boundary")
        directory, (capture,) = self.make_dir("capture data", [1024])
        result = self.run_prune(directory, "-t", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(capture.exists(), result.stderr)

    def test_prunes_when_usage_equals_percent_threshold(self):
        pct = current_use_pct(self.root)
        if pct < 1:
            self.skipTest("filesystem reports 0% used")
        directory, (capture,) = self.make_dir("capture", [1024])
        # Use% won't change by deleting a tiny file, so this also checks that the
        # script exits once it runs out of files while still at the threshold.
        result = self.run_prune(directory, "-t", str(pct))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(capture.exists(), result.stderr)

    def test_keeps_files_below_percent_threshold(self):
        pct = current_use_pct(self.root)
        if pct >= 99:
            self.skipTest(f"filesystem is at {pct}%")
        directory, (capture,) = self.make_dir("capture", [1024])
        result = self.run_prune(directory, "-t", "100")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(capture.exists())

    def test_prunes_when_size_equals_gb_threshold(self):
        directory, (capture,) = self.make_dir("capture", [GB])
        result = self.run_prune(directory, "-m", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(capture.exists(), result.stderr)

    def test_size_pruning_removes_oldest_first_and_stops_below_limit(self):
        # After deleting 1 GB, the remaining 0.6 GB is below the limit.
        # Rounding that remainder to 1 GB would incorrectly delete the middle file.
        directory, (oldest, middle, newest) = self.make_dir("capture", [GB, int(0.2 * GB), int(0.4 * GB)])
        result = self.run_prune(directory, "-m", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(oldest.exists(), result.stderr)
        self.assertTrue(middle.exists(), result.stderr)
        self.assertTrue(newest.exists(), result.stderr)

    def test_keeps_files_below_size_threshold(self):
        directory, (capture,) = self.make_dir("capture", [int(0.4 * GB)])
        result = self.run_prune(directory, "-m", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(capture.exists())

    def test_keeps_files_above_half_a_gb_but_below_one_gb(self):
        directory, (capture,) = self.make_dir("capture", [600_000_000])
        result = self.run_prune(directory, "-m", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(capture.exists(), result.stdout + result.stderr)

    def test_keeps_files_just_below_ten_gb(self):
        directory, (capture,) = self.make_dir("capture", [9_600_000_000])
        result = self.run_prune(directory, "-m", "10")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(capture.exists(), result.stdout + result.stderr)

    def test_exact_byte_boundary(self):
        for delta in (-1, 0, 1):
            with self.subTest(delta=delta):
                directory, (capture,) = self.make_dir(f"capture{delta}", [GB])
                # Account for the directory's apparent size as well as the file.
                total = int(subprocess.check_output(["du", "-sb", str(directory)], text=True).split()[0])
                with capture.open("r+b") as handle:
                    handle.truncate(GB + delta - (total - GB))
                measured = int(subprocess.check_output(["du", "-sb", str(directory)], text=True).split()[0])
                self.assertEqual(measured, GB + delta)
                result = self.run_prune(directory, "-m", "1")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(capture.exists(), delta < 0, result.stdout + result.stderr)

    @unittest.skipUnless(shutil.which("humanfriendly"), "requires the optional humanfriendly size parser")
    def test_human_readable_limits_keep_byte_precision(self):
        cases = (
            ("500MB", 400_000_000, True),
            ("500MB", 600_000_000, False),
            ("1.5GB", 1_400_000_000, True),
            ("1.5GB", 1_600_000_000, False),
            ("1GiB", 1_050_000_000, True),
            ("1GiB", 1_100_000_000, False),
            ("512MiB", 520_000_000, True),
            ("512MiB", 550_000_000, False),
        )
        for index, (limit, size, keep) in enumerate(cases):
            with self.subTest(limit=limit, size=size):
                directory, (capture,) = self.make_dir(f"capture{index}", [size])
                result = self.run_prune(directory, "-m", limit)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(capture.exists(), keep, result.stdout + result.stderr)

    def test_percentage_trigger_still_applies_below_size_limit(self):
        pct = current_use_pct(self.root)
        if pct < 1:
            self.skipTest("filesystem reports 0% used")
        directory, (capture,) = self.make_dir("capture", [1024])
        result = self.run_prune(directory, "-t", str(pct), "-m", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(capture.exists(), result.stdout + result.stderr)

    def test_disabled_size_limit_keeps_files(self):
        directory, (capture,) = self.make_dir("capture", [GB])
        result = self.run_prune(directory, "-m", "0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(capture.exists(), result.stdout + result.stderr)

    def test_oversized_limits_fail_before_deleting_files(self):
        for index, limit in enumerate(("9223372037", "18446744074", "999999999999999999999999")):
            with self.subTest(limit=limit):
                directory, (capture,) = self.make_dir(f"capture{index}", [600_000_000])
                result = self.run_prune(directory, "-m", limit)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("supported byte range", result.stderr)
                self.assertTrue(capture.exists())

    def test_leading_zeroes_do_not_change_limit_units(self):
        directory, (capture,) = self.make_dir("capture", [600_000_000])
        result = self.run_prune(directory, "-m", "0001")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(capture.exists(), result.stdout + result.stderr)
