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
        # 1.6 GB total rounds to 2; deleting the oldest 1 GB file leaves 0.6 GB,
        # which rounds to 1 and is still at the limit, so the next file goes too.
        # Keep the newest one (0.4 GB rounds to 0) to show pruning stops.
        directory, (oldest, middle, newest) = self.make_dir("capture", [GB, int(0.2 * GB), int(0.4 * GB)])
        result = self.run_prune(directory, "-m", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(oldest.exists(), result.stderr)
        self.assertFalse(middle.exists(), result.stderr)
        self.assertTrue(newest.exists(), result.stderr)

    def test_keeps_files_below_size_threshold(self):
        directory, (capture,) = self.make_dir("capture", [int(0.4 * GB)])
        result = self.run_prune(directory, "-m", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(capture.exists())
