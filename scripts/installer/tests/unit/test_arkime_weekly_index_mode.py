"""Regression tests for weekly, provider-prefixed network indices in Arkime."""

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
HELPER = ROOT / "arkime/scripts/arkime-index-query-mode.sh"
ENTRYPOINT = ROOT / "arkime/scripts/docker_entrypoint.sh"
ARKIME_ENV = ROOT / "config/arkime.env.example"


def resolve_mode(setting, suffix, network_pattern, arkime_pattern="arkime_sessions3-*"):
    command = (
        'source "$1"; shift; arkime_index_query_mode "$@"'
    )
    return subprocess.run(
        [
            "/bin/bash",
            "-c",
            command,
            "_",
            str(HELPER),
            setting,
            suffix,
            network_pattern,
            arkime_pattern,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


class TestArkimeWeeklyIndexMode(unittest.TestCase):
    def test_custom_weekly_indices_use_all_indices(self):
        for suffix in ("%{%yw%U}", "{{event.provider}}-%{%yw%U}", "%{%Yw%W}", "%{%G-w%V}"):
            with self.subTest(suffix=suffix):
                result = resolve_mode("auto", suffix, "network_logs-*")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "true")

    def test_daily_indices_do_not_force_wide_queries(self):
        for suffix in ("%{%y%m%d}", "{{event.provider}}-%{%P%y%m%d}", "%{%Y-%m}"):
            with self.subTest(suffix=suffix):
                result = resolve_mode("auto", suffix, "network_logs-*")
                self.assertEqual(result.stdout.strip(), "false")

    def test_default_arkime_indices_do_not_force_wide_queries(self):
        self.assertEqual(
            resolve_mode("auto", "%{%yw%U}", "arkime_sessions3-*").stdout.strip(),
            "false",
        )
        self.assertEqual(resolve_mode("auto", "%{%yw%U}", "").stdout.strip(), "false")

    def test_explicit_true_and_false_are_always_honored(self):
        for setting in ("true", "false", "TRUE", "False"):
            result = resolve_mode(setting, "%{%yw%U}", "network_logs-*")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), setting.lower())

    def test_invalid_mode_fails_closed(self):
        result = resolve_mode("anything", "%{%yw%U}", "network_logs-*")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("Invalid ARKIME_QUERY_ALL_INDICES", result.stderr)

    def test_entrypoint_sets_effective_setting_and_preserves_custom_indices(self):
        entrypoint = ENTRYPOINT.read_text()
        self.assertIn("source /usr/local/bin/arkime-index-query-mode.sh", entrypoint)
        self.assertIn("ARKIME_QUERY_ALL_INDICES_RESOLVED=", entrypoint)
        self.assertRegex(
            entrypoint,
            re.compile(
                r'sed -i "s/\^\\\(queryAllIndices=.*?'
                r'ARKIME_QUERY_ALL_INDICES_RESOLVED',
                re.DOTALL,
            ),
        )
        self.assertIn("queryExtraIndices=", entrypoint)

    def test_new_default_is_auto_for_existing_config_template(self):
        config = ARKIME_ENV.read_text()
        self.assertIn("ARKIME_QUERY_ALL_INDICES=auto", config)
        self.assertNotIn("ARKIME_QUERY_ALL_INDICES=false", config)


if __name__ == "__main__":
    unittest.main()
