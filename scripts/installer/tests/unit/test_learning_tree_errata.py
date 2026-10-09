"""Keep the Learning Tree configuration errata consistent with shipped defaults."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
ERRATA = ROOT / "docs/learning-tree-errata.md"
DOCS_INDEX = ROOT / "docs/README.md"
CONFIG_DOCS = ROOT / "docs/malcolm-config.md"
ROOT_README = ROOT / "README.md"


def env_value(filename: str, variable: str) -> str:
    """Return an uncommented default from an example environment file."""
    text = (ROOT / "config" / filename).read_text(encoding="utf-8")
    matches = re.findall(rf"^{re.escape(variable)}=(.*)$", text, re.MULTILINE)
    if len(matches) != 1:
        raise AssertionError(
            f"Expected exactly one default for {variable} in {filename}"
        )
    return matches[0]


class LearningTreeErrataTest(unittest.TestCase):
    def setUp(self):
        self.text = ERRATA.read_text(encoding="utf-8")

    def test_configuration_script_reference_is_current(self):
        configure = ROOT / "scripts/configure"
        self.assertTrue(configure.is_symlink())
        self.assertEqual(configure.resolve(), (ROOT / "scripts/install.py").resolve())
        self.assertIn("./scripts/configure", self.text)

    def test_configuration_profile_defaults_match_source(self):
        self.assertEqual(env_value("process.env.example", "MALCOLM_PROFILE"), "malcolm")
        self.assertIn("MALCOLM_PROFILE=malcolm", self.text)
        self.assertIn("MALCOLM_PROFILE=hedgehog", self.text)

    def test_authentication_defaults_match_source(self):
        self.assertEqual(
            env_value("auth-common.env.example", "NGINX_AUTH_MODE"), "basic"
        )
        for name in (
            "basic",
            "ldap",
            "keycloak",
            "keycloak_remote",
            "no_authentication",
        ):
            self.assertIn(name, self.text)

    def test_opensearch_defaults_match_source(self):
        self.assertEqual(
            env_value("opensearch.env.example", "OPENSEARCH_PRIMARY"),
            "opensearch-local",
        )
        self.assertEqual(
            env_value("opensearch.env.example", "OPENSEARCH_URL"),
            "https://opensearch:9200",
        )
        self.assertIn("OPENSEARCH_PRIMARY=opensearch-local", self.text)
        self.assertIn("OPENSEARCH_URL=https://opensearch:9200", self.text)

    def test_capture_defaults_match_source(self):
        self.assertEqual(
            env_value("arkime-live.env.example", "ARKIME_LIVE_CAPTURE"), "false"
        )
        self.assertIn("ARKIME_LIVE_CAPTURE=false", self.text)
        self.assertIn("PCAP_IFACE", self.text)
        self.assertIn(
            "PCAP_IFACE=", (ROOT / "config/pcap-capture.env.example").read_text()
        )

    def test_forwarder_defaults_match_source(self):
        self.assertEqual(
            env_value("beats-common.env.example", "LOGSTASH_HOST"),
            "logstash:5044",
        )
        self.assertIn("LOGSTASH_HOST=logstash:5044", self.text)

    def test_dashboard_setting_exists(self):
        self.assertTrue(
            env_value("dashboards-helper.env.example", "OPENSEARCH_DEFAULT_DASHBOARD")
        )
        self.assertIn("OPENSEARCH_DEFAULT_DASHBOARD", self.text)

    def test_runnable_service_scripts_exist(self):
        for name in ("start", "stop", "wipe", "auth_setup"):
            with self.subTest(name=name):
                self.assertTrue((ROOT / "scripts" / name).exists())

    def test_local_document_links_resolve(self):
        for link in re.findall(r"\]\(([^)]+\.md(?:#[^)]*)?)\)", self.text):
            filepath = link.split("#", 1)[0]
            with self.subTest(filepath=filepath):
                self.assertTrue((ERRATA.parent / filepath).is_file(), filepath)

    def test_readme_and_config_documentation_link_to_errata(self):
        for path in (ROOT_README, DOCS_INDEX, CONFIG_DOCS):
            with self.subTest(path=path.name):
                self.assertIn("learning-tree-errata.md", path.read_text())

    def test_training_wiki_is_clearly_separate(self):
        self.assertIn("https://github.com/cisagov/Malcolm/wiki/Learning", self.text)
        self.assertIn("Changes to the documentation repository do not edit", self.text)
        self.assertIn("issue #631", self.text)

    def test_versioned_reference_has_no_claim_of_video_review(self):
        self.assertIn("26.09.0", self.text)
        self.assertIn("not", self.text.lower())
        self.assertIn("a particular", self.text)


if __name__ == "__main__":
    unittest.main()
