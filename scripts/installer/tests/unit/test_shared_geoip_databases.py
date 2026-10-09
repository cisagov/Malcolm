"""Offline tests for shared MaxMind GeoIP data in Arkime and Logstash."""

import importlib.util
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
CONFIG = ROOT / "logstash/scripts/configure_geoip_databases.py"
PUBLISH = ROOT / "arkime/scripts/publish-shared-geoip.sh"

spec = importlib.util.spec_from_file_location("geoip_configuration", CONFIG)
geoip = importlib.util.module_from_spec(spec)
spec.loader.exec_module(geoip)

PIPELINES = (
    "logstash/pipelines/beats/12_lookups.conf",
    "logstash/pipelines/enrichment/11_lookups.conf",
    "logstash/pipelines/zeek/1200_zeek_mutate.conf",
)


class TestSharedGeoIP(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.shared = self.root / "shared"
        self.shared.mkdir()
        self.city = self.shared / "GeoLite2-City.mmdb"
        self.asn = self.shared / "GeoLite2-ASN.mmdb"
        self.city.write_bytes(b"synthetic City database")
        self.asn.write_bytes(b"synthetic ASN database")
        self.pipelines = self.root / "pipelines"
        self.pipelines.mkdir()
        for name in PIPELINES:
            source = ROOT / name
            target = self.pipelines / source.parent.name / source.name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())

    def snapshots(self):
        return {str(path): path.read_bytes() for path in self.pipelines.rglob("*.conf")}

    def publish(self, source, shared=None):
        return subprocess.run(
            ["sh", str(PUBLISH), str(source), str(shared or self.shared)],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_all_realtime_geoip_filters_get_matching_databases(self):
        self.assertEqual(geoip.configure_pipeline_dir(self.pipelines, self.shared), 13)
        count = 0
        for path in self.pipelines.rglob("*.conf"):
            for block in re.findall(
                r"\bgeoip\s*\{([^{}]*)\}", path.read_text(), re.DOTALL
            ):
                count += 1
                selected = (
                    self.asn if 'default_database_type => "ASN"' in block else self.city
                )
                self.assertIn(f'database => "{selected}"', block)
        self.assertEqual(count, 13)

    def test_injection_is_idempotent(self):
        self.assertEqual(geoip.configure_pipeline_dir(self.pipelines, self.shared), 13)
        baseline = self.snapshots()
        self.assertEqual(geoip.configure_pipeline_dir(self.pipelines, self.shared), 0)
        self.assertEqual(self.snapshots(), baseline)

    def test_absent_or_empty_databases_fail_before_modifying_config(self):
        for filename in (self.city, self.asn):
            for replacement in (None, b""):
                original = filename.read_bytes()
                if replacement is None:
                    filename.unlink()
                else:
                    filename.write_bytes(replacement)
                baseline = self.snapshots()
                with self.subTest(name=filename.name, replacement=replacement):
                    with self.assertRaisesRegex(FileNotFoundError, filename.name):
                        geoip.configure_pipeline_dir(self.pipelines, self.shared)
                    self.assertEqual(self.snapshots(), baseline)
                filename.write_bytes(original)

    def test_custom_geoip_database_is_not_overwritten(self):
        text = """filter {
  geoip {
    id => "custom"
    database => "/custom/database.mmdb"
  }
  geoip {
    id => "shared"
    default_database_type => "ASN"
  }
}
"""
        converted, count = geoip.configure_text(text, self.city, self.asn)
        self.assertEqual(count, 1)
        self.assertEqual(converted.count("/custom/database.mmdb"), 1)
        self.assertIn(f'database => "{self.asn}"', converted)

    def test_unterminated_filter_does_not_modify_other_files(self):
        (self.pipelines / "broken.conf").write_text("filter {\n geoip {\n")
        baseline = self.snapshots()
        with self.assertRaisesRegex(ValueError, "Unclosed geoip"):
            geoip.configure_pipeline_dir(self.pipelines, self.shared)
        self.assertEqual(self.snapshots(), baseline)

    def test_publish_updates_city_asn_country_atomically(self):
        source = self.root / "source"
        source.mkdir()
        for name in ("City", "ASN", "Country"):
            (source / f"GeoLite2-{name}.mmdb").write_bytes(name.encode())
        result = self.publish(source)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("City", "ASN", "Country"):
            target = self.shared / f"GeoLite2-{name}.mmdb"
            self.assertEqual(target.read_bytes(), name.encode())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)
        self.assertEqual(list(self.shared.glob(".GeoLite2-*.mmdb.*")), [])

    def test_publish_keeps_other_databases_if_missing(self):
        source = self.root / "source"
        source.mkdir()
        self.city.write_bytes(b"old city")
        self.asn.write_bytes(b"old ASN")
        (source / self.city.name).write_bytes(b"updated city")
        result = self.publish(source)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.city.read_bytes(), b"updated city")
        self.assertEqual(self.asn.read_bytes(), b"old ASN")

    def test_missing_shared_directory_does_not_publish(self):
        source = self.root / "source"
        source.mkdir()
        result = self.publish(source, self.root / "missing")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not exist", result.stderr)

    def test_compose_mounts_all_required_containers(self):
        config = (ROOT / "docker-compose.yml").read_text()
        for service, mode in (
            ("logstash", "geoip-shared:/var/local/geoip:ro"),
            ("arkime", "geoip-shared:/var/local/geoip\n"),
            ("arkime-live", "geoip-shared:/var/local/geoip\n"),
        ):
            begin = config.index(f"  {service}:\n")
            tail = config[begin + 1 :]
            boundary = re.search(r"(?m)^  [a-z][a-z0-9-]*:\s*$", tail)
            self.assertIsNotNone(boundary)
            self.assertIn(mode, tail[: boundary.start()])
        self.assertIn("\n  geoip-shared:\n", config)

    def test_default_remains_bundled_and_shared_is_explicit(self):
        env = (ROOT / "config/logstash.env.example").read_text()
        runner = (ROOT / "logstash/scripts/logstash-start.sh").read_text()
        updater = (ROOT / "arkime/scripts/arkime_update_geo.sh").read_text()
        self.assertIn("LOGSTASH_GEOIP_SHARED_DB=false", env)
        self.assertIn('case "${LOGSTASH_GEOIP_SHARED_DB:-false}" in', runner)
        self.assertIn("configure_geoip_databases.py", runner)
        self.assertIn("publish-shared-geoip.sh", updater)


if __name__ == "__main__":
    unittest.main()
