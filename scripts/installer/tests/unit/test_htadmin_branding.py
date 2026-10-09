"""Tests for consistent Malcolm branding on the htadmin account management UI."""

import os
import shutil
import subprocess
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
HEADER = ROOT / "htadmin/src/includes/head.php"
NAV = ROOT / "htadmin/src/includes/nav.php"
FOOTER = ROOT / "htadmin/src/includes/footer.php"
CSS = ROOT / "htadmin/src/malcolm.css"
DOCKERFILE = ROOT / "Dockerfiles/htadmin.Dockerfile"


class _MarkupParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.images = []
        self.navigation = []
        self.footer_count = 0

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "a":
            self.links.append(attributes.get("href", ""))
        if tag == "img":
            self.images.append(attributes)
        if tag == "nav":
            self.navigation.append(attributes.get("aria-label", ""))
        if tag == "footer":
            self.footer_count += 1


class TestHtadminMalcolmBranding(unittest.TestCase):
    @unittest.skipUnless(shutil.which("php"), "PHP CLI is not available")
    def test_php_files_have_valid_syntax(self):
        for file in (HEADER, NAV, FOOTER):
            with self.subTest(file=file.name):
                proc = subprocess.run(
                    ["php", "-l", str(file)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)

    def _render_nav(self, is_admin):
        php = (
            "$ini = ['app_title' => 'Account management']; "
            f"function check_admin_login() {{ return {'true' if is_admin else 'false'}; }} "
            "include $argv[1];"
        )
        result = subprocess.run(
            ["php", "-r", php, str(NAV)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        parser = _MarkupParser()
        parser.feed(result.stdout)
        return parser, result.stdout

    @unittest.skipUnless(shutil.which("php"), "PHP CLI is not available")
    def test_unauthenticated_navigation_retains_both_workflows(self):
        parsed, html = self._render_nav(False)
        self.assertIn("admin_login.php", parsed.links)
        self.assertIn("selfservice.php", parsed.links)
        self.assertNotIn("admin_logout.php", parsed.links)
        self.assertIn("Account Management", html)

    @unittest.skipUnless(shutil.which("php"), "PHP CLI is not available")
    def test_authenticated_navigation_provides_logout(self):
        parsed, _ = self._render_nav(True)
        self.assertIn("admin_logout.php", parsed.links)
        self.assertNotIn("admin_login.php", parsed.links)
        self.assertNotIn("selfservice.php", parsed.links)

    @unittest.skipUnless(shutil.which("php"), "PHP CLI is not available")
    def test_navigation_has_home_and_accessible_logo(self):
        parsed, _ = self._render_nav(False)
        self.assertIn("/", parsed.links)
        self.assertIn("Account management navigation", parsed.navigation)
        self.assertTrue(any(img.get("alt") == "CISA" for img in parsed.images))

    @unittest.skipUnless(shutil.which("php"), "PHP CLI is not available")
    def test_footer_includes_brand_and_navigation(self):
        result = subprocess.run(
            ["php", "-r", "include $argv[1];", str(FOOTER)],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "MALCOLM_VERSION": "26.09.0"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        parser = _MarkupParser()
        parser.feed(result.stdout)
        self.assertEqual(parser.footer_count, 1)
        self.assertIn("/", parser.links)
        self.assertIn("/readme/", parser.links)
        self.assertIn("/mapi/ready", parser.links)
        self.assertIn("Malcolm resources", parser.navigation)
        self.assertIn("Malcolm 26.09.0", result.stdout)

    def test_bootstrap_and_application_assets_are_preserved(self):
        html = HEADER.read_text()
        self.assertIn('href="bootstrap.css"', html)
        self.assertIn('href="styles/style.css"', html)
        self.assertIn('href="malcolm.css"', html)
        self.assertIn('href="favicon.ico"', html)
        self.assertLess(
            html.index('href="bootstrap.css"'), html.index('href="malcolm.css"')
        )

    def test_consistent_brand_palette_and_responsive_layout(self):
        css = CSS.read_text()
        for token in ("#0d6efd", "#212529", "#6c757d", "#f8f9fa"):
            self.assertIn(token, css)
        self.assertIn("@media (max-width: 767px)", css)
        self.assertIn(".malcolm-navigation", css)
        self.assertIn(".malcolm-footer", css)

    def test_image_is_part_of_the_upstream_landing_page(self):
        logo = ROOT / "nginx/landingpage/assets/img/CISA.svg"
        self.assertTrue(logo.is_file())
        self.assertIn("<svg", logo.read_text())

    def test_dockerfile_installs_overrides_and_shared_logo(self):
        dockerfile = DOCKERFILE.read_text()
        self.assertIn("htadmin/src/includes/*.php", dockerfile)
        self.assertIn("htadmin/src/malcolm.css", dockerfile)
        self.assertIn(
            "nginx/landingpage/assets/img/CISA.svg /var/www/htadmin/malcolm-cisa.svg",
            dockerfile,
        )
        self.assertIn("htadmin/src/bootstrap.*", dockerfile)

    def test_original_workflows_are_still_reachable(self):
        text = NAV.read_text()
        for route in ("admin_login.php", "selfservice.php", "admin_logout.php"):
            self.assertIn(f'href="{route}"', text)
        self.assertIn("check_admin_login()", text)


if __name__ == "__main__":
    unittest.main()
