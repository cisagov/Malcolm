#!/usr/bin/env python3
# Copyright (c) 2026 Battelle Energy Alliance, LLC. All rights reserved.
"""Regression tests for Arkime's reader selection for uploaded PCAPNG files."""

import ast
from pathlib import Path
import tempfile
import unittest


def _load_reader_choice():
    # Extract the actual production helper so tests need no OpenSearch,
    # Suricata, pyzmq or running Arkime image.
    source = Path(__file__).resolve().parents[1] / "pcap_processor.py"
    module = ast.parse(source.read_text())
    function = next(
        n for n in module.body
        if isinstance(n, ast.FunctionDef)
        and n.name == "arkime_pcap_reader_option"
    )
    namespace = {"PCAPNG_MAGIC": bytes.fromhex("0a0d0d0a")}
    exec(compile(ast.Module(body=[function], type_ignores=[]),
                 str(source), "exec"), namespace)
    return namespace[function.name]


class PcapngReaderTest(unittest.TestCase):

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.reader = _load_reader_choice()

    def _capture(self, name, payload):
        file = Path(self.directory.name) / name
        file.write_bytes(payload)
        return str(file)

    def test_pcapng_forces_scheme_when_libpcap_selected(self):
        # Recognize content even if an exporter supplied a .pcap extension.
        for name in ("sessions.pcapng", "sessions.pcap", "unusual.bin"):
            with self.subTest(name=name):
                path = self._capture(name, b"\x0a\x0d\x0d\x0a" + b"rest")
                self.assertEqual(self.reader(path, True), "--scheme")

    def test_libpcap_preserved_for_classic_pcap(self):
        for magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                      b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            with self.subTest(magic=magic):
                path = self._capture("capture.pcap", magic + b"rest")
                self.assertEqual(self.reader(path, True), "--libpcap")
                self.assertEqual(self.reader(path, False), "--scheme")

    def test_pcapng_extension_does_not_override_content(self):
        path = self._capture("fake.pcapng", b"\xd4\xc3\xb2\xa1more")
        self.assertEqual(self.reader(path, True), "--libpcap")

    def test_scheme_default_unchanged(self):
        # With scheme configured, no format check or disk read is required.
        self.assertEqual(self.reader("/nonexistent/file.pcapng", False),
                         "--scheme")

    def test_empty_input_uses_configured_reader(self):
        path = self._capture("empty.pcapng", b"")
        self.assertEqual(self.reader(path, True), "--libpcap")

    def test_worker_uses_selected_option(self):
        source = Path(__file__).resolve().parents[1] / "pcap_processor.py"
        text = source.read_text()
        self.assertIn("cmd.append(arkime_pcap_reader_option(", text)
        self.assertIn("fileInfo[FILE_INFO_DICT_NAME], useLibPcap)", text)


if __name__ == "__main__":
    unittest.main()
