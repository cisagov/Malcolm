"""Tests for the VPC Flow Log exporter, without AWS/network dependencies."""

import contextlib
import gzip
import io
import json
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import aws_vpc_flow_to_json as converter

EXAMPLE = (
    "2 000012345678 eni-abc 192.0.2.10 2001:db8::4 443 50231 "
    "6 17 5120 1690000000 1690000060 ACCEPT OK"
)


class VpcFlowLogConverterTest(unittest.TestCase):
    def test_default_record_preserves_account_and_network_fields(self):
        record = converter.parse_record(EXAMPLE, converter.DEFAULT_FIELDS)
        self.assertEqual(record["module"], "aws_vpcflow")
        self.assertEqual(record["account_id"], "000012345678")
        self.assertEqual(record["srcaddr"], "192.0.2.10")
        self.assertEqual(record["dstaddr"], "2001:db8::4")
        self.assertEqual(record["srcport"], 443)
        self.assertEqual(record["dstport"], 50231)
        self.assertEqual(record["packets"], 17)
        self.assertEqual(record["bytes"], 5120)
        self.assertEqual(record["protocol"], 6)
        self.assertEqual(record["date"], 1690000000)
        self.assertEqual(record["action"], "ACCEPT")
        self.assertEqual(record["raw"], EXAMPLE)

    def test_cloudwatch_export_timestamp_prefix(self):
        stamped = "1690000060123 " + EXAMPLE
        event = converter.parse_record(stamped, converter.DEFAULT_FIELDS)
        self.assertEqual(event["cloudwatch_timestamp_ms"], 1690000060123)
        self.assertEqual(event["date"], 1690000000)
        self.assertEqual(event["raw"], stamped)
        rows = list(converter.convert_lines([
            "1690000000123 " + " ".join(converter.DEFAULT_FIELDS),
            stamped,
        ]))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0], event)

    def test_missing_values_and_nodata_remain_searchable(self):
        line = "2 012345678901 eni-test - - - - - - - 1690000000 1690000060 - NODATA"
        event = converter.parse_record(line, converter.DEFAULT_FIELDS)
        self.assertEqual(event["log_status"], "NODATA")
        self.assertNotIn("srcaddr", event)
        self.assertNotIn("protocol", event)
        self.assertIn("date", event)

    def test_custom_fields_and_automatic_header(self):
        header = "version account-id interface-id srcaddr dstaddr packets bytes start end action log-status region"
        line = "3 123456789012 eni-123 10.0.0.1 10.0.0.2 5 99 1690000000 1690000010 REJECT OK eu-west-2"
        rows = list(converter.convert_lines([header, line], source="flows"))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["region"], "eu-west-2")
        self.assertEqual(rows[0]["version"], 3)
        self.assertEqual(rows[0]["action"], "REJECT")
        fields = converter.parse_field_names("version,account-id,srcaddr")
        self.assertEqual(fields, ("version", "account-id", "srcaddr"))

    def test_malformed_and_unsafe_records_rejected(self):
        variants = [
            EXAMPLE.replace("192.0.2.10", "bad-ip"),
            EXAMPLE.replace(" 443 50231 ", " 70000 50231 "),
            EXAMPLE.replace(" 6 17 5120 ", " 999 17 5120 "),
            EXAMPLE.replace(" 6 17 5120 ", " 6 -17 5120 "),
            EXAMPLE + " extra",
            EXAMPLE.rsplit(" ", 1)[0].rsplit(" ", 1)[0],
        ]
        for text in variants:
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    converter.parse_record(text, converter.DEFAULT_FIELDS)
        for fields in ("", "version,version", "version,account@id"):
            with self.subTest(fields=fields):
                with self.assertRaises(ValueError):
                    converter.parse_field_names(fields)

    def test_input_rows_are_streamed_and_skip_invalid_is_explicit(self):
        rows = iter([EXAMPLE, "bad data", EXAMPLE])
        errors = []
        output = converter.convert_lines(
            rows, source="vpc.log", skip_invalid=True, errors=errors
        )
        self.assertEqual(next(output)["action"], "ACCEPT")
        self.assertEqual(len(errors), 0)
        self.assertEqual(len(list(output)), 1)
        self.assertEqual(len(errors), 1)
        self.assertIn("vpc.log:2:", errors[0])
        with self.assertRaisesRegex(ValueError, "vpc.log:2:"):
            list(converter.convert_lines([EXAMPLE, "bad data"], source="vpc.log"))

    def test_main_reads_plain_and_gz_files_and_writes_ndjson(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "first.log"
            path.write_text("# exported VPC logs\n" + EXAMPLE + "\n", encoding="utf-8")
            gz = Path(tmp) / "second.log.gz"
            with gzip.open(gz, "wt", encoding="utf-8") as f:
                f.write(EXAMPLE + "\n")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(converter.main([str(path), str(gz)]), 0)
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0], records[1])

    def test_main_skip_invalid_logs_errors_without_losing_good_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vpc.log"
            path.write_text("invalid\n" + EXAMPLE + "\n", encoding="utf-8")
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                self.assertEqual(converter.main(["--skip-invalid", str(path)]), 0)
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assertIn("Skipped 1 invalid record", errors.getvalue())

    def test_main_send_uses_tls_connection_and_ndjson(self):
        class FakeTls:
            def __init__(self):
                self.data = bytearray()

            def sendall(self, data):
                self.data.extend(data)

        channel = FakeTls()

        @contextlib.contextmanager
        def local_tls(*args):
            self.assertEqual(args[:3], ("localhost", 5045, "/tmp/ca.crt"))
            yield channel

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vpc.log"
            path.write_text(EXAMPLE + "\n", encoding="utf-8")
            output = io.StringIO()
            with mock.patch.object(converter, "tls_connection", local_tls):
                with contextlib.redirect_stdout(output):
                    self.assertEqual(converter.main([
                        "--send-host", "localhost", "--ca-cert", "/tmp/ca.crt",
                        str(path)
                    ]), 0)
        self.assertEqual(output.getvalue(), "")
        rows = [json.loads(line) for line in channel.data.decode().splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["account_id"], "000012345678")

    def test_tls_connection_verifies_peer_and_loads_client_credentials(self):
        with mock.patch.object(converter.ssl, "create_default_context") as make_tls:
            with mock.patch.object(converter.socket, "create_connection") as connect:
                with converter.tls_connection(
                    "127.0.0.1", 5045, "/tmp/ca.crt",
                    client_cert="/tmp/client.crt",
                    client_key="/tmp/client.key",
                    server_name="malcolm.local"
                ) as connection:
                    self.assertIs(
                        connection,
                        make_tls.return_value.wrap_socket.return_value.__enter__.return_value
                    )
                make_tls.assert_called_once_with(cafile="/tmp/ca.crt")
                make_tls.return_value.load_cert_chain.assert_called_once_with(
                    certfile="/tmp/client.crt", keyfile="/tmp/client.key"
                )
                connect.assert_called_once_with(("127.0.0.1", 5045), timeout=15)
                make_tls.return_value.wrap_socket.assert_called_once_with(
                    connect.return_value.__enter__.return_value,
                    server_hostname="malcolm.local"
                )

    def test_sender_requires_ca_and_valid_client_cert_pair(self):
        for options in (["--send-host", "localhost"],
                        ["--client-cert", "client.crt"]):
            with self.subTest(options=options):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as exc:
                        converter.main(options + ["-"])
                self.assertEqual(exc.exception.code, 2)

    def test_main_error_exits_nonzero_without_traceback(self):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            self.assertEqual(converter.main(["/missing/aws-flow.log.gz"]), 1)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("conversion failed", errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
