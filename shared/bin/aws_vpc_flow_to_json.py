#!/usr/bin/env python3
# Copyright (c) 2026 Battelle Energy Alliance, LLC. All rights reserved.
"""Stream AWS VPC Flow Log exports as JSON lines for Malcolm's TCP log input.

Supports the default 14-field v2 record, optional S3-style header rows,
custom --fields order, plain text and gzip input. No AWS credentials or
network connections are needed; retrieve authorized exports separately.
"""

import argparse
import contextlib
import gzip
import ipaddress
import json
import re
import socket
import ssl
import sys
from pathlib import Path

DEFAULT_FIELDS = (
    "version", "account-id", "interface-id", "srcaddr", "dstaddr",
    "srcport", "dstport", "protocol", "packets", "bytes", "start",
    "end", "action", "log-status",
)
INTEGER_FIELDS = {
    "version", "srcport", "dstport", "protocol", "packets", "bytes",
    "start", "end", "tcp-flags",
}
IP_FIELDS = {"srcaddr", "dstaddr", "pkt-srcaddr", "pkt-dstaddr"}
# The field order may be customized in the AWS VPC Flow Log configuration.
FIELD_PATTERN = re.compile(r"^[a-z][a-z0-9_-]*$")


def parse_field_names(text):
    """Normalize comma- or space-delimited AWS field names."""
    fields = tuple(part for part in re.split(r"[,\s]+", text.strip()) if part)
    if not fields or any(not FIELD_PATTERN.fullmatch(item) for item in fields):
        raise ValueError("expected space- or comma-separated AWS field names")
    if len(set(fields)) != len(fields):
        raise ValueError("duplicate AWS VPC Flow Log field names")
    return fields


def parse_record(line, fields):
    """Convert a single flow-log row to a Malcolm-compatible JSON event."""
    values = line.split()
    # CloudWatch-to-S3 exports may prefix each log message with a UNIX
    # timestamp in milliseconds. The direct VPC-to-S3 format does not.
    exported_at = None
    if (len(values) == len(fields) + 1 and len(values[0]) >= 13
            and values[0].isascii() and values[0].isdecimal()):
        exported_at = int(values.pop(0))
    if len(values) != len(fields):
        raise ValueError(f"expected {len(fields)} fields, received {len(values)}")

    original = dict(zip(fields, values))
    record = {
        "module": "aws_vpcflow",
        "raw": line,
    }
    if exported_at is not None:
        record["cloudwatch_timestamp_ms"] = exported_at
    for name, value in original.items():
        # AWS uses '-' for unavailable data, including NODATA and SKIPDATA.
        if value == "-":
            continue
        if name in INTEGER_FIELDS:
            try:
                converted = int(value, 10)
            except ValueError as exc:
                raise ValueError(f"invalid integer for {name}: {value!r}") from exc
            if converted < 0:
                raise ValueError(f"negative integer for {name}: {value!r}")
            if name in {"srcport", "dstport"} and converted > 65535:
                raise ValueError(f"invalid port {name}: {value!r}")
            if name == "protocol" and converted > 255:
                raise ValueError(f"invalid protocol number: {value!r}")
        elif name in IP_FIELDS:
            try:
                converted = str(ipaddress.ip_address(value))
            except ValueError as exc:
                raise ValueError(f"invalid IP address for {name}: {value!r}") from exc
        else:
            converted = value
        record[name.replace("-", "_")] = converted

    # The existing Malcolm miscbeat pipeline uses the date key as UNIX time.
    if "start" in record:
        record["date"] = record["start"]
    return record


def convert_lines(lines, *, fields=DEFAULT_FIELDS, skip_invalid=False,
                  source="<stdin>", errors=None):
    """Yield records incrementally; never buffer an entire AWS export."""
    active_fields = tuple(fields)
    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # AWS's S3 exports may contain a header listing the ordered fields.
        # A CloudWatch export can prefix that header with an event timestamp.
        parts = line.split()
        if (len(parts) > 1 and len(parts[0]) >= 13
                and parts[0].isascii() and parts[0].isdecimal()):
            possible_header = parts[1:]
        else:
            possible_header = parts
        if possible_header and possible_header[0] == "version":
            active_fields = parse_field_names(" ".join(possible_header))
            continue
        try:
            yield parse_record(line, active_fields)
        except ValueError as exc:
            message = f"{source}:{line_number}: {exc}"
            if not skip_invalid:
                raise ValueError(message) from exc
            if errors is not None:
                errors.append(message)


def _read_file(path):
    if path == "-":
        return contextlib.nullcontext(sys.stdin)
    filename = Path(path)
    opener = gzip.open if filename.suffix == ".gz" else open
    return opener(filename, "rt", encoding="utf-8-sig")


@contextlib.contextmanager
def tls_connection(host, port, ca_cert, client_cert=None, client_key=None,
                   server_name=None):
    """Open a verified TLS session for Malcolm's Filebeat TCP JSON listener."""
    context = ssl.create_default_context(cafile=ca_cert)
    if client_cert:
        context.load_cert_chain(certfile=client_cert, keyfile=client_key)
    with socket.create_connection((host, port), timeout=15) as connection:
        with context.wrap_socket(connection, server_hostname=server_name or host) as secure:
            yield secure


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", help="Flow Log exports (.log or .gz), or '-' for stdin")
    parser.add_argument(
        "--fields",
        help="Ordered custom AWS VPC Flow Log fields, separated by spaces or commas",
    )
    parser.add_argument(
        "--skip-invalid",
        action="store_true",
        help="Log invalid input rows to stderr instead of exiting",
    )
    parser.add_argument(
        "--send-host",
        help="Send the JSON lines to Malcolm's secured Filebeat TCP listener",
    )
    parser.add_argument("--port", type=int, default=5045)
    parser.add_argument(
        "--ca-cert", help="Trusted CA PEM file; required with --send-host",
    )
    parser.add_argument("--client-cert", help="Optional TLS client certificate PEM")
    parser.add_argument("--client-key", help="Optional TLS client private key PEM")
    parser.add_argument(
        "--server-name",
        help="Expected DNS name in Malcolm's TLS certificate (defaults to send host)",
    )
    args = parser.parse_args(argv)
    if args.send_host and not args.ca_cert:
        parser.error("--ca-cert is required when sending to Malcolm")
    if bool(args.client_cert) != bool(args.client_key):
        parser.error("--client-cert and --client-key must be specified together")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    try:
        names = parse_field_names(args.fields) if args.fields else DEFAULT_FIELDS
        errors = []
        connection = (
            tls_connection(args.send_host, args.port, args.ca_cert,
                           args.client_cert, args.client_key, args.server_name)
            if args.send_host else contextlib.nullcontext(None)
        )
        with connection as destination:
            for filename in args.files:
                with _read_file(filename) as handle:
                    for row in convert_lines(
                        handle, fields=names, skip_invalid=args.skip_invalid,
                        source=filename, errors=errors
                    ):
                        payload = json.dumps(row, separators=(",", ":")) + "\n"
                        if destination is None:
                            sys.stdout.write(payload)
                        else:
                            destination.sendall(payload.encode("utf-8"))
        for item in errors:
            print(item, file=sys.stderr)
        if errors:
            print(f"Skipped {len(errors)} invalid record(s)", file=sys.stderr)
        return 0
    except (OSError, ValueError) as exc:
        print(f"VPC Flow Log conversion failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
