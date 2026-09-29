#!/usr/bin/env python3
"""
check_scanner_output.py — determine, per scanner, whether a Strelka results
JSONL file shows evidence of that scanner actually producing output, not
merely running without error.

Background: a scanner's "success" signal isn't uniform across Strelka's
codebase. Three different mechanisms are used, and a scanner may rely on
one, two, or all three:

  1. FIELDS  — the scanner adds keys to its own `scan.<name>` dict beyond
               the baseline {elapsed, scanner}. This is what a naive jq
               `keys` check catches, and is the default assumption below
               unless a scanner is known to behave differently.

  2. FLAG    — the scanner's ONLY signal is an entry in the top-level
               `flags` array for that result. Two flag styles exist in
               this codebase:
                 - self.add_flag(x)      -> stored as "{scanner_key}:{x}"
                 - self.flags.append(x)  -> stored as a bare "{x}", with
                                            no scanner-name prefix at all
               Bare flags are only attributable to a specific scanner
               because we already know (from `scan` / `exceptions` on the
               same result) which scanners ran against that file.

  3. CHILD   — the scanner's only signal is emitting a brand-new child
               file elsewhere in `results.strelka.results[]`, via
               `self.emit_file(...)`. Child results carry a `file.source`
               tag identifying what produced them; this script assumes
               that tag equals the scanner's own short key (e.g. "zip",
               "cart") unless overridden below, matching what's been
               observed in practice. If a given scanner's child files
               don't actually carry that tag, override its `child` list.

For every scanner we've inspected source for, this script encodes which
mechanism(s) apply, cross-referenced only against results where that
scanner is known to have actually run (present in `scan` or `exceptions`
for that result) — so a bare flag string can't be misattributed to a
scanner that never ran on that file.

Usage:
    python3 check_scanner_output.py results.jsonl
    python3 check_scanner_output.py results.jsonl --verbose
    python3 check_scanner_output.py results.jsonl --scanner cart,transcode
"""

import argparse
import json
import sys
from collections import defaultdict

# ----------------------------------------------------------------------
# Per-scanner rules. Keys are the short scanner name as it appears under
# `scan.<name>` (i.e. the snake_case form without the "Scan" prefix).
#
#   fields: True  -> any key beyond {elapsed, scanner} counts as success
#                     (this is the default for any scanner NOT listed here)
#   flags:  [...] -> any of these exact strings appearing in `flags` for
#                     a result where this scanner ran counts as success
#   child:  [...] -> any child result whose file.source is in this list
#                     counts as success for the PARENT result that scanner
#                     ran against
#
# A scanner can have more than one mechanism; ANY of them firing counts
# as success. Scanners not listed here fall back to fields-only checking,
# which is correct for the majority of Strelka's scanners.
# ----------------------------------------------------------------------
SCANNER_RULES = {
    # Category A: success is emit_file only, self.event untouched on success
    "antiword":  {"child": ["antiword"]},
    "bzip2":     {"child": ["bzip2"]},
    "gzip":      {"child": ["gzip"]},
    "lzma":      {"child": ["lzma"]},
    "zstd":      {"child": ["zstd"]},
    "cart":      {"child": ["cart"]},

    # Category B: success only visible via flags, never in scan.<name>
    "ccn":       {"flags": ["ccn:luhn_match"]},
    "clamav":    {"flags": ["clamav:signature_match"]},
    "upx":       {"flags": ["upx_packed"], "child": ["upx"]},

    # Mixed: has a real success flag AND/OR emits a child
    "transcode": {"flags": ["transcoded"], "child": ["transcode"]},
    "zlib":      {"fields": True, "child": ["zlib"]},   # sets event["size"] AND emits
    "rpm":       {"fields": True, "child": ["rpm"]},    # sets metadata fields AND emits
    "encrypted_doc": {"child": ["encrypted_doc"]},      # only emits on a successful crack+decrypt

    # Everything else defaults to fields=True (uncomment / add overrides
    # here as you learn more about a given scanner):
    # "base64":    {"fields": True},   # decoded_header always set on success
    # "iqy":       {"fields": True},   # address_found always set (even False)
    # "rtf":       {"fields": True},   # event["total"] always set
    # "tnef":      {"fields": True},   # event["total"] always set
    # "plist":     {"fields": True},   # event["keys"] set even if empty
}

# Scanners we expect to eventually see exercised, so they're reported as
# NEVER_RAN rather than silently omitted when the data has zero mentions
# of them at all (no clean run, no exception, no rule override above).
# This is the full enabled-scanner universe as of the last "enable
# everything" pass. Update as your enabled-scanner list changes.
#
# Note: ScanBase64PE is intentionally NOT listed separately — it shares
# scan_base64.py with ScanBase64 (same class, same self.key, routed via a
# different YARA flavor tag only), so it can never appear under its own
# name in the data. Its success is covered entirely by "base64".
EXPECTED_SCANNERS = {
    "antiword", "base64", "batch", "bmp_eof", "bzip2", "capa", "cart",
    "ccn", "clamav", "dmg", "docx", "donut", "elf", "email",
    "encrypted_doc", "encrypted_zip", "entropy", "exiftool", "footer",
    "gif_eof", "gzip", "header", "html", "ini", "iqy", "iso",
    "jar_manifest", "javascript", "jnlp", "jpeg_eof", "json", "libarchive",
    "lnk", "lsb", "lzma", "macho", "manifest", "msi", "nf", "ocr", "ole",
    "onenote", "pdf", "pe", "pgp", "php", "pkcs7", "plist", "png_eof",
    "pyinstaller", "qr", "rar", "rpm", "rtf", "seven_zip", "strings",
    "swf", "tar", "tlsh", "tnef", "transcode", "udf", "upx", "url", "vb",
    "vba", "vhd", "vsto", "x509", "xar", "xl4ma", "xml", "yara", "zip",
    "zlib", "zstd",
}

BASELINE_KEYS = {"elapsed", "scanner"}


def load_jsonl(path):
    docs = []
    with open(path, "r") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                docs.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"warning: skipping malformed line {lineno}: {e}", file=sys.stderr)
    return docs


def iter_results(docs):
    """Yield every result dict across every document's results.strelka.results[]."""
    for doc in docs:
        results = (
            doc.get("results", {})
            .get("strelka", {})
            .get("results", [])
        )
        for r in results or []:
            yield r


def analyze(docs, only_scanners=None):
    results = list(iter_results(docs))

    ran_clean = defaultdict(int)
    ran_exception = defaultdict(int)
    has_fields = defaultdict(int)
    has_success_flag = defaultdict(int)
    has_success_child = defaultdict(int)
    examples = defaultdict(list)

    # Pass 1: per-result scanner activity (fields, flags, exceptions)
    for r in results:
        scan_dict = r.get("scan", {}) or {}
        exc_scanners = {e.get("scanner") for e in (r.get("exceptions") or [])}
        flags = r.get("flags") or []

        for scanner, payload in scan_dict.items():
            if only_scanners and scanner not in only_scanners:
                continue

            if scanner in exc_scanners:
                ran_exception[scanner] += 1
                continue

            ran_clean[scanner] += 1

            extra_keys = set(payload.keys()) - BASELINE_KEYS if isinstance(payload, dict) else set()
            rule = SCANNER_RULES.get(scanner, {"fields": True})

            if rule.get("fields") and extra_keys:
                has_fields[scanner] += 1
                if len(examples[scanner]) < 3:
                    examples[scanner].append(f"fields: {sorted(extra_keys)}")

            for flag_name in rule.get("flags", []):
                if flag_name in flags:
                    has_success_flag[scanner] += 1
                    if len(examples[scanner]) < 3:
                        examples[scanner].append(f"flag: {flag_name}")

        for scanner in exc_scanners:
            if only_scanners and scanner not in only_scanners:
                continue
            if scanner not in scan_dict:
                ran_exception[scanner] += 1

    # Pass 2: child-emission detection.
    for r in results:
        source = (r.get("file") or {}).get("source")
        if not source:
            continue
        for scanner, rule in SCANNER_RULES.items():
            if only_scanners and scanner not in only_scanners:
                continue
            if source in rule.get("child", []):
                has_success_child[scanner] += 1
                if len(examples[scanner]) < 3:
                    examples[scanner].append(f"child emitted (source={source})")

    all_scanners = set(ran_clean) | set(ran_exception) | set(SCANNER_RULES) | EXPECTED_SCANNERS
    if only_scanners:
        all_scanners = set(only_scanners)

    report = {}
    for scanner in sorted(all_scanners):
        clean = ran_clean.get(scanner, 0)
        exc = ran_exception.get(scanner, 0)
        success = (
            has_fields.get(scanner, 0)
            + has_success_flag.get(scanner, 0)
            + has_success_child.get(scanner, 0)
        )

        if clean == 0 and exc == 0:
            status = "NEVER_RAN"
        elif success > 0:
            status = "SUCCESS"
        elif exc > 0 and clean == 0:
            status = "EXCEPTION_ONLY"
        else:
            status = "RAN_NO_SIGNAL"

        report[scanner] = {
            "status": status,
            "clean_runs": clean,
            "exceptions": exc,
            "success_hits": success,
            "examples": examples.get(scanner, []),
        }

    return report


def print_report(report, verbose=False):
    order = {"SUCCESS": 0, "RAN_NO_SIGNAL": 1, "EXCEPTION_ONLY": 2, "NEVER_RAN": 3}
    rows = sorted(report.items(), key=lambda kv: (order[kv[1]["status"]], kv[0]))

    symbol = {
        "SUCCESS": "YES",
        "RAN_NO_SIGNAL": "no  (ran clean, no output signal)",
        "EXCEPTION_ONLY": "no  (only threw exceptions)",
        "NEVER_RAN": "no  (never invoked)",
    }

    name_w = max(len(s) for s in report) + 2 if report else 10
    print(f"{'scanner'.ljust(name_w)}{'output?'.ljust(38)}clean  exc  hits")
    print("-" * (name_w + 38 + 16))
    for scanner, info in rows:
        print(
            f"{scanner.ljust(name_w)}{symbol[info['status']].ljust(38)}"
            f"{info['clean_runs']:<7}{info['exceptions']:<5}{info['success_hits']:<5}"
        )
        if verbose and info["examples"]:
            for ex in info["examples"]:
                print(f"{'':<{name_w}}  -> {ex}")

    counts = defaultdict(int)
    for _, info in report.items():
        counts[info["status"]] += 1
    print()
    print(
        f"Summary: {counts['SUCCESS']} confirmed producing output, "
        f"{counts['RAN_NO_SIGNAL']} ran but no signal, "
        f"{counts['EXCEPTION_ONLY']} exception-only, "
        f"{counts['NEVER_RAN']} never invoked."
    )


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("jsonl_path", help="Path to the Strelka results JSONL file")
    ap.add_argument("--verbose", action="store_true", help="Show example evidence per scanner")
    ap.add_argument(
        "--scanner",
        help="Comma-separated list of scanner short names to restrict the report to (e.g. cart,transcode)",
    )
    ap.add_argument(
        "--expected",
        help=(
            "Comma-separated list of scanner short names that should be reported as "
            "NEVER_RAN if absent, replacing the built-in EXPECTED_SCANNERS list."
        ),
    )
    args = ap.parse_args()

    only = set(s.strip() for s in args.scanner.split(",")) if args.scanner else None

    docs = load_jsonl(args.jsonl_path)
    if not docs:
        print("no valid JSON documents found", file=sys.stderr)
        sys.exit(1)

    if args.expected:
        global EXPECTED_SCANNERS
        EXPECTED_SCANNERS = set(s.strip() for s in args.expected.split(","))

    report = analyze(docs, only_scanners=only)
    print_report(report, verbose=args.verbose)


if __name__ == "__main__":
    main()
