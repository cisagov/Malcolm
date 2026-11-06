#!/usr/bin/env python3
# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.
"""Use Arkime-published MaxMind databases in the Logstash GeoIP filters.

This is opt-in and runs on the copied runtime pipeline files, never on the
source templates. It fails before modifying any files if the shared volume
does not contain both databases required by the filters.
"""

import argparse
import os
import re
import tempfile
from pathlib import Path

GEOIP_OPEN = re.compile(r"^(\s*)geoip\s*\{\s*(?:#.*)?$")
GEOIP_CLOSE = re.compile(r"^\s*}\s*$")
CUSTOM_DATABASE = re.compile(r"^\s*database\s*=>", re.MULTILINE)
ASN_DATABASE = re.compile(
    r"""^\s*default_database_type\s*=>\s*['"]ASN['"]""", re.MULTILINE
)
DEFAULT_SHARED_DIR = Path("/var/local/geoip")


def configure_text(text: str, city: Path, asn: Path) -> tuple[str, int]:
    """Insert the appropriate database path into each GeoIP filter."""
    output: list[str] = []
    block: list[str] = []
    indent = ""
    updated = 0

    for line in text.splitlines(keepends=True):
        if not block:
            match = GEOIP_OPEN.match(line.rstrip("\r\n"))
            if match:
                block = [line]
                indent = match.group(1)
            else:
                output.append(line)
            continue

        if not GEOIP_CLOSE.match(line.rstrip("\r\n")):
            block.append(line)
            continue

        block_text = "".join(block)
        if not CUSTOM_DATABASE.search(block_text):
            database = asn if ASN_DATABASE.search(block_text) else city
            block.append(f'{indent}  database => "{database}"\n')
            updated += 1
        output.extend(block)
        output.append(line)
        block.clear()

    if block:
        raise ValueError("Unclosed geoip filter in pipeline configuration")
    return "".join(output), updated


def configure_pipeline_dir(pipelines: Path, shared: Path) -> int:
    """Validate MMDBs, then update each active filter config atomically."""
    databases = {kind: shared / f"GeoLite2-{kind}.mmdb" for kind in ("City", "ASN")}
    for path in databases.values():
        if not path.is_file() or path.stat().st_size == 0:
            raise FileNotFoundError(
                f"Shared GeoIP database missing or empty: {path}. "
                "Start Arkime with MaxMind credentials and publish its "
                "databases before enabling LOGSTASH_GEOIP_SHARED_DB."
            )

    changes: dict[Path, str] = {}
    total = 0
    for path in sorted(pipelines.rglob("*.conf")):
        new_text, count = configure_text(
            path.read_text(encoding="utf-8"),
            databases["City"],
            databases["ASN"],
        )
        if count:
            changes[path] = new_text
            total += count

    # Do not mutate any files until all selected configs have been validated.
    for path, text in changes.items():
        fd, temporary = tempfile.mkstemp(prefix=".geoip-", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                output.write(text)
            os.chmod(temporary, path.stat().st_mode & 0o777)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    return total


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pipelines", type=Path)
    parser.add_argument(
        "--shared-dir",
        type=Path,
        default=DEFAULT_SHARED_DIR,
        help="Directory with Arkime-published City and ASN MMDB files.",
    )
    args = parser.parse_args()
    try:
        total = configure_pipeline_dir(args.pipelines, args.shared_dir)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Unable to configure shared GeoIP databases: {error}\n")
    print(f"Configured {total} Logstash GeoIP filters using shared MaxMind MMDBs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
