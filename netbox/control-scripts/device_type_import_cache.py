"""Store per-library NetBox import completion markers in the NetBox database.

The device library ships inside the container, while NetBox's PostgreSQL database
survives container restarts. Tag records in NetBox itself avoid assuming that
host-side media caches and the database are always restored together.
"""

import hashlib
import logging
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)

MARKER_PREFIX = "malcolm-device-library-"


def selected_vendors(value):
    """Parse an optional comma-separated list accepted by nb-dt-import."""
    return tuple(sorted({slug for part in (value or "").split(",") if (slug := part.strip().casefold())}))


def library_fingerprint(library_dir, vendors=()):
    """Compute a stable identity for all bundled YAML inputs and vendor scope."""
    source = Path(library_dir) / "repo"
    if not source.is_dir():
        return None
    files = sorted(
        path for path in source.rglob("*")
        if path.is_file() and not path.is_symlink() and path.suffix.casefold() in (".yaml", ".yml")
    )
    if not files:
        return None

    digest = hashlib.sha256()
    for vendor in vendors:
        digest.update(b"vendor\0")
        digest.update(vendor.encode("utf-8"))
        digest.update(b"\0")
    for path in files:
        digest.update(path.relative_to(source).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return MARKER_PREFIX + digest.hexdigest()[:32]


def import_successful(exit_code, output):
    """Do not cache partial imports: the upstream importer can exit zero on failures."""
    if exit_code != 0 or not output:
        return False
    return not any(
        re.search(
            r"\b(?:[1-9][0-9]* (?:device types?|modules?|rack types?) (?:FAILED|failed|partially updated)|failed to create or update)\b",
            str(line),
            re.IGNORECASE,
        )
        for line in output
    )


def completed(nb, marker):
    """Check a marker stored in the same PostgreSQL DB as the imported types."""
    return bool(nb.extras.tags.get(slug=marker))


def record_completion(nb, marker):
    """Only persist completion after a successful, non-partial import."""
    nb.extras.tags.create(
        {
            "name": marker,
            "slug": marker,
            "color": "808080",
            "description": "Malcolm device-type library initialization completed",
        }
    )


def import_device_type_library(args, netbox_venv_py, nb, run_process, pushd):
    """Import bundled device types only when their DB-backed marker is absent."""
    success = False

    # ######  Device-Type-Library-Import ###########################################################################
    if os.path.isdir(args.library_dir):
        vendors = selected_vendors(args.library_vendors)
        marker = library_fingerprint(args.library_dir, vendors)
        if marker and nb and not args.force_library_import:
            try:
                if completed(nb, marker):
                    logger.info("Device type library already imported; skipping unchanged library and vendor selection")
                    return True
            except Exception as e:  # noqa: BLE001 - fail open, preserving import
                # A failed marker lookup must never silently skip an import.
                logger.warning(f"Cannot check NetBox device library import marker; importing: {e}")

        try:
            with pushd(args.library_dir):
                os_env = os.environ.copy()
                os_env['NETBOX_URL'] = args.netbox_url
                os_env['NETBOX_TOKEN'] = args.netbox_token
                os_env.pop('VIRTUAL_ENV', None)
                os_env['REPO_URL'] = 'local'
                os_env['REPO_PATH'] = './repo'
                cmd = [netbox_venv_py, '-m', 'uv', 'run', '--no-sync', 'nb-dt-import.py']
                if vendors:
                    cmd.extend(['--vendors', *vendors])
                err, results = run_process(
                    cmd,
                    logger=logging,
                    env=os_env,
                )
                if import_successful(err, results):
                    logger.debug(f"nb-dt-import.py: {results}")
                    success = True
                    if marker and nb:
                        try:
                            record_completion(nb, marker)
                        except Exception as e:  # noqa: BLE001 - fail open, preserving import
                            # Successful imports remain valid even if the marker cannot be saved;
                            # they will simply be retried on the next container restart.
                            logger.warning(f"Device type library imported but completion marker was not saved: {e}")
                else:
                    logger.error(f"{err} running nb-dt-import.py (possibly partial import): {results}")

        except Exception as e:  # noqa: BLE001 - fail open, preserving import
            logger.error(f"{type(e).__name__} processing library: {e}")

    return success
