#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""Write .env files: staged all-or-nothing saves, raw .env restore, and --extra support."""

from __future__ import annotations

import glob
import os
import re
import shutil
import tempfile
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Dict, Iterable, Iterator, Optional

from scripts.installer.utils.logger_utils import InstallerLogger
from scripts.installer.core.config_env_mapper import EnvMapper
from scripts.malcolm_utils import base64_decode_files_to_dir

if TYPE_CHECKING:
    from scripts.installer.core.malcolm_config import MalcolmConfig

_EXTRA_PATTERN = re.compile(r"^([^:]+):([^=]+)=(.*)$")

# a line that sets a variable in a .env file: "NAME=value" (optionally "export NAME=value")
_ENV_ASSIGNMENT_PATTERN = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")


@contextmanager
def staged_env_dir(output_dir: str) -> Iterator[str]:
    """Prepare .env changes in a scratch copy of output_dir, then move them in only if all succeed.

    Yields a staging directory holding copies of the existing .env files in output_dir. When the
    block finishes without an exception, each staged .env file replaces its counterpart in
    output_dir (os.replace, so each file is swapped in whole). If the block raises, output_dir is
    left exactly as it was. The staging directory is a hidden subdirectory of output_dir, so it's
    always writable and on the same filesystem (os.replace can't cross filesystems), and things that
    read the configuration (which look for *.env, skipping hidden directories) never see it. It is
    always removed.
    """
    output_dir = os.path.realpath(output_dir)
    staging_dir = tempfile.mkdtemp(prefix=".staging-", dir=output_dir)
    try:
        for env_file in glob.glob(os.path.join(output_dir, "*.env")):
            shutil.copy2(env_file, staging_dir)  # copy2 keeps the file's permissions
        yield staging_dir
        for staged_file in glob.glob(os.path.join(staging_dir, "*.env")):
            os.replace(staged_file, os.path.join(output_dir, os.path.basename(staged_file)))
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)


def restore_raw_env_files(raw_envs: Dict[str, Any], config_dir: str) -> int:
    """Restore .env files backed up in an imported settings file's "raw" section into config_dir.

    The backed-up file replaces an existing one so its comments and formatting come back, but any
    variable that only the existing file sets is kept (appended at the end). Variables the installer
    manages are written afterward by generate_env_files, so this mostly matters for the settings and
    comments the installer doesn't know about.

    Returns:
        The number of files restored.
    """
    restored = 0
    with tempfile.TemporaryDirectory(prefix="malcolm-raw-env-") as raw_dir:
        base64_decode_files_to_dir(raw_envs, raw_dir, "*.env")
        for raw_file in glob.glob(os.path.join(raw_dir, "*.env")):
            target_file = os.path.join(config_dir, os.path.basename(raw_file))
            with open(raw_file, "r", encoding="utf-8") as f:
                raw_lines = f.readlines()
            if raw_lines and not raw_lines[-1].endswith("\n"):
                raw_lines[-1] += "\n"  # so nothing appended later runs onto the last line
            if os.path.isfile(target_file):
                raw_names = {m.group(1) for line in raw_lines if (m := _ENV_ASSIGNMENT_PATTERN.match(line))}
                with open(target_file, "r", encoding="utf-8") as f:
                    kept_lines = [
                        line
                        for line in f.readlines()
                        if (m := _ENV_ASSIGNMENT_PATTERN.match(line)) and (m.group(1) not in raw_names)
                    ]
                if kept_lines:
                    raw_lines.append("# settings kept from the existing file\n")
                    raw_lines.extend(line if line.endswith("\n") else line + "\n" for line in kept_lines)
            with open(target_file, "w", encoding="utf-8") as f:
                f.writelines(raw_lines)
            restored += 1
    return restored


def write_configuration_files(
    malcolm_config: "MalcolmConfig",
    output_dir: str,
    raw_envs: Optional[Dict[str, Any]] = None,
    extras: Optional[Iterable[str]] = None,
) -> None:
    """Save the configuration to the .env files in output_dir, all or nothing.

    In a staging copy of output_dir: restore the .env backup from an imported settings file (if
    any), write the configuration, then apply --extra settings. Only if all of that succeeds do
    the new files replace the old ones.

    Raises:
        FileOperationError (or another exception) if any step fails; output_dir is unchanged.
    """
    with staged_env_dir(output_dir) as staging_dir:
        if raw_envs:
            restored = restore_raw_env_files(raw_envs, staging_dir)
            InstallerLogger.info(f"Restored {restored} of {len(raw_envs)} .env file(s) from the imported settings file")
        malcolm_config.generate_env_files(staging_dir)
        if extras:
            apply_extra_env_settings(staging_dir, extras, malcolm_config.get_env_mapper())
    malcolm_config.config_dir_written = output_dir


def _set_env_var_in_file(file_path: str, key: str, value: str) -> bool:
    """Create or update a KEY=value in a .env file.

    - If the file exists, update the first matching KEY=... entry, preserving other lines.
    - If the key does not exist, append KEY=value to the end of the file.
    - If the file does not exist, create it with a simple header and the KEY=value line.

    Returns True on success, False on error.
    """
    try:
        lines: list[str] = []
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            updated = False
            for i, line in enumerate(lines):
                # Match KEY=... at start of line, ignoring whitespace
                if line.lstrip().startswith(f"{key}="):
                    lines[i] = f"{key}={value}\n"
                    updated = True
                    break
            if not updated:
                # ensure file ends with a newline before appending
                if lines and not lines[-1].endswith("\n"):
                    lines[-1] = lines[-1] + "\n"
                lines.append(f"{key}={value}\n")

            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
            return True

        # create new file
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(f"{key}={value}\n")
        return True
    except Exception as e:  # pragma: no cover - basic file I/O error path
        InstallerLogger.error(f"Failed updating env file {file_path}: {e}")
        return False


def apply_extra_env_settings(
    config_dir: str,
    extras: Optional[Iterable[str]],
    env_mapper: Optional["EnvMapper"] = None,
) -> None:
    """Apply extra env settings to .env files in config_dir.

    Each entry in 'extras' must be of the form 'file.env:KEY=value'. Only
    updates to files ending in .env are allowed. If an entry refers to an
    installer-managed variable (i.e., one mapped to ConfigItems), it will be
    ignored to preserve the installer as the source of truth.
    """
    if not extras:
        return

    # Normalize mapper usage based on availability
    def _is_cli_managed(variable_name: str, target_file_basename: str) -> bool:
        # If mapper not provided or unavailable, treat as not managed
        if env_mapper is None or not hasattr(env_mapper, "get_item_keys_by_env_var"):
            return False

        try:
            # Only consider a variable managed if it maps to one or more config items
            # and resides in the same target .env file according to the mapper.
            item_keys = env_mapper.get_item_keys_by_env_var(variable_name)
            mapped_file = env_mapper.get_file_for_variable(variable_name)
            return bool(item_keys) and (os.path.basename(mapped_file or "") == target_file_basename)
        except Exception:
            return False

    for extra in extras:
        m = _EXTRA_PATTERN.match(str(extra))
        if not m:
            InstallerLogger.error(f"Ignoring invalid --extra format: {extra}")
            continue

        file_part, var_name, var_value = [s.strip() for s in m.groups()]
        file_basename = os.path.basename(file_part)
        target_file = os.path.join(config_dir, file_basename)

        if not file_basename.endswith(".env"):
            InstallerLogger.error(f"Ignoring extra value ({var_name}={var_value}) in {file_basename} (not .env file)")
            continue

        if _is_cli_managed(var_name, file_basename):
            InstallerLogger.error(
                f"Ignoring extra value ({var_name}={var_value}) in {file_basename} (use dedicated CLI argument)"
            )
            continue

        success = _set_env_var_in_file(target_file, var_name, var_value)
        InstallerLogger.info(
            f"Setting extra value ({var_name}={var_value}) in {file_basename} {'succeeded' if success else 'failed'}"
        )
