#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Apply extra KEY=VALUE entries to .env files for --extra support."""

from __future__ import annotations

import os
import re
from typing import Iterable, Optional

from scripts.installer.utils.logger_utils import InstallerLogger
from scripts.installer.core.config_env_mapper import EnvMapper

_EXTRA_PATTERN = re.compile(r"^([^:]+):([^=]+)=(.*)$")


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
            return bool(item_keys) and (
                os.path.basename(mapped_file or "") == target_file_basename
            )
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
            InstallerLogger.error(
                f"Ignoring extra value ({var_name}={var_value}) in {file_basename} (not .env file)"
            )
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
