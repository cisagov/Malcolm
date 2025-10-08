#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Utilities for artifact detection, validation, and extraction.
"""

import os
import glob
import shutil
import subprocess
import tarfile
from typing import Optional, Tuple, List, Callable


def validate_malcolm_tarball(path: str) -> Tuple[bool, Optional[str]]:
    """Validate that the provided path is a usable Malcolm tarball.

    Performs quick checks:
    - path exists and is a tar archive (auto-detect compression)
    - contains a docker-compose.yml somewhere within

    Returns: (is_valid, error_message)
    """
    if not path or not os.path.isfile(path):
        return False, f"Tarball not found: {path}"
    try:
        if not tarfile.is_tarfile(path):
            return False, f"Not a valid tar archive: {path}"
        with tarfile.open(path, mode="r:*") as tf:
            names = [m.name for m in tf.getmembers() if m.isfile()]
            if not any(n.endswith("docker-compose.yml") for n in names):
                return False, "Archive does not contain docker-compose.yml"
        return True, None
    except Exception as e:
        return False, f"Error validating tarball: {e}"


def validate_image_archive(path: str) -> Tuple[bool, Optional[str]]:
    """Validate that the provided path is a usable images archive (.tar.xz).

    Quick checks:
    - path exists and is a tar archive (auto-detect compression)

    Returns: (is_valid, error_message)
    """
    if not path or not os.path.isfile(path):
        return False, f"Image archive not found: {path}"
    try:
        if not tarfile.is_tarfile(path):
            return False, f"Not a valid tar archive: {path}"
        return True, None
    except Exception as e:
        return False, f"Error validating images archive: {e}"


def detect_malcolm_and_image_files(
    malcolm_file_arg: str = None, image_file_arg: str = None
) -> Tuple[List[str], List[str]]:
    """Detect Malcolm and image tarball files.

    Args:
        malcolm_file_arg: Malcolm .tar.gz file path from command line arguments
        image_file_arg: Malcolm container images .tar.xz file path from command line arguments

    Returns:
        Tuple of (list_of_malcolm_files, list_of_image_files)
    """
    malcolm_files = []
    image_files = []

    # Check if Malcolm file was provided via command line
    if malcolm_file_arg and os.path.isfile(malcolm_file_arg):
        malcolm_files.append(malcolm_file_arg)
    else:
        # Find all non-image tarballs, searching in pwd and then script path
        script_dir = os.path.dirname(os.path.abspath(__file__))
        current_dir = os.getcwd()

        # Support both hyphenated and underscored naming from packager
        malcolm_files = _discover_files(
            patterns=["malcolm[-_]*.tar.gz"],
            roots=[current_dir, script_dir],
            allow=lambda p: "_images" not in p,
        )

    # Check if image file was provided via command line
    if image_file_arg and os.path.isfile(image_file_arg):
        image_files.append(image_file_arg)
    else:
        # Find all image tarballs in pwd and script path
        script_dir = os.path.dirname(os.path.abspath(__file__))
        current_dir = os.getcwd()

        image_files = _discover_files(
            patterns=["malcolm[-_]*_images.tar.xz"],
            roots=[current_dir, script_dir],
        )

    return malcolm_files, image_files


 
# Selections and prompts are handled in higher-level logic (see artifact_utils).


def extract_malcolm_tarball(
    malcolm_install_file: str, install_path: str
) -> Tuple[bool, Optional[str]]:
    """Extract the Malcolm tarball to a specified directory.

    Args:
        malcolm_install_file: Path to the Malcolm .tar.gz file
        install_path: Directory path where to extract the tarball

    Returns:
        Tuple of (success, config_dir_path) where config_dir_path is the path to the created config directory
    """
    # Import here to avoid circular imports
    from scripts.installer.utils.logger_utils import InstallerLogger

    if os.path.isdir(install_path):
        InstallerLogger.error(
            f"{install_path} already exists, please specify a different installation path"
        )
        return False, None

    try:
        os.makedirs(install_path)
    except Exception as e:
        InstallerLogger.error(
            f"Failed to create {install_path}: {e}, please specify a different installation path"
        )
        return False, None

    # extract runtime files
    from scripts.malcolm_utils import SYSTEM_INFO, ChownRecursive

    ext_uid = SYSTEM_INFO["recommended_nonroot_uid"]
    ext_gid = SYSTEM_INFO["recommended_nonroot_gid"]

    with tarfile.open(malcolm_install_file, "r:gz") as tar:
        tar.extractall(path=install_path, numeric_owner=True)
    ChownRecursive(install_path, ext_uid, ext_gid)

    # .tar.gz normally will contain an intermediate subdirectory. if so, move files back one level
    child_dir = glob.glob(f"{install_path}/*/")
    if (len(child_dir) == 1) and os.path.isdir(child_dir[0]):
        try:
            for f in os.listdir(child_dir[0]):
                shutil.move(os.path.join(child_dir[0], f), install_path)
            shutil.rmtree(child_dir[0], ignore_errors=True)
        except Exception as e:
            InstallerLogger.error(
                f"Failed to move files from {child_dir[0]} to {install_path}: {e}"
            )
            return False, None

    # create the config directory for the .env files
    config_dir_path = os.path.join(install_path, "config")
    try:
        os.makedirs(config_dir_path, exist_ok=True)
    except Exception as e:
        InstallerLogger.error(f"Failed to create {config_dir_path}: {e}")
        return False, None

    # verify the installation worked
    if os.path.isfile(os.path.join(install_path, "docker-compose.yml")):
        InstallerLogger.info(f"Malcolm runtime files extracted to {install_path}")
        return True, config_dir_path
    else:
        InstallerLogger.error(
            f"Malcolm install file extracted to {install_path}, but missing runtime files?"
        )
        return False, None


def extract_image_files(
    image_file: str, install_path: str, runtime_bin: str = "docker"
) -> bool:
    """Load container images from archive file using docker/podman.

    Args:
        image_file: Path to the container images .tar.xz file
        install_path: Directory path where Malcolm is installed
        runtime_bin: Container runtime binary ('docker' or 'podman')

    Returns:
        True if successful, False otherwise
    """
    # Import here to avoid circular imports
    from scripts.installer.utils.logger_utils import InstallerLogger

    if not image_file or not os.path.isfile(image_file):
        InstallerLogger.error(f"Image file not found: {image_file}")
        return False

    # locate docker-compose.yml if present (not strictly required to load images)
    compose_file = os.path.join(install_path, "docker-compose.yml")
    if not os.path.isfile(compose_file):
        InstallerLogger.warning(
            f"No docker-compose.yml found under {install_path}; proceeding to load images anyway"
        )

    InstallerLogger.info(f"Loading Malcolm images from {image_file}")
    # construct the docker/podman load command (omit -q to surface progress)
    load_cmd = [runtime_bin, "load", "-i", image_file]

    try:
        # run the command with elevated privileges when needed
        if os.geteuid() != 0:
            load_cmd = ["sudo"] + load_cmd

        result = subprocess.run(
            load_cmd,
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode == 0:
            InstallerLogger.info("Successfully loaded Malcolm container images")
            return True
        else:
            InstallerLogger.error(f"Loading Malcolm images failed: {result.stderr}")
            return False

    except Exception as e:
        InstallerLogger.error(f"Error loading Malcolm images: {e}")
        return False
def _discover_files(
    patterns: List[str], roots: List[str], *, allow: Optional[Callable[[str], bool]] = None
) -> List[str]:
    """Discover files matching patterns across roots, with optional filter.

    Ensures de-duplication and returns paths sorted by modified time (desc).
    """
    discovered: List[str] = []
    for root in roots:
        for pat in patterns:
            try:
                for path in glob.glob(os.path.join(root, pat), recursive=False):
                    if allow is None or allow(path):
                        discovered.append(path)
            except Exception:
                # ignore unreadable roots/pattern issues
                pass

    # de-duplicate and sort newest first
    unique = list(set(discovered))
    try:
        unique.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    except Exception:
        # fall back to stable sort if mtimes not available
        unique.sort()
    return unique
