#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Resolve and handle Malcolm tarball/image artifacts during early setup."""

from typing import Optional, Tuple
from scripts.malcolm_common import UserInterfaceMode
import os

from scripts.installer.utils.logger_utils import InstallerLogger
from scripts.installer.utils.file_utils import (
    detect_malcolm_and_image_files,
    extract_image_files,
    extract_malcolm_tarball,
    validate_image_archive,
    validate_malcolm_tarball,
)
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_RUNTIME_BIN,
    KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
)
from scripts.malcolm_constants import OrchestrationFramework
from scripts.installer.configs.constants.enums import InstallerResult


def _ask_yes_no(ui_impl, question: str, default: bool) -> bool:
    try:
        if ui_impl is None:
            return default
        return bool(ui_impl.ask_yes_no(question, default=default))
    except Exception:
        return default


def _ask_string(ui_impl, prompt: str, default: str) -> str:
    try:
        if ui_impl is None:
            return default
        value = ui_impl.ask_string(prompt, default)
        return value or default
    except Exception:
        return default


def _orchestration_mode(malcolm_config):
    try:
        return malcolm_config.get_value(KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE)
    except Exception:
        return None


def _default_install_path(orig_path: str) -> str:
    return os.path.join(orig_path, "malcolm")


def _validate_artifacts_or_exit(
    mpath: Optional[str], ipath: Optional[str], cli_ifile_provided: bool
) -> Tuple[Optional[str], Optional[str]]:
    if mpath:
        ok, err = validate_malcolm_tarball(mpath)
        if not ok:
            InstallerLogger.error(f"Invalid Malcolm tarball: {mpath}: {err}")
            raise SystemExit(2)
    if ipath:
        ok, err = validate_image_archive(ipath)
        if not ok:
            if cli_ifile_provided:
                InstallerLogger.error(f"Invalid images archive: {ipath}: {err}")
                raise SystemExit(2)
            else:
                InstallerLogger.warning(
                    f"Ignoring invalid images archive: {ipath}: {err}"
                )
                ipath = None
    return mpath, ipath


def _perform_artifact_handling(
    mpath: Optional[str],
    ipath: Optional[str],
    install_path: str,
    control_flow,
    malcolm_config,
    ui_impl,
    orig_path: str,
) -> Tuple[bool, Optional[str]]:
    if control_flow.should_write_files():
        ok, cfg_dir = (
            extract_malcolm_tarball(mpath, install_path) if mpath else (True, None)
        )
        if not ok:
            InstallerLogger.error("Failed to process Malcolm tarball. Aborting.")
            raise SystemExit(1)
        if ipath:
            runtime_bin = malcolm_config.get_value(KEY_CONFIG_ITEM_RUNTIME_BIN) or "docker"
            InstallerLogger.info(
                "Loading container images from archive... This may take several minutes."
            )
            try:
                if ui_impl is not None and ui_impl.ui_mode == UserInterfaceMode.InteractionDialog:
                    ui_impl.display_message(
                        "Loading container images from archive... This may take several minutes."
                    )
            except Exception:
                pass
            extract_image_files(ipath, install_path if mpath else orig_path, runtime_bin)
        InstallerLogger.end("INSTALLER", InstallerResult.SUCCESS, "Package handling completed")
        return True, cfg_dir
    else:
        if mpath:
            InstallerLogger.info(
                f"Dry run: would extract Malcolm tarball {os.path.basename(mpath)} to {install_path}"
            )
        if ipath:
            InstallerLogger.info(
                f"Dry run: would extract image archive {os.path.basename(ipath)}"
            )
        InstallerLogger.end(
            "INSTALLER",
            InstallerResult.SKIPPED,
            "Dry run successful: skipped actual installation",
        )
        return True, None


def _detect_files_or_exit() -> Tuple[list, list]:
    try:
        return detect_malcolm_and_image_files()
    except Exception as e:
        InstallerLogger.error(
            f"Error while attempting to detect malcolm and image files: {e}"
        )
        raise SystemExit(1)


def decide_and_handle_artifacts(
    parsed_args,
    ui_impl,
    malcolm_config,
    control_flow,
    orig_path: str,
) -> Tuple[bool, Optional[str], Optional[str], Optional[str], Optional[str]]:
    """Resolve and optionally handle packaged artifacts early in setup.

    Returns tuple:
      (handled, selected_malcolm_file, selected_image_file, install_path, config_dir_override)

    When handled=True, the function already performed extraction/load and logged
    final status; the caller should exit the main flow early.
    """
    # 1) Handle CLI-provided artifacts
    # CLI args are always present; empty string means "not provided"
    cli_m = parsed_args.mfile or None
    cli_i = parsed_args.ifile or None

    # Kubernetes orchestration fast-exit: when Kubernetes mode is active and the user
    # did not explicitly supply artifact paths via CLI, skip tarball/images handling entirely.
    # This prevents unintended auto-detection from interfering with kubeconfig-driven flows.
    orch_mode = _orchestration_mode(malcolm_config)
    if (orch_mode == OrchestrationFramework.KUBERNETES) and (not cli_m) and (not cli_i):
        InstallerLogger.info("Kubernetes mode: skipping packaged artifact handling")
        return False, None, None, None, None
    # Split flows by whether CLI values were provided
    if cli_m or cli_i:
        return _handle_cli_artifacts(
            parsed_args, ui_impl, malcolm_config, control_flow, orig_path, cli_m, cli_i
        )

    return _handle_detected_artifacts(
        parsed_args, ui_impl, malcolm_config, control_flow, orig_path
    )


def _validate_cli_paths(cli_m: Optional[str], cli_i: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    mfile = cli_m if (cli_m and os.path.isfile(cli_m)) else None
    if cli_m and not mfile:
        InstallerLogger.error(f"Specified Malcolm tarball not found: {cli_m}")
        raise SystemExit(2)
    ifile = cli_i if (cli_i and os.path.isfile(cli_i)) else None
    if cli_i and not ifile:
        InstallerLogger.error(f"Specified images archive not found: {cli_i}")
        raise SystemExit(2)
    return mfile, ifile


def _maybe_offer_complementary_artifacts(
    mfile: Optional[str],
    ifile: Optional[str],
    parsed_args,
    ui_impl,
    install_path: str,
) -> Tuple[Optional[str], Optional[str], str]:
    # If only one provided, offer to use the other when detected
    if (mfile and not ifile) or (ifile and not mfile):
        det_m, det_i = detect_malcolm_and_image_files()
        if (ifile and not mfile) and det_m:
            # Offer tarball; if accepted, ensure we have an install path
            if parsed_args.non_interactive:
                mfile = det_m[0]
            else:
                if _ask_yes_no(
                    ui_impl,
                    f"Found Malcolm tarball: {os.path.basename(det_m[0])}. Use this file?",
                    default=True,
                ):
                    mfile = det_m[0]
                    if not parsed_args.non_interactive:
                        install_path = _ask_string(
                            ui_impl,
                            f"Enter installation path for Malcolm [{install_path}]",
                            install_path,
                        )
        if (mfile and not ifile) and det_i:
            # Offer image file after path has been chosen
            if not parsed_args.non_interactive and _ask_yes_no(
                ui_impl,
                f"Found container images file: {os.path.basename(det_i[0])}. Use this file?",
                default=True,
            ):
                ifile = det_i[0]
    return mfile, ifile, install_path


def _handle_cli_artifacts(
    parsed_args,
    ui_impl,
    malcolm_config,
    control_flow,
    orig_path: str,
    cli_m: Optional[str],
    cli_i: Optional[str],
) -> Tuple[bool, Optional[str], Optional[str], Optional[str], Optional[str]]:
    mfile, ifile = _validate_cli_paths(cli_m, cli_i)

    # Front-load install path prompt first when a tarball is involved.
    install_path = _default_install_path(orig_path)
    if mfile and not parsed_args.non_interactive:
        install_path = _ask_string(
            ui_impl,
            f"Enter installation path for Malcolm [{install_path}]",
            install_path,
        )

    mfile, ifile, install_path = _maybe_offer_complementary_artifacts(
        mfile, ifile, parsed_args, ui_impl, install_path
    )

    # validate and handle
    mfile, ifile = _validate_artifacts_or_exit(mfile, ifile, bool(cli_i))
    handled, cfg_override = _perform_artifact_handling(
        mfile, ifile, install_path, control_flow, malcolm_config, ui_impl, orig_path
    )
    return handled, mfile, ifile, install_path, cfg_override


def _handle_detected_artifacts(
    parsed_args,
    ui_impl,
    malcolm_config,
    control_flow,
    orig_path: str,
) -> Tuple[bool, Optional[str], Optional[str], Optional[str], Optional[str]]:
    # 2) Neither provided via CLI: detect and prompt early
    mal_files, img_files = _detect_files_or_exit()

    # Offer tarball first; if accepted, offer images once; then fast-path
    if mal_files:
        if parsed_args.non_interactive or _ask_yes_no(
            ui_impl,
            f"Found Malcolm tarball: {os.path.basename(mal_files[0])}. Use this file?",
            default=True,
        ):
            mfile = mal_files[0]
            install_path = _default_install_path(orig_path)
            if not parsed_args.non_interactive:
                install_path = _ask_string(
                    ui_impl,
                    f"Enter installation path for Malcolm [{install_path}]",
                    install_path,
                )

            ifile = None
            if img_files and parsed_args.non_interactive:
                ifile = img_files[0]
            elif img_files and not parsed_args.non_interactive:
                if _ask_yes_no(
                    ui_impl,
                    f"Found container images file: {os.path.basename(img_files[0])}. Use this file?",
                    default=True,
                ):
                    ifile = img_files[0]

            # validate and handle after all UI prompts are complete
            mfile, ifile = _validate_artifacts_or_exit(mfile, ifile, False)
            handled, cfg_override = _perform_artifact_handling(
                mfile, ifile, install_path, control_flow, malcolm_config, ui_impl, orig_path
            )
            return handled, mfile, ifile, install_path, cfg_override

    # If user declined tarball (or none found) but an images archive is present,
    # offer to load images independently.
    if img_files:
        if parsed_args.non_interactive or _ask_yes_no(
            ui_impl,
            f"Found container images file: {os.path.basename(img_files[0])}. Use this file?",
            default=True,
        ):
            mfile = None
            ifile = img_files[0]
            # validate and handle (no install path needed for images-only)
            _, ifile = _validate_artifacts_or_exit(mfile, ifile, False)
            handled, cfg_override = _perform_artifact_handling(
                mfile, ifile, orig_path, control_flow, malcolm_config, ui_impl, orig_path
            )
            return handled, mfile, ifile, None, cfg_override

    # Nothing handled
    return False, None, None, None, None
