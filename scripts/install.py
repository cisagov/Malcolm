#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

import argparse
import json
import os
import pathlib
import secrets
import sys
import types

from dataclasses import dataclass
from typing import Optional

# Dynamically create a module named "scripts" which points to this directory
if "scripts" not in sys.modules:
    scripts_module = types.ModuleType("scripts")
    scripts_module.__path__ = [os.path.dirname(os.path.abspath(__file__))]
    sys.modules["scripts"] = scripts_module

sys.dont_write_bytecode = True

from scripts.malcolm_constants import (
    DEFAULT_INDEX_DIR,
    DEFAULT_INDEX_SNAPSHOT_DIR,
    DEFAULT_SURICATA_LOG_DIR,
    DEFAULT_ZEEK_LOG_DIR,
    MALCOLM_DB_DIR,
    MALCOLM_LOGS_DIR,
    MALCOLM_PCAP_DIR,
    OrchestrationFramework,
    PresentationMode,
    SettingsFileFormat,
)

from scripts.malcolm_common import (
    ClearScreen,
    DetermineYamlFileFormat,
    DoDynamicImport,
    DotEnvDynamic,
    DumpYaml,
    get_default_config_dir,
    get_platform_name,
    KubernetesDynamic,
    LoadYamlOrJson,
    MalcolmCfgRunOnceFile,
    RequestsDynamic,
    SYSTEM_INFO,
    UserInterfaceMode,
    YAMLDynamic,
)
from scripts.malcolm_utils import (
    base64_decode_files_to_dir,
    base64_encode_files_in_dir,
    ChownRecursive,
    get_main_script_dir,
    LoadFileIfJson,
    touch,
)

from scripts.installer.args.basic_args import add_basic_args
from scripts.installer.args.orchestration_args import add_orchestration_args
from scripts.installer.args.environment_args import add_environment_args
from scripts.installer.args.extras_args import add_extras_args
from scripts.installer.args.install_files_args import add_install_files_args, remove_malcolm_file_args
from scripts.installer.args.presentation_args import add_presentation_args

from scripts.installer.configs.constants.installation_item_keys import *
from scripts.installer.configs.constants.configuration_item_keys import *
from scripts.installer.configs.constants.enums import InstallerResult, ControlFlow, ContainerRuntime
from scripts.installer.configs.constants.constants import MAIN_MENU_KEYS

from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.installer.core.install_context import InstallContext
from scripts.installer.core.validation import (
    validate_required,
    format_validation_summary,
)

from scripts.installer.platforms import get_platform_installer

from scripts.installer.ui.dui.dui_installer_ui import DialogInstallerUI
from scripts.installer.ui.shared.splash_screen import splash_screen
from scripts.installer.ui.tui.tui_installer_ui import TUIInstallerUI

from scripts.installer.utils.artifact_utils import decide_and_handle_artifacts
from scripts.installer.utils.env_file_utils import apply_extra_env_settings
from scripts.installer.utils.logger_utils import InstallerLogger
from scripts.installer.utils.settings_file_handler import SettingsFileHandler


###################################################################################################
SCRIPT_NAME = os.path.basename(__file__)
SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))
ORIG_PATH = os.getcwd()


@dataclass
class InstallerDirs:
    input_dir: str
    output_dir: str


def build_arg_parser(parser: argparse.ArgumentParser) -> None:
    """Add arguments specific to the installer itself"""
    add_basic_args(parser)
    add_presentation_args(parser)
    add_orchestration_args(parser)
    add_environment_args(parser)
    add_install_files_args(parser)
    add_extras_args(parser)
    # add_test_args(parser)


def create_ui_implementation(presentation_mode: PresentationMode, ui_mode_flag: UserInterfaceMode):
    """Create the appropriate UI implementation based on interface mode.

    Args:
        presentation_mode: tui/gui/silent
        ui_mode_flag: User interface mode flag (dialog or input)

    Returns:
        Appropriate UI implementation instance
    """

    if presentation_mode == PresentationMode.MODE_TUI:
        return TUIInstallerUI(ui_mode_flag)
    elif presentation_mode == PresentationMode.MODE_DUI:
        return DialogInstallerUI(UserInterfaceMode.InteractionDialog)
    elif presentation_mode == PresentationMode.MODE_GUI:
        raise NotImplementedError("GUI is not implemented yet")
    elif presentation_mode == PresentationMode.MODE_SILENT:
        return None
    else:
        raise Exception("Unsupported interface mode")


def handle_artifact_path_preseed_file(malcolm_config):

    # special case for the Malcolm ISO-installed environment: if the file .os-disk-config-defaults was created by
    # the environment (os-disk-config.py) we'll use those as defaults for the artifact storage directories
    disk_format_info_file = os.path.join(
        os.path.realpath(os.path.join(get_main_script_dir(), "..")), ".os-disk-config-defaults"
    )
    if malcolm_config and os.path.isfile(disk_format_info_file):
        try:
            InstallerLogger.debug("here")
            with open(disk_format_info_file) as f:
                disk_format_info = LoadFileIfJson(f)

            if disk_format_info := {k: v for k, v in disk_format_info.items() if os.path.isdir(v)}:

                dirs_to_create = {
                    MALCOLM_DB_DIR: [DEFAULT_INDEX_DIR, DEFAULT_INDEX_SNAPSHOT_DIR],
                    MALCOLM_LOGS_DIR: [DEFAULT_ZEEK_LOG_DIR, DEFAULT_SURICATA_LOG_DIR],
                }
                for base_key, subdirs in dirs_to_create.items():
                    if base_path := disk_format_info.get(base_key):
                        for subdir in subdirs:
                            pathlib.Path(os.path.join(base_path, subdir)).mkdir(parents=False, exist_ok=True)

                paths_to_check = [
                    (MALCOLM_DB_DIR, DEFAULT_INDEX_DIR, KEY_CONFIG_ITEM_INDEX_DIR, True),
                    (MALCOLM_DB_DIR, DEFAULT_INDEX_SNAPSHOT_DIR, KEY_CONFIG_ITEM_INDEX_SNAPSHOT_DIR, True),
                    (MALCOLM_PCAP_DIR, None, KEY_CONFIG_ITEM_PCAP_DIR, False),
                    (MALCOLM_LOGS_DIR, DEFAULT_SURICATA_LOG_DIR, KEY_CONFIG_ITEM_SURICATA_LOG_DIR, True),
                    (MALCOLM_LOGS_DIR, DEFAULT_ZEEK_LOG_DIR, KEY_CONFIG_ITEM_ZEEK_LOG_DIR, True),
                ]
                default_storage = True
                for base_key, subdir, config_key, path_must_exist in paths_to_check:
                    if base_path := disk_format_info.get(base_key):
                        path = os.path.realpath(os.path.join(base_path, subdir) if subdir else base_path)
                        if (not path_must_exist) or os.path.isdir(path):
                            malcolm_config.apply_default(config_key, path, ignore_errors=True)
                            default_storage = False
                            InstallerLogger.debug(
                                f"Set default for {config_key} to {path} from {os.path.basename(disk_format_info_file)}"
                            )
                if not default_storage:
                    malcolm_config.apply_default(
                        KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS, default_storage, ignore_errors=True
                    )

        except Exception as e:
            InstallerLogger.error(f"Failed to set path defaults from {os.path.basename(disk_format_info_file)}: {e}")


def handle_config_directories_tui_mode(
    malcolm_config,
    ui_impl,
    non_interactive,
    use_defaults,
    load_existing_env: Optional[bool],
    malcolm_orchestration_file: Optional[bool],
    importing_configs: bool,
    dirs: InstallerDirs,
    no_write: bool = False,
):
    """Handle config directory validation and setup for TUI/DUI/Silent modes.

    Args:
        malcolm_config: MalcolmConfig instance
        ui_impl: UI implementation
        non_interactive: Whether in non-interactive mode
        use_defaults: Whether to use default values

    Returns:
        bool: True if successful, False otherwise
    """
    # Note: MalcolmConfig initialization earlier will fail fast if templates are missing.

    orch_mode = malcolm_config.get_value(KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE)

    # 2. Ensure output config directory exists
    if not os.path.exists(dirs.output_dir):
        if non_interactive:
            if no_write:
                InstallerLogger.error(
                    f"Dry run: output config directory not found and cannot prompt in non-interactive mode: {dirs.output_dir}"
                )
                return False
            try:
                os.makedirs(dirs.output_dir, exist_ok=True)
                InstallerLogger.info(f"Created output config directory: {dirs.output_dir}") # fmt: skip
            except Exception as e:
                InstallerLogger.error(f"Failed to create output config directory: {e}")
                return False
        else:
            # interactive: prompt, even in dry-run
            prompt = f"Provided output config directory:\n{dirs.output_dir} does not exist\nDo you want to create it?"
            if ui_impl and ui_impl.ask_yes_no(prompt, default=True):
                if no_write:
                    InstallerLogger.info(f"Dry run: would create output config directory: {dirs.output_dir}")
                else:
                    try:
                        os.makedirs(dirs.output_dir, exist_ok=True)
                        InstallerLogger.info(f"Created output config directory: {dirs.output_dir}") # fmt: skip
                    except Exception as e:
                        InstallerLogger.error(f"Failed to create output config directory: {e}") # fmt: skip
                        return False
            else:
                InstallerLogger.info("Output directory creation declined by user.") # fmt: skip
                return False

    # 3. If not using defaults, decide whether to load existing .env files
    if not use_defaults:
        env_files = []
        try:
            if os.path.isdir(dirs.input_dir):
                env_files = [f for f in os.listdir(dirs.input_dir) if f.endswith(".env")]
        except Exception as e:
            InstallerLogger.warning(f"Could not scan for .env files in {dirs.input_dir}: {e}")

        if env_files:
            decision = load_existing_env
            if (decision is None) and (not importing_configs):
                if non_interactive:
                    decision = True
                elif ui_impl:
                    decision = ui_impl.ask_yes_no(
                        f"Found existing .env files in: {dirs.input_dir}\nDo you want to load settings from these files?",
                        default=True,
                    )
            if decision:
                try:
                    malcolm_config.load_from_env_files(dirs.input_dir)
                    InstallerLogger.info(f"Loaded existing .env files from: {dirs.input_dir}") # fmt: skip
                except Exception as e:
                    InstallerLogger.error(f"Failed to load .env files from {dirs.input_dir}: {e}") # fmt: skip
                    return False
                if orch_mode != OrchestrationFramework.KUBERNETES:
                    try:
                        loaded_from_orch_filename = malcolm_config.load_from_orchestration_file(
                            dirs.input_dir, malcolm_orchestration_file
                        )
                        InstallerLogger.info(f"Loaded config from from: {loaded_from_orch_filename}") # fmt: skip
                    except Exception as e:
                        InstallerLogger.error(f"Failed to load config from compose file: {e}") # fmt: skip
                        return False

            else:
                InstallerLogger.info("Skipping load of existing .env files.") # fmt: skip
        else:
            if importing_configs:
                # When importing a settings file, skip any prompts to ingest config/
                InstallerLogger.info(
                    "Skipping config directory ingestion prompts because --import-malcolm-config-file was provided."
                )
            else:
                # no .env files in provided input directory
                default_dir = get_default_config_dir()

                # If we're already using the default config directory and it has no .env files,
                # this is likely a first-time install - skip the prompt and continue
                if os.path.abspath(dirs.input_dir) == os.path.abspath(default_dir):
                    InstallerLogger.info(
                        "No existing .env files found in config directory. Proceeding with fresh configuration."
                    )
                    # Continue with the install - no need to prompt
                else:
                    InstallerLogger.warning(f"No .env files detected in provided input directory: {dirs.input_dir}")
                    if non_interactive:
                        InstallerLogger.warning(
                            "Non-interactive mode: cannot prompt to use default config/. Proceeding with fresh configuration."
                        )

                    # interactive: offer to use the default config/ directory instead
                    elif ui_impl and ui_impl.ask_yes_no(
                        f"No .env files found in {dirs.input_dir}.\nCheck default config directory instead?\n({default_dir})",
                        default=True,
                    ):
                        dirs.input_dir = default_dir
                        try:
                            fallback_env_files = [f for f in os.listdir(dirs.input_dir) if f.endswith(".env")]
                        except Exception:
                            fallback_env_files = []

                        if fallback_env_files:
                            decision = load_existing_env
                            if (decision is None) and (not importing_configs):
                                decision = ui_impl.ask_yes_no(
                                    f"Found .env files in: {dirs.input_dir}\nDo you want to load settings from these files?",
                                    default=True,
                                )
                            if decision:
                                try:
                                    malcolm_config.load_from_env_files(dirs.input_dir)
                                    InstallerLogger.info(f"Loaded existing .env files from: {dirs.input_dir}")
                                except Exception as e:
                                    InstallerLogger.error(f"Failed to load .env files from {dirs.input_dir}: {e}")
                                    return False
                                if orch_mode != OrchestrationFramework.KUBERNETES:
                                    try:
                                        loaded_from_orch_filename = malcolm_config.load_from_orchestration_file(
                                            dirs.input_dir, malcolm_orchestration_file
                                        )
                                        InstallerLogger.info(f"Loaded config from from: {loaded_from_orch_filename}") # fmt: skip
                                    except Exception as e:
                                        InstallerLogger.error(f"Failed to load config from compose file: {e}") # fmt: skip
                                        return False
                            else:
                                InstallerLogger.info("Skipping load of existing .env files.")
                        else:
                            InstallerLogger.info(
                                "No existing .env files found in config directory. Proceeding with fresh configuration."
                            )

                    else:
                        InstallerLogger.info(
                            "No existing .env files found in config directory. Proceeding with fresh configuration."
                        )

    handle_artifact_path_preseed_file(malcolm_config)

    return True


def handle_config_directories_gui_mode(malcolm_config):
    """Handle config directory setup for GUI mode.

    This function is called during the GUI "Get Started" flow and should:
    1. Present directory pickers for input and output directories
    2. Validate the selected directories
    3. Ask about loading existing .env files

    Args:
        malcolm_config: MalcolmConfig instance

    Returns:
        tuple: (success, config_dir_input, config_dir_output) or (False, None, None)
    """
    # TODO: This will be implemented when GUI is added
    # For now, this is a placeholder that shows the intended interface
    raise NotImplementedError("GUI config directory handling not yet implemented")

    # Future GUI implementation would:
    # 1. Show directory picker for input dir (with .env.example files)
    # 2. Validate input dir has required .env.example files
    # 3. Show directory picker for output dir
    # 4. Ask about creating output dir if it doesn't exist
    # 5. Ask about loading existing .env files if they exist in input dir
    # 6. Return (True, input_dir, output_dir) on success


def handle_config_export(parsed_args, malcolm_config, install_context):
    """Handle configuration export if --export-config was specified.

    Args:
        parsed_args: Parsed command line arguments
        malcolm_config: MalcolmConfig instance with user's choices
        install_context: InstallContext instance with installation choices
    """
    result = None
    if parsed_args.exportMalcolmConfigFile is not None:
        try:
            settings_handler = SettingsFileHandler(malcolm_config, install_context)

            # determine output filename
            if parsed_args.exportMalcolmConfigFile == "":
                # generate default filename with timestamp
                export_filename = settings_handler.generate_default_export_filename("json")
                InstallerLogger.info(f"No filename specified, using default: {export_filename}")
            else:
                export_filename = parsed_args.exportMalcolmConfigFile

            # save settings to file
            settings_handler.save_to_file(
                export_filename, config_only=parsed_args.configOnly or install_context.config_only
            )
            result = export_filename
            InstallerLogger.info(f"Configuration exported successfully to: {export_filename}")

        except Exception as e:
            InstallerLogger.error(
                f"Failed to export settings to {export_filename if 'export_filename' in locals() else 'config file'}: {e}"
            )

    return result


def determine_presentation_mode(parsed_args: argparse.Namespace) -> PresentationMode:
    """Determine which interface mode to use based on args and environment."""

    # def check_for_gui_environment():
    #     if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
    #         try:
    #             import customtkinter
    #         except ImportError:
    #             pass  # GUI not available
    #     return

    def check_for_python_dialog():
        if not DoDynamicImport("dialog", "pythondialog"):
            return None
        try:
            # Verify the dialog binary is usable by initializing MainDialog
            from scripts.malcolm_common import DialogInit, MainDialog

            DialogInit()
            if MainDialog is None:
                return None

            return PresentationMode.MODE_DUI
        except Exception:
            return None  # DUI library not available

    # Check for explicit mode selection first
    if parsed_args.non_interactive:
        return PresentationMode.MODE_SILENT
    if parsed_args.tui:
        return PresentationMode.MODE_TUI
    dui_mode = check_for_python_dialog()
    if parsed_args.dui and dui_mode:
        return dui_mode
    if parsed_args.gui:
        raise NotImplementedError("GUI mode is not yet supported")

    # if nothing was explicitly requested attempt python dialogs else default to TUI
    if dui_mode:
        return dui_mode

    return PresentationMode.MODE_TUI


def main():
    dirs = InstallerDirs(input_dir=get_default_config_dir(), output_dir=get_default_config_dir())

    try:
        parser = argparse.ArgumentParser(description="Malcolm Installer", conflict_handler="resolve")
        build_arg_parser(parser)
    except Exception as e:
        InstallerLogger.error(f"Failed to build installer specific argument parser: {e}")  # fmt: skip
        sys.exit(1)

    try:
        parsed_args = parser.parse_args()
        if os.path.islink(os.path.join(SCRIPT_PATH, SCRIPT_NAME)) and SCRIPT_NAME.startswith('configure'):
            parsed_args.configOnly = True
    except Exception as e:
        InstallerLogger.error(f"Failed to parse arguments: {e}")
        sys.exit(1)

    try:
        if (not parsed_args.configOnly) and (SYSTEM_INFO.get('platform_name') == "linux") and (os.geteuid() != 0):
            InstallerLogger.error("This installer must be run as root.") # fmt: skip
            sys.exit(1)
    except Exception as e:
        InstallerLogger.error(f"Failed to check if running as root: {e}")
        sys.exit(1)

    # Optional splash screen (interactive only)
    try:
        if (
            not parsed_args.skipSplash
            and not parsed_args.non_interactive
            and sys.stdin.isatty()
            and sys.stdout.isatty()
        ):
            splash_screen()
    except Exception:
        # Splash is non-critical; ignore failures
        pass

    # determine control flow (dry-run, config-only, or full install)
    control_flow = None
    if parsed_args.dryRun:
        control_flow = ControlFlow.DRYRUN
    elif parsed_args.configOnly:
        control_flow = ControlFlow.CONFIG
    else:
        control_flow = ControlFlow.INSTALL

    exported_config_file = None
    imported_config_file = None

    if parsed_args.quiet:
        InstallerLogger.set_console_output(False)

    # Set up debug logging if --debug flag was provided
    if parsed_args.debug:
        InstallerLogger.set_debug_enabled(True)

    try:
        presentation_mode = determine_presentation_mode(parsed_args)
        ui_mode_flag = (
            UserInterfaceMode.InteractionDialog
            if presentation_mode == PresentationMode.MODE_DUI
            else UserInterfaceMode.InteractionInput
        )
        # buffer logs when using terminal UIs and not logging to file
        if presentation_mode in (
            PresentationMode.MODE_DUI,
            PresentationMode.MODE_TUI,
        ) and (parsed_args.logToFile is None):
            InstallerLogger.set_buffered_console(True)
        InstallerLogger.start("Determining Presentation Format") # fmt: skip
        InstallerLogger.end("Determining Presentation Format", InstallerResult.SUCCESS, f"Using {presentation_mode.name}") # fmt: skip
    except Exception as e:
        InstallerLogger.error(f"Failed to determine interface mode: {e}") # fmt: skip
        sys.exit(1)

    InstallerLogger.debug(f"Arguments: {sys.argv[1:]}")
    InstallerLogger.debug(f"Arguments: {parsed_args}")

    # handle log file setup if --log-to-file was specified
    if parsed_args.logToFile is not None:
        if parsed_args.logToFile == "":
            log_filename = InstallerLogger.generate_timestamped_filename()
            InstallerLogger.info(f"No log filename specified, using: {log_filename}") # fmt: skip
        else:
            log_filename = parsed_args.logToFile

        InstallerLogger.set_log_file(log_filename)
        InstallerLogger.info(f"Logging to file: {log_filename}") # fmt: skip

    for pkgLoop in (1, 2):
        requests_imported = RequestsDynamic(
            debug=parsed_args.debug, forceInteraction=(not parsed_args.non_interactive), silent=(pkgLoop == 1)
        )
        yaml_imported = YAMLDynamic(
            debug=parsed_args.debug, forceInteraction=(not parsed_args.non_interactive), silent=(pkgLoop == 1)
        )
        dotenv_imported = DotEnvDynamic(
            debug=parsed_args.debug, forceInteraction=(not parsed_args.non_interactive), silent=(pkgLoop == 1)
        )
        InstallerLogger.debug(f"Imported requests: {requests_imported}")
        InstallerLogger.debug(f"Imported yaml: {yaml_imported}")
        InstallerLogger.debug(f"Imported dotenv: {dotenv_imported}")
        if (not all((requests_imported, yaml_imported, dotenv_imported))) and (pkgLoop != 1):
            InstallerLogger.error("Missing one or more required libraries")
            sys.exit(1)

    try:
        # note: this will fail if the .env.example files are not present in config/ as we use them to map the .env files
        InstallerLogger.start("Initializing Internal Malcolm Configs") # fmt: skip
        malcolm_config = MalcolmConfig()
        InstallerLogger.end("Initializing Internal Malcolm Configs", InstallerResult.SUCCESS) # fmt: skip
    except Exception as e:
        import traceback

        InstallerLogger.error(f"Failed to initialize MalcolmConfig: {e}") # fmt: skip
        InstallerLogger.debug(f"Error: {e}\n{traceback.format_exc()}") # fmt: skip
        sys.exit(1)

    # create UI implementation early so we can use it for all user interactions
    try:
        InstallerLogger.start("Initializing User Interface") # fmt: skip
        ui_impl = create_ui_implementation(presentation_mode, ui_mode_flag)
        InstallerLogger.end("Initializing User Interface", InstallerResult.SUCCESS, "UI initialized") # fmt: skip
    except Exception as e:
        InstallerLogger.error(f"Failed to create UI implementation: {e}") # fmt: skip
        sys.exit(1)

    try:
        # detect orchestration mode from provided configuration file, if any
        detected_orch_mode = None
        if parsed_args.malcolmOrchestrationFile:
            if not os.path.isfile(parsed_args.malcolmOrchestrationFile):
                InstallerLogger.error(f"Configuration file not found: {parsed_args.malcolmOrchestrationFile}")
                sys.exit(2)
            detected_orch_mode = DetermineYamlFileFormat(parsed_args.malcolmOrchestrationFile)
            if detected_orch_mode not in (
                OrchestrationFramework.DOCKER_COMPOSE,
                OrchestrationFramework.KUBERNETES,
            ):
                InstallerLogger.error(
                    f"{parsed_args.malcolmOrchestrationFile} must be a docker-compose or kubeconfig YAML file"
                )
                sys.exit(2)

            # if kubernetes, validate kubeconfig via python client (parity with legacy)
            if detected_orch_mode == OrchestrationFramework.KUBERNETES:
                kube_success = False
                try:
                    if kube_imported := KubernetesDynamic(silent=False):
                        InstallerLogger.info(f"Imported kubernetes: {kube_imported}")
                        kube_imported.config.load_kube_config(parsed_args.malcolmOrchestrationFile)
                        kube_success = True
                except Exception as e:
                    InstallerLogger.error(f"Failed loading kubeconfig {parsed_args.malcolmOrchestrationFile}: {e}")
                    sys.exit(2)
                if not kube_success:
                    if kube_imported:
                        InstallerLogger.error(f"Failed loading kubeconfig {parsed_args.malcolmOrchestrationFile}")
                    else:
                        InstallerLogger.error(
                            f"The official Python client library for kubernetes is required for for {detected_orch_mode} mode"
                        )
                    sys.exit(2)

        # prefer detected mode; otherwise use existing config default
        orchestration_mode = (
            detected_orch_mode
            or malcolm_config.get_value(KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE)
            or OrchestrationFramework.DOCKER_COMPOSE
        )

        # legacy parity: when Kubernetes is selected, a kubeconfig file is required via -f/--configure-file
        if (orchestration_mode == OrchestrationFramework.KUBERNETES) and (
            (not parsed_args.malcolmOrchestrationFile) or (not os.path.isfile(parsed_args.malcolmOrchestrationFile))
        ):
            InstallerLogger.error(
                f"{orchestration_mode} requires specifying a kubeconfig file via -f/--configure-file/--compose-file/--kube-file"
            )
            sys.exit(2)

        # persist orchestration mode into config for downstream transforms
        try:
            malcolm_config.set_value(KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE, orchestration_mode)
            if orchestration_mode == OrchestrationFramework.KUBERNETES:
                malcolm_config.set_value(KEY_CONFIG_ITEM_RUNTIME_BIN, ContainerRuntime.KUBERNETES.value)
        except Exception as e:
            InstallerLogger.error(f"Failed to persist orchestration settings: {e}")

        InstallerLogger.start("Spawning Platform-specific Installer")
        platform_installer = get_platform_installer(
            orchestration_mode,
            ui_impl,
            parsed_args.debug,
            control_flow,
        )
        InstallerLogger.end(
            "Spawning Platform-specific Installer",
            InstallerResult.SUCCESS,
            f"Detected {SYSTEM_INFO['platform_name']}",
        )
    except Exception as e:
        InstallerLogger.error(f"Failed to determine platform: {e}")
        sys.exit(1)

    try:
        install_context = InstallContext()
        install_context.initialize_for_platform(get_platform_name())
        # reflect CLI-driven control flow in context for UI summaries
        try:
            install_context.config_only = control_flow.is_config_only()
            if install_context.config_only:
                install_context.set_value(KEY_INSTALLATION_ITEM_AUTO_TWEAKS, False)
        except Exception:
            pass
    except Exception as e:
        InstallerLogger.error(f"Failed to spawn installation context: {e}")
        sys.exit(1)

    # Early artifact resolution/handling (fast-path); exits early when handled
    handled, sel_m, sel_i, sel_path, cfg_override = decide_and_handle_artifacts(
        parsed_args, ui_impl, malcolm_config, control_flow, ORIG_PATH
    )
    if handled:
        if sel_path and os.path.isdir(sel_path):
            new_installer_py = os.path.join(sel_path, os.path.join('scripts', SCRIPT_NAME))
            if os.path.isfile(new_installer_py):
                # exec the new installer and abandon this one (replace the process)
                cleaned_argv = remove_malcolm_file_args(sys.argv[1:])
                # send something bogus that doesn't exist for --malcolm-file so we don't loop
                cleaned_argv.extend(["--malcolm-file", secrets.token_hex(32)])
                os.execv(sys.executable, [sys.executable, new_installer_py, *cleaned_argv])
        return

    # capture any selections for downstream logic if needed (artifact handler performs work)
    # selections are no longer used downstream; configuration directory override is respected
    if cfg_override:
        dirs.output_dir = cfg_override

    # Artifact handling delegated to decide_and_handle_artifacts above; continue setup.

    # handle settings file import if specified
    if parsed_args.importMalcolmConfigFile:
        try:
            settings_handler = SettingsFileHandler(malcolm_config, install_context)
            missing_items = settings_handler.load_from_file(
                parsed_args.importMalcolmConfigFile, config_only=parsed_args.configOnly or install_context.config_only
            )
            imported_config_file = parsed_args.importMalcolmConfigFile
            InstallerLogger.info(f"Successfully loaded settings from: {parsed_args.importMalcolmConfigFile}") # fmt: skip

            # report missing configuration items that used defaults
            if missing_items["missing_configuration"]:
                InstallerLogger.warning(f"Found {len(missing_items['missing_configuration'])} configuration items missing from settings file, using defaults") # fmt: skip
                if parsed_args.debug:
                    for item_key in missing_items["missing_configuration"]:
                        item = malcolm_config.get_item(item_key)
                        InstallerLogger.debug(f'  {item_key}: using default "{str(item.get_value())}"')

            # report missing installation items that used defaults
            if missing_items["missing_installation"]:
                InstallerLogger.warning(f"Found {len(missing_items['missing_installation'])} installation items missing from settings file, using defaults") # fmt: skip
                if parsed_args.debug:
                    for item_key in missing_items["missing_installation"]:
                        InstallerLogger.debug(f'  {item_key}: using default "{str(item.get_value())}"')

        except Exception as e:
            InstallerLogger.error(f"Failed to load settings from {parsed_args.importMalcolmConfigFile}: {e}") # fmt: skip
            sys.exit(1)

    # check if input environment directory was specified via --environment-dir-input
    if parsed_args.configDirInput:
        dirs.input_dir = parsed_args.configDirInput
    else:
        dirs.input_dir = get_default_config_dir()

    # check if output environment directory was specified via --environment-dir or -e
    if parsed_args.configDir:
        dirs.output_dir = parsed_args.configDir
    else:
        dirs.output_dir = get_default_config_dir()

    # Handle config directory setup based on presentation mode
    if presentation_mode == PresentationMode.MODE_GUI:
        # GUI mode: config directory handling will be done during GUI flow
        try:
            success, input_dir, output_dir = handle_config_directories_gui_mode(malcolm_config)
            if not success:
                InstallerLogger.error("Config directory setup cancelled by user.")
                sys.exit(1)
            dirs.input_dir = input_dir
            dirs.output_dir = output_dir
        except NotImplementedError:
            InstallerLogger.error("GUI mode is not yet implemented.")
            sys.exit(1)
    else:
        # TUI/DUI/Silent modes: use traditional flow
        if not handle_config_directories_tui_mode(
            malcolm_config,
            ui_impl,
            parsed_args.non_interactive,
            parsed_args.use_defaults,
            parsed_args.loadExistingEnv,
            parsed_args.malcolmOrchestrationFile,
            parsed_args.importMalcolmConfigFile is not None,
            dirs,
            no_write=control_flow.is_dry_run(),
        ):
            InstallerLogger.error("Failed to setup configuration directories.")
            sys.exit(1)

    # Configuration gathering user input (conditional on presentation mode)
    config_success = True
    if presentation_mode in [PresentationMode.MODE_TUI, PresentationMode.MODE_DUI]:
        # Interactive mode: Run configuration menu
        config_success = ui_impl.run_configuration_menu(
            malcolm_config,
            install_context,
            main_menu_keys=MAIN_MENU_KEYS,
            debug_mode=parsed_args.debug,
        )

        if not config_success:
            InstallerLogger.end("INSTALLER", InstallerResult.SKIPPED, "Configuration cancelled by user.")  # fmt: skip
            return

        # Minimal dependency-aware validation loop before proceeding
        while True:
            issues = validate_required(malcolm_config)
            if not issues:
                break

            # Provide a single dialog combining the summary and the prompt
            summary = format_validation_summary(issues)
            combined_message = (
                f"{summary}\n\nReturn to configuration to fix these now?"
                if summary
                else "Missing required settings. Return to configuration to fix these now?"
            )
            fix_now = ui_impl.ask_yes_no(combined_message, default=True, force_interaction=True)
            if not fix_now:
                InstallerLogger.end(
                    "INSTALLER",
                    InstallerResult.SKIPPED,
                    "Missing required settings; installation cancelled by user.",
                )
                return

            # Re-run the configuration menu; allow user to adjust values
            config_success = ui_impl.run_configuration_menu(
                malcolm_config,
                install_context,
                main_menu_keys=MAIN_MENU_KEYS,
                debug_mode=parsed_args.debug,
            )
            if not config_success:
                InstallerLogger.end(
                    "INSTALLER",
                    InstallerResult.SKIPPED,
                    "Configuration cancelled by user.",
                )
                return

        if not install_context.config_only:
            # attach runtime source so InstallContext can compute visibility without UI logic
            try:
                install_context.attach_runtime_source(malcolm_config)
            except Exception:
                pass
            # attach platform probes for docker/compose availability
            try:
                install_context.attach_platform_probe(platform_installer)
            except Exception:
                pass
            install_context = ui_impl.gather_install_options(platform_installer, malcolm_config, install_context)

        if install_context is None:
            InstallerLogger.info("Installation cancelled by user.") # fmt: skip
            return
    elif presentation_mode == PresentationMode.MODE_GUI:
        InstallerLogger.error("GUI mode is not yet implemented.") # fmt: skip
        return
    else:
        # Silent/non-interactive: enforce validation before proceeding
        issues = validate_required(malcolm_config)
        if issues:
            summary = format_validation_summary(issues)
            InstallerLogger.error(summary)
            sys.exit(2)

    # Export configuration to malcolm config file if requested (no writes to env yet)
    if parsed_args.exportMalcolmConfigFile is not None:
        exported_config_file = handle_config_export(parsed_args, malcolm_config, install_context)

    # Final summary and confirmation (interactive modes only)
    if presentation_mode in [PresentationMode.MODE_TUI, PresentationMode.MODE_DUI]:
        try:
            proceed = ui_impl.show_final_configuration_summary(
                malcolm_config,
                dirs.output_dir,
                install_context,
                is_dry_run=control_flow.is_dry_run(),
            )
        except Exception as e:
            InstallerLogger.error(f"Failed to render final configuration summary: {e}")
            proceed = False
        # clear terminal after closing the confirmation to present a clean post-UI view
        ClearScreen()

        if not proceed:
            InstallerLogger.end(
                "INSTALLER",
                InstallerResult.SKIPPED,
                "Installation cancelled by user at confirmation.",
            )
            return

    # Generate configuration files after configuration steps complete
    InstallerLogger.info(
        control_flow.would(f"save configuration to {dirs.output_dir}")
        if not control_flow.should_write_files()
        else f"Configuration will be saved to {dirs.output_dir}"
    )
    if control_flow.should_write_files():

        # if we imported a configuration from a .json/.yaml file earlier, before we write out
        # the final .env files here we want to write the contents of the "raw" file stored in
        # that import file to the output directory. this way we also preserve the user's other
        # settings/comments that are in the .env files but are not known by MalcolmConfig
        if os.path.isfile(str(imported_config_file)):
            imported_config_data, imported_config_format = LoadYamlOrJson(imported_config_file)
            if isinstance(imported_config_data, dict) and ("raw" in imported_config_data):
                if raw_envs := imported_config_data.get("raw", {}):
                    base64_decode_files_to_dir(raw_envs, dirs.output_dir)
                    InstallerLogger.info(
                        f"Raw configuration from {imported_config_file} ({len(raw_envs)} files) restored to {dirs.output_dir}"
                    )

        malcolm_config.generate_env_files(dirs.output_dir)

        # Apply any arbitrary extra .env settings requested via CLI (handle after file generation)
        try:
            if getattr(parsed_args, "extraSettings", None):
                apply_extra_env_settings(
                    dirs.output_dir,
                    parsed_args.extraSettings,
                    malcolm_config.get_env_mapper(),
                )
        except Exception as e:
            InstallerLogger.warning(f"Failed to apply --extra settings: {e}")

        # Adjust ownership if running as root
        puid = malcolm_config.get_value(KEY_CONFIG_ITEM_PROCESS_USER_ID) or SYSTEM_INFO.get(
            "recommended_nonroot_uid", 0
        )
        pgid = malcolm_config.get_value(KEY_CONFIG_ITEM_PROCESS_GROUP_ID) or SYSTEM_INFO.get(
            "recommended_nonroot_gid", 0
        )
        if needs_config_chown := (
            (SYSTEM_INFO.get('platform_name') in ("linux", "macos")) and (os.getuid() == 0) and puid and pgid
        ):
            InstallerLogger.info(f"Setting ownership of {dirs.output_dir} directory to {puid}:{pgid}...")
            try:
                ChownRecursive(dirs.output_dir, puid, pgid)
            except Exception as e:
                InstallerLogger.warning(f"Could not change ownership of config directory: {e}")

        try:
            touch(MalcolmCfgRunOnceFile)
            if needs_config_chown:
                os.chown(MalcolmCfgRunOnceFile, int(puid), int(pgid))
        except Exception:
            pass

        # if we exported configuration to a file, update the "raw" section containing the base64-encoded
        # .env files with these new/fresher .env files we just wrote out
        if os.path.isfile(str(exported_config_file)):
            exported_config_data, exported_config_format = LoadYamlOrJson(exported_config_file)
            if (
                isinstance(exported_config_data, dict)
                and ("raw" in exported_config_data)
                and exported_config_format != SettingsFileFormat.UNKNOWN
            ):
                exported_config_data["raw"] = base64_encode_files_in_dir(dirs.output_dir, "*.env")
                if exported_config_data.get("raw"):
                    if exported_config_format == SettingsFileFormat.YAML:
                        DumpYaml(exported_config_data, exported_config_file)
                    else:
                        with open(exported_config_file, "w") as f:
                            json.dump(exported_config_data, f, indent=2, sort_keys=True)
                    InstallerLogger.info(
                        f"Updated raw configuration in: {exported_config_file} ({exported_config_format.value})"
                    )

    # Run installation steps (dry-run skips body; config-only skips install steps)
    if control_flow.is_dry_run():
        InstallerLogger.info("Dry run: executing no-op pass over installation steps for reporting only") # fmt: skip

    install_ok = platform_installer.run_installation(
        malcolm_config,
        dirs.output_dir,
        install_context,
        parsed_args.malcolmOrchestrationFile,
    )

    # report final status according to control flow
    if control_flow.is_dry_run():
        InstallerLogger.end(
            "INSTALLER",
            InstallerResult.SKIPPED,
            "Dry run successful: skipped actual installation",
        )
    elif control_flow.is_config_only():
        InstallerLogger.end(
            "INSTALLER",
            InstallerResult.SKIPPED,
            "Configuration-only: installation steps skipped",
        )
    else:
        if install_ok:
            InstallerLogger.end(
                "INSTALLER",
                InstallerResult.SUCCESS,
                "Installation completed successfully",
            )
        else:
            InstallerLogger.end("INSTALLER", InstallerResult.FAILURE, "Installation failed")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        InstallerLogger.error("Installation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        import traceback

        tb = traceback.format_exc()
        # Include traceback in error log so failures are actionable without --debug
        InstallerLogger.error(f"Error executing main(): {e}\n{tb}")
        InstallerLogger.debug(f"Main debug: {e}\n{tb}")
        sys.exit(1)
    finally:
        # final safety flush for terminal UIs so buffered logs are emitted even on early returns
        try:
            InstallerLogger.flush_buffer_to_console()
            InstallerLogger.set_buffered_console(False)
        except Exception:
            pass
