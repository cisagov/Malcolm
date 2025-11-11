#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Linux-specific tweak aggregator used by the platform installer.

This module provides Linux-specific tweak implementations and a single
apply_all() entry point used by LinuxInstaller.
"""

from typing import Any

from scripts.installer.configs.constants.enums import InstallerResult
from scripts.installer.utils.tweak_utils import should_apply_tweak
from scripts.malcolm_utils import file_contents, which
from scripts.malcolm_common import SYSTEM_INFO

from scripts.installer.utils import InstallerLogger as logger


def _normalize_status(result: Any) -> InstallerResult:
    status = result
    if isinstance(result, tuple):
        status = result[0]
    if isinstance(status, bool):
        return InstallerResult.SUCCESS if status else InstallerResult.FAILURE
    if isinstance(status, InstallerResult):
        return status
    return InstallerResult.SUCCESS


def apply_sysctl(malcolm_config, config_dir: str, platform, ctx) -> tuple[InstallerResult, str]:
    """Apply sysctl tweaks"""
    import os
    import tempfile

    SYSCTL_SETTINGS = [
        ("fs.file-max", "2097152"),
        ("fs.inotify.max_user_watches", "131072"),
        ("fs.inotify.max_queued_events", "131072"),
        ("fs.inotify.max_user_instances", "512"),
        ("vm.max_map_count", "262144"),
        ("vm.swappiness", "1"),
        ("vm.dirty_background_ratio", "40"),
        ("vm.dirty_ratio", "80"),
        ("vm.overcommit_memory", "1"),
        ("net.core.somaxconn", "65535"),
        ("net.ipv4.tcp_retries2", "5"),
    ]

    def _write_to_sysctl_conf(setting_name: str, setting_value: str) -> bool:
        path = '/etc/sysctl.d/99-sysctl-performance.conf' if os.path.isdir('/etc/sysctl.d') else '/etc/sysctl.conf'
        prefix = f"{setting_name}="
        err = 1
        try:
            if os.path.exists(path) and (existing_contents := file_contents(path)):
                existing_lines = [
                    ln.strip() for ln in (existing_contents.splitlines() if isinstance(existing_contents, str) else [])
                ]
            else:
                existing_lines = []
            desired_line = f"{prefix}{setting_value}"
            if desired_line in existing_lines:
                return True
            filtered = [ln for ln in existing_lines if not ln.startswith(prefix)]
            filtered.append(desired_line)
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
                tmp.writelines(f'{s}\n' for s in filtered)
                tmp_path = tmp.name
            err, out = platform.run_process(["cp", tmp_path, path])
            if err == 0 and os.path.exists(path):
                try:
                    os.chmod(path, 0o644)
                except (PermissionError, OSError) as e:
                    logger.warning(f"Could not chmod {path}: {e}")
            try:
                os.unlink(tmp_path)
            except OSError as e:
                logger.warning(f"Failed to cleanup temp file {tmp_path}: {e}")
            return err == 0
        except Exception as e:
            logger.error(f"Error applying sysctl settings: {e}")
            return False

    # Allow either granular sysctl_* toggles or a coarse "sysctl" group toggle
    group_selected = should_apply_tweak(ctx, "sysctl")
    any_selected = group_selected or any(
        should_apply_tweak(ctx, f"sysctl_{name.split('.')[-1].replace('-', '_')}") for name, _ in SYSCTL_SETTINGS
    )
    if not any_selected:
        return InstallerResult.SKIPPED, "No sysctl tweaks selected"

    successes = 0
    for setting_name, setting_value in SYSCTL_SETTINGS:
        if not (group_selected or should_apply_tweak(ctx, f"sysctl_{setting_name.split('.')[-1].replace('-', '_')}")):
            successes += 1
            continue
        if platform.is_dry_run():
            logger.info(f"Dry run: would set {setting_name}={setting_value}")
            successes += 1
            continue
        if _write_to_sysctl_conf(setting_name, setting_value):
            logger.info(f"Applied {setting_name}={setting_value}")
            successes += 1
        else:
            logger.error(f"Failed to apply {setting_name}={setting_value}")

    if platform.is_dry_run():
        return InstallerResult.SKIPPED, "Dry run: would apply sysctl settings"
    return (
        (InstallerResult.SUCCESS, "Applied sysctl settings")
        if successes == len(SYSCTL_SETTINGS)
        else (InstallerResult.FAILURE, "Some sysctl settings failed")
    )


def apply_security_limits(malcolm_config, config_dir: str, platform, ctx) -> tuple[InstallerResult, str]:
    if not should_apply_tweak(ctx, "security_limits"):
        return InstallerResult.SKIPPED, "Security limits not selected"
    import os
    import tempfile
    import pathlib

    SECURITY_LIMITS_DIR = "/etc/security/limits.d"
    MALCOLM_LIMITS_FILE = "99-malcolm.conf"
    limits_file = os.path.join(SECURITY_LIMITS_DIR, MALCOLM_LIMITS_FILE)
    desired_content = [
        "# Malcolm file and memory limits",
        "* soft nofile 65535",
        "* hard nofile 65535",
        "* soft memlock unlimited",
        "* hard memlock unlimited",
        "* soft nproc 262144",
        "* hard nproc 524288",
    ]
    try:
        if platform.is_dry_run():
            logger.info(f"Dry run: would write {limits_file} with security limits")
            return InstallerResult.SKIPPED, "Security limits skipped (dry run)"
        try:
            pathlib.Path(SECURITY_LIMITS_DIR).mkdir(parents=True, exist_ok=True)
        except PermissionError:
            logger.warning(f"No permission to create {SECURITY_LIMITS_DIR}, skipping security limits")
            return InstallerResult.SKIPPED, "Security limits skipped (no permissions)"
        try:
            if os.path.exists(limits_file) and (existing_contents := file_contents(limits_file)):
                existing_lines = [
                    ln.strip()
                    for ln in (existing_contents.splitlines() if isinstance(existing_contents, str) else [])
                    if ln.strip()
                ]
            else:
                existing_lines = []
        except (PermissionError, OSError):
            logger.warning(f"Cannot read {limits_file}, assuming it needs to be written")
            existing_lines = []
        if existing_lines == desired_content:
            logger.info(f"Security limits already configured in {limits_file}")
            return InstallerResult.SUCCESS, "Already configured"
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.writelines(f'{s}\n' for s in desired_content)
            tmp_path = tmp.name
        err, out = platform.run_process(["cp", tmp_path, limits_file])
        if err == 0:
            if os.path.exists(limits_file):
                try:
                    os.chmod(limits_file, 0o644)
                except (PermissionError, OSError) as e:
                    logger.warning(f"Could not chmod {limits_file}: {e}")
            try:
                os.unlink(tmp_path)
            except OSError as e:
                logger.warning(f"Failed to cleanup temp file {tmp_path}: {e}")
            logger.info(f"Applied security limits to {limits_file}")
            return InstallerResult.SUCCESS, "Security limits applied"
        try:
            os.unlink(tmp_path)
        except OSError as e:
            logger.warning(f"Failed to cleanup temp file {tmp_path}: {e}")
        logger.error(f"Failed to apply security limits: {' '.join(out)}")
        return InstallerResult.FAILURE, "Security limits failed"
    except Exception as e:
        logger.error(f"Error applying security limits: {e}")
        return InstallerResult.FAILURE, "Security limits exception"


def apply_systemd_limits(
    malcolm_config,
    config_dir: str,
    platform,
    ctx,
) -> tuple[InstallerResult, str]:
    if not should_apply_tweak(ctx, "systemd_limits"):
        return InstallerResult.SKIPPED, "Systemd limits not selected"
    import os
    import tempfile
    import pathlib

    SYSTEMD_LIMITS_DIR = "/etc/systemd/system.conf.d"
    MALCOLM_SYSTEMD_FILE = "99-malcolm.conf"

    if SYSTEM_INFO["distro"] not in ["centos"] and SYSTEM_INFO["codename"] not in ["core"]:
        logger.info(f"Skipping systemd limits (not applicable for {SYSTEM_INFO['distro']} {SYSTEM_INFO['distro']})")
        return InstallerResult.SKIPPED, "Not applicable"
    limits_file = os.path.join(SYSTEMD_LIMITS_DIR, MALCOLM_SYSTEMD_FILE)
    desired_content = [
        "[Manager]" "DefaultLimitNOFILE=65535:65535",
        "DefaultLimitMEMLOCK=infinity",
    ]
    try:
        if platform.is_dry_run():
            logger.info(f"Dry run: would write {limits_file} with systemd limits")
            return InstallerResult.SKIPPED, "Systemd limits skipped (dry run)"

        try:
            if os.path.exists(limits_file) and (existing_contents := file_contents(limits_file)):
                existing_lines = [
                    ln.strip()
                    for ln in (existing_contents.splitlines() if isinstance(existing_contents, str) else [])
                    if ln.strip()
                ]
            else:
                existing_lines = []
        except (PermissionError, OSError):
            logger.warning(f"Cannot read {limits_file}, assuming it needs to be written")
            existing_lines = []
        if existing_lines == desired_content:
            logger.info(f"Systemd limits already configured in {limits_file}")
            return InstallerResult.SUCCESS, "Already configured"
        try:
            pathlib.Path(SYSTEMD_LIMITS_DIR).mkdir(parents=True, exist_ok=True)
        except PermissionError:
            logger.warning(f"No permission to create {SYSTEMD_LIMITS_DIR}, skipping systemd limits")
            return InstallerResult.SKIPPED, "Systemd limits skipped (no permissions)"
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.writelines(f'{s}\n' for s in desired_content)
            tmp_path = tmp.name
        err, out = platform.run_process(["cp", tmp_path, limits_file])
        if err == 0:
            if os.path.exists(limits_file):
                try:
                    os.chmod(limits_file, 0o644)
                except (PermissionError, OSError) as e:
                    logger.warning(f"Could not chmod {limits_file}: {e}")
            try:
                os.unlink(tmp_path)
            except OSError as e:
                logger.warning(f"Failed to cleanup temp file {tmp_path}: {e}")
            logger.info(f"Applied systemd limits to {limits_file}")
            return InstallerResult.SUCCESS, "Systemd limits applied"
        try:
            os.unlink(tmp_path)
        except OSError as e:
            logger.warning(f"Failed to cleanup temp file {tmp_path}: {e}")
        logger.error(f"Failed to apply systemd limits: {' '.join(out)}")
        return InstallerResult.FAILURE, "Systemd limits failed"
    except Exception as e:
        logger.error(f"Error applying systemd limits: {e}")
        return InstallerResult.FAILURE, "Systemd limits exception"


def apply_grub_cgroup(
    malcolm_config,
    config_dir: str,
    platform,
    ctx,
    grub_file="/etc/default/grub",
    params=None,
    backup=True,
) -> tuple[InstallerResult, str]:
    if not should_apply_tweak(ctx, "grub_cgroup"):
        logger.info("cgroup kernel parameters tweak not selected, skipping.")
        return InstallerResult.SKIPPED, "cgroup kernel parameters not selected"
    import os
    import re

    if params is None:
        params = [
            "systemd.unified_cgroup_hierarchy=1",
            "cgroup_enable=memory",
            "swapaccount=1",
            "cgroup.memory=nokmem",
        ]

    def system_uses_systemd_boot():
        # systemd-boot uses kernelstub, installs loader entries in /boot/loader/entries, and (usually) has /boot/loader/loader.conf
        return (
            which("kernelstub") and os.path.isdir("/boot/loader/entries") and os.path.isfile("/boot/loader/loader.conf")
        )

    def system_uses_bls():
        # BLS-enabled if both grubby and /boot/loader/entries exist, and not disabled in /etc/default/grub
        if which("grubby") and os.path.isdir("/boot/loader/entries"):
            try:
                with open("/etc/default/grub", "r") as f:
                    for line in f:
                        if "GRUB_ENABLE_BLSCFG" in line and "false" in line.lower():
                            return False
                return True
            except FileNotFoundError:
                return True
        return False

    def modify_line(varname, content):
        match = re.search(rf'^{varname}="(.*?)"', content, re.MULTILINE)
        if match:
            existing = match.group(1).split()
            new_params = [p for p in params if p not in existing]
            if not new_params:
                return content, []
            updated = " ".join(existing + new_params)
            content = content[: match.start()] + f'{varname}="{updated}"' + content[match.end() :]
            return content, new_params
        else:
            # variable not found, append at the end
            line = f'\n{varname}="' + " ".join(params) + '"\n'
            return content + line, params

    try:
        if platform.is_dry_run():
            logger.info(f"Dry run: would update cgroup kernel parameters parameters in {grub_file}")
            return InstallerResult.SKIPPED, "cgroup kernel parameters skipped (dry run)"

        if system_uses_systemd_boot():
            err, out = platform.run_process(['kernelstub', '-a', ' '.join(params)])
            if err == 0:
                logger.info("Applied new kernel parameters with kernelstub")
                return InstallerResult.SUCCESS, "cgroup kernel parameters applied"
            logger.error(f"Failed to apply kernel parameters with kernelstub: {' '.join(out)}")
            return InstallerResult.FAILURE, "cgroup kernel parameters failed"

        elif system_uses_bls():
            err, out = platform.run_process(['grubby', '--update-kernel=ALL', f"--args={' '.join(params)}"])
            if err == 0:
                logger.info("Applied new kernel parameters with grubby")
                return InstallerResult.SUCCESS, "cgroup kernel parameters applied"
            logger.error(f"Failed to apply kernel parameters with grubby: {' '.join(out)}")
            return InstallerResult.FAILURE, "cgroup kernel parameters failed"

        elif os.path.exists(grub_file):
            with open(grub_file, "r", encoding="utf-8") as f:
                orig_content = f.read()

            # prefer GRUB_CMDLINE_LINUX, fallback to DEFAULT
            if re.search(r"^GRUB_CMDLINE_LINUX=", orig_content, re.MULTILINE):
                varname = "GRUB_CMDLINE_LINUX"
            elif re.search(r"^GRUB_CMDLINE_LINUX_DEFAULT=", orig_content, re.MULTILINE):
                varname = "GRUB_CMDLINE_LINUX_DEFAULT"
            else:
                varname = "GRUB_CMDLINE_LINUX"
            new_content, added = modify_line(varname, orig_content)

            if added:
                if backup:
                    try:
                        with open(f"{grub_file}.bak", "w", encoding="utf-8") as f:
                            f.write(orig_content)
                    except OSError as e:
                        logger.warning(f"Failed to create backup of {grub_file}: {e}")
                with open(grub_file, "w", encoding="utf-8") as f:
                    f.write(new_content)
                try:
                    os.chmod(grub_file, 0o644)
                except Exception:
                    pass

                if which('update-grub'):
                    err, out = platform.run_process(['update-grub'])
                elif which('update-grub2'):
                    err, out = platform.run_process(['update-grub2'])
                elif which('grub2-mkconfig') and os.path.isfile('/boot/grub2/grub.cfg'):
                    err, out = platform.run_process(['grub2-mkconfig', '-o', '/boot/grub2/grub.cfg'])
                else:
                    err = 0
                    logger.warning(
                        f"{grub_file} has been modified, consult your distribution's documentation generate new grub config file"
                    )

                if err == 0:
                    logger.info(f"Applied new kernel parameters to {grub_file}")
                    return InstallerResult.SUCCESS, "cgroup kernel parameters applied"
                logger.error(f"Failed to apply cgroup kernel parameters to {grub_file}: {' '.join(out)}")
                return InstallerResult.FAILURE, "cgroup kernel parameters failed"
            else:
                logger.info(f"no changes needed in GRUB config file {grub_file}")
                return InstallerResult.SKIPPED, "no changes needed in GRUB config file"

        else:
            logger.info(f"GRUB config file {grub_file} does not exist, skipping")
            return InstallerResult.SKIPPED, "GRUB config file missing"

    except Exception as e:
        logger.error(f"Error applying cgroup kernel parameters: {e}")
        return InstallerResult.FAILURE, "cgroup kernel parameters exception"


def apply_all(malcolm_config, config_dir: str, platform, ctx) -> tuple[InstallerResult, str]:
    if not platform.should_run_install_steps():
        return InstallerResult.SKIPPED, "Tweaks skipped (non-install control flow)"
    for func in (apply_sysctl, apply_security_limits, apply_systemd_limits, apply_grub_cgroup):
        status, _ = func(malcolm_config, config_dir, platform, ctx)
        if status == InstallerResult.FAILURE:
            return status, "A Linux tweak failed"
    return InstallerResult.SUCCESS, "All Linux tweaks applied"
