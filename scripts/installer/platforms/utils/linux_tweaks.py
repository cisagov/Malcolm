#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Linux-specific tweak aggregator used by the platform installer.

This module provides Linux-specific tweak implementations and a single
apply_all() entry point used by LinuxInstaller.
"""

from typing import Any, List

from scripts.installer.configs.constants.enums import InstallerResult
from scripts.installer.utils.tweak_utils import should_apply_tweak


def _normalize_status(result: Any) -> InstallerResult:
    status = result
    if isinstance(result, tuple):
        status = result[0]
    if isinstance(status, bool):
        return InstallerResult.SUCCESS if status else InstallerResult.FAILURE
    if isinstance(status, InstallerResult):
        return status
    return InstallerResult.SUCCESS


def apply_sysctl(malcolm_config, config_dir: str, platform, ctx, logger) -> tuple[InstallerResult, str]:
    """Apply sysctl tweaks (ported from steps/tweak_sysctl.py)."""
    import os, tempfile

    SYSCTL_SETTINGS = [
        ("fs.file-max", "2097152", "immediate"),
        ("fs.inotify.max_user_watches", "131072", "immediate"),
        ("fs.inotify.max_queued_events", "131072", "immediate"),
        ("fs.inotify.max_user_instances", "512", "immediate"),
        ("vm.max_map_count", "262144", "config_file"),
        ("vm.swappiness", "1", "config_file"),
        ("vm.dirty_background_ratio", "40", "config_file"),
        ("vm.dirty_ratio", "80", "config_file"),
        ("net.core.somaxconn", "65535", "immediate"),
        ("net.ipv4.tcp_retries2", "5", "config_file"),
    ]

    def _write_to_sysctl_conf(setting_name: str, setting_value: str) -> bool:
        path = "/etc/sysctl.conf"
        prefix = f"{setting_name}="
        try:
            existing_lines = []
            if os.path.exists(path):
                err, out = platform.run_process(["cat", path], privileged=True)
                if err == 0 and out:
                    existing_lines = [line + ("\n" if not line.endswith("\n") else "") for line in out]
            desired_line = f"{prefix}{setting_value}\n"
            for line in existing_lines:
                if line.strip().startswith(prefix) and line.strip() == desired_line.strip():
                    return True
            filtered = [ln for ln in existing_lines if not ln.strip().startswith(prefix)]
            filtered.append(desired_line)
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
                tmp.writelines(filtered)
                tmp_path = tmp.name
            err, _ = platform.run_process(["cp", tmp_path, path], privileged=True)
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
            return err == 0
        except Exception:
            return False

    # Allow either granular sysctl_* toggles or a coarse "sysctl" group toggle
    group_selected = should_apply_tweak(ctx, "sysctl")
    any_selected = group_selected or any(
        should_apply_tweak(
            ctx, f"sysctl_{name.split('.')[-1].replace('-', '_')}"
        )
        for name, _, _ in SYSCTL_SETTINGS
    )
    if not any_selected:
        return InstallerResult.SKIPPED, "No sysctl tweaks selected"

    successes = 0
    for setting_name, setting_value, method in SYSCTL_SETTINGS:
        if not (
            group_selected
            or should_apply_tweak(
                ctx, f"sysctl_{setting_name.split('.')[-1].replace('-', '_')}"
            )
        ):
            successes += 1
            continue
        if platform.is_dry_run():
            logger.info(f"Dry run: would set {setting_name}={setting_value} ({method})")
            successes += 1
            continue
        ok = False
        if method == "immediate":
            err, _ = platform.run_process(["sysctl", "-w", f"{setting_name}={setting_value}"], privileged=True)
            ok = err == 0
        else:
            ok = _write_to_sysctl_conf(setting_name, setting_value)
        if ok:
            logger.info(f"Applied {setting_name}={setting_value}")
            successes += 1
        else:
            logger.error(f"Failed to apply {setting_name}={setting_value}")

    if platform.is_dry_run():
        return InstallerResult.SKIPPED, "Dry run: would apply sysctl settings"
    return (
        (InstallerResult.SUCCESS, "Applied sysctl settings") if successes == len(SYSCTL_SETTINGS) else (InstallerResult.FAILURE, "Some sysctl settings failed")
    )


def apply_security_limits(malcolm_config, config_dir: str, platform, ctx, logger) -> tuple[InstallerResult, str]:
    if not should_apply_tweak(ctx, "security_limits"):
        return InstallerResult.SKIPPED, "Security limits not selected"
    import os, tempfile
    SECURITY_LIMITS_DIR = "/etc/security/limits.d"
    MALCOLM_LIMITS_FILE = "99-malcolm.conf"
    limits_file = os.path.join(SECURITY_LIMITS_DIR, MALCOLM_LIMITS_FILE)
    lines = [
        "# Malcolm security limits",
        "* soft nofile 65535",
        "* hard nofile 65535",
        "* soft memlock unlimited",
        "* hard memlock unlimited",
        "* soft nproc 262144",
        "* hard nproc 524288",
        "",
    ]
    content = "\n".join(lines) + "\n"
    try:
        if platform.is_dry_run():
            logger.info(f"Dry run: would write {limits_file} with security limits")
            return InstallerResult.SKIPPED, "Security limits skipped (dry run)"
        err, out = platform.run_process(["mkdir", "-p", SECURITY_LIMITS_DIR], privileged=True)
        if err != 0:
            logger.error(f"Failed to create {SECURITY_LIMITS_DIR}: {' '.join(out)}")
            return InstallerResult.FAILURE, "Could not create limits dir"
        if os.path.exists(limits_file):
            err, out = platform.run_process(["cat", limits_file], privileged=True)
            if err == 0 and "\n".join(out).strip() == content.strip():
                logger.info(f"Security limits already configured in {limits_file}")
                return InstallerResult.SUCCESS, "Already configured"
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        err, out = platform.run_process(["cp", tmp_path, limits_file], privileged=True)
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        if err == 0:
            logger.info(f"Applied security limits to {limits_file}")
            return InstallerResult.SUCCESS, "Security limits applied"
        logger.error(f"Failed to apply security limits: {' '.join(out)}")
        return InstallerResult.FAILURE, "Security limits failed"
    except Exception as e:
        logger.error(f"Error applying security limits: {e}")
        return InstallerResult.FAILURE, "Security limits exception"


def apply_systemd_limits(malcolm_config, config_dir: str, platform, ctx, logger) -> tuple[InstallerResult, str]:
    if not should_apply_tweak(ctx, "systemd_limits"):
        return InstallerResult.SKIPPED, "Systemd limits not selected"
    import os, tempfile
    SYSTEMD_LIMITS_DIR = "/etc/systemd/system.conf.d"
    MALCOLM_SYSTEMD_FILE = "99-malcolm.conf"
    distro = getattr(platform, "distro", "").lower()
    codename = getattr(platform, "codename", "").lower()
    if distro not in ["centos"] and codename not in ["core"]:
        logger.info(f"Skipping systemd limits (not applicable for {distro} {codename})")
        return InstallerResult.SKIPPED, "Not applicable"
    limits_file = os.path.join(SYSTEMD_LIMITS_DIR, MALCOLM_SYSTEMD_FILE)
    content = """[Manager]
DefaultLimitNOFILE=65535:65535
DefaultLimitMEMLOCK=infinity
"""
    try:
        if platform.is_dry_run():
            logger.info(f"Dry run: would write {limits_file} with systemd limits")
            return InstallerResult.SKIPPED, "Systemd limits skipped (dry run)"
        if os.path.exists(limits_file):
            err, out = platform.run_process(["cat", limits_file], privileged=True)
            if err == 0 and "\n".join(out).strip() == content.strip():
                logger.info(f"Systemd limits already configured in {limits_file}")
                return InstallerResult.SUCCESS, "Already configured"
        err, out = platform.run_process(["mkdir", "-p", SYSTEMD_LIMITS_DIR], privileged=True)
        if err != 0:
            logger.error(f"Failed to create {SYSTEMD_LIMITS_DIR}: {' '.join(out)}")
            return InstallerResult.FAILURE, "Could not create dir"
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        err, out = platform.run_process(["cp", tmp_path, limits_file], privileged=True)
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        if err == 0:
            logger.info(f"Applied systemd limits to {limits_file}")
            return InstallerResult.SUCCESS, "Systemd limits applied"
        logger.error(f"Failed to apply systemd limits: {' '.join(out)}")
        return InstallerResult.FAILURE, "Systemd limits failed"
    except Exception as e:
        logger.error(f"Error applying systemd limits: {e}")
        return InstallerResult.FAILURE, "Systemd limits exception"


def apply_grub_cgroup(malcolm_config, config_dir: str, platform, ctx, logger) -> tuple[InstallerResult, str]:
    if not should_apply_tweak(ctx, "grub_cgroup"):
        logger.info("GRUB cgroup tweak not selected, skipping.")
        return InstallerResult.SKIPPED, "GRUB cgroup not selected"
    import os
    GRUB_DEFAULT_PATH = "/etc/default/grub"
    try:
        if platform.is_dry_run():
            logger.info("Dry run: would update GRUB cgroup parameters in /etc/default/grub")
            return InstallerResult.SKIPPED, "GRUB cgroup skipped (dry run)"
        if not os.path.exists(GRUB_DEFAULT_PATH):
            logger.info(f"GRUB config file {GRUB_DEFAULT_PATH} does not exist, skipping.")
            return InstallerResult.SKIPPED, "GRUB file missing"
        has_cgroup = False
        with open(GRUB_DEFAULT_PATH, "r") as f:
            has_cgroup = any("cgroup" in line.lower() for line in f.readlines())
        if has_cgroup:
            logger.info(f"GRUB cgroup parameters already configured in {GRUB_DEFAULT_PATH}.")
            return InstallerResult.SKIPPED, "Already configured"
        cgroup_params = "cgroup_enable=memory swapaccount=1 cgroup.memory=nokmem"
        err, out = platform.run_process([
            "bash",
            "-c",
            f"sed -i 's/^GRUB_CMDLINE_LINUX=\\\"/{cgroup_params} /' {GRUB_DEFAULT_PATH}",
        ], privileged=True)
        if err != 0:
            logger.error(f"Failed to modify GRUB configuration: {' '.join(out)}")
            return InstallerResult.FAILURE, "GRUB update failed"
        return InstallerResult.SUCCESS, "GRUB cgroup applied"
    except Exception as e:
        logger.error(f"Error applying GRUB cgroup configuration: {e}")
        return InstallerResult.FAILURE, "GRUB cgroup exception"


def apply_network_interface(malcolm_config, config_dir: str, platform, ctx, logger) -> tuple[InstallerResult, str]:
    from scripts.installer.configs.constants.configuration_item_keys import (
        KEY_CONFIG_ITEM_TWEAK_IFACE, KEY_CONFIG_ITEM_PCAP_IFACE,
    )
    if not should_apply_tweak(ctx, "network_interface"):
        logger.info("Network interface tweak not selected, skipping.")
        return InstallerResult.SKIPPED, "Network interface not selected"
    tweak_iface = malcolm_config.get_value(KEY_CONFIG_ITEM_TWEAK_IFACE)
    pcap_iface = malcolm_config.get_value(KEY_CONFIG_ITEM_PCAP_IFACE)
    if not tweak_iface or not pcap_iface:
        logger.info("Network interface tweaks not configured, skipping.")
        return InstallerResult.SKIPPED, "Network interface not configured"
    ethtool_commands: List[List[str]] = [
        ["ethtool", "-G", pcap_iface, "rx", "4096"],
        ["ethtool", "-G", pcap_iface, "tx", "4096"],
        ["ethtool", "-K", pcap_iface, "rx", "off"],
        ["ethtool", "-K", pcap_iface, "tx", "off"],
        ["ethtool", "-K", pcap_iface, "sg", "off"],
        ["ethtool", "-K", pcap_iface, "tso", "off"],
        ["ethtool", "-K", pcap_iface, "ufo", "off"],
        ["ethtool", "-K", pcap_iface, "gso", "off"],
        ["ethtool", "-K", pcap_iface, "gro", "off"],
        ["ethtool", "-K", pcap_iface, "lro", "off"],
        ["ethtool", "-K", pcap_iface, "rxvlan", "off"],
        ["ethtool", "-K", pcap_iface, "txvlan", "off"],
        ["ethtool", "-K", pcap_iface, "ntuple", "off"],
        ["ethtool", "-K", pcap_iface, "rxhash", "off"],
    ]
    all_ok = True
    for cmd in ethtool_commands:
        if platform.is_dry_run():
            logger.info(f"Dry run: would run: {' '.join(cmd)}")
            continue
        try:
            err, out = platform.run_process(cmd, privileged=True)
            if err == 0:
                logger.info(f"Success: {' '.join(cmd)}")
            else:
                logger.error(f"Failed: {' '.join(cmd)} (exit code {err})")
                if out:
                    logger.error(f"    Output: {' '.join(out)}")
                all_ok = False
        except Exception as e:
            logger.error(f"Error: {' '.join(cmd)} ({e})")
            all_ok = False
    if platform.is_dry_run():
        return InstallerResult.SKIPPED, "Network interface tweaks skipped (dry run)"
    return (InstallerResult.SUCCESS, "Network interface tweaks applied") if all_ok else (InstallerResult.FAILURE, "Network interface tweaks failed")


def apply_all(malcolm_config, config_dir: str, platform, ctx, logger) -> tuple[InstallerResult, str]:
    if not platform.should_run_install_steps():
        return InstallerResult.SKIPPED, "Tweaks skipped (non-install control flow)"
    for func in (apply_sysctl, apply_security_limits, apply_systemd_limits, apply_grub_cgroup, apply_network_interface):
        status, _ = func(malcolm_config, config_dir, platform, ctx, logger)
        if status == InstallerResult.FAILURE:
            return status, "A Linux tweak failed"
    return InstallerResult.SUCCESS, "All Linux tweaks applied"


def _sentence_case(s: str) -> str:
    if not s:
        return s
    return s[0].upper() + s[1:]


def get_sysctl_tweak_definitions() -> list[dict]:
    """Return metadata for sysctl tweaks for UI/tests."""
    settings = [
        ("fs.file-max", "maximum file handles"),
        ("fs.inotify.max_user_watches", "file monitoring limits"),
        ("fs.inotify.max_queued_events", "inotify event queue size"),
        ("fs.inotify.max_user_instances", "inotify user instances"),
        ("vm.max_map_count", "memory map count"),
        ("vm.swappiness", "swappiness (prefer memory over swap)"),
        ("vm.dirty_background_ratio", "dirty background ratio"),
        ("vm.dirty_ratio", "dirty ratio"),
        ("net.core.somaxconn", "socket connection limits"),
        ("net.ipv4.tcp_retries2", "TCP retries"),
    ]
    defs: list[dict] = []
    for name, desc in settings:
        tweak_id = f"sysctl_{name.split('.')[-1].replace('-', '_')}"
        defs.append({
            "id": tweak_id,
            "description": f"Adjust {desc} ({name})",
            "label": f"{_sentence_case(desc)} ({name})",
            "value_display": "",
        })
    return defs


def get_tweak_definitions() -> list[dict]:
    """Return all Linux tweak definitions for UI selection.

    Includes granular sysctl settings and top-level toggles for other tweaks.
    """
    defs = []
    # Granular sysctl toggles
    defs.extend(get_sysctl_tweak_definitions())
    # Other coarse-grained tweaks
    defs.append(
        {
            "id": "security_limits",
            "label": "Security Limits (/etc/security/limits.d)",
            "description": "Apply recommended process/file descriptor limits",
        }
    )
    defs.append(
        {
            "id": "systemd_limits",
            "label": "Systemd Limits (/etc/systemd/system.conf.d)",
            "description": "Apply recommended systemd Manager limits",
        }
    )
    defs.append(
        {
            "id": "grub_cgroup",
            "label": "GRUB Cgroup Parameters",
            "description": "Enable memory cgroup and swapaccount in GRUB",
        }
    )
    defs.append(
        {
            "id": "network_interface",
            "label": "Optimize Capture Network Interface",
            "description": "Apply ethtool queue and offload settings",
        }
    )
    # Coarse group switch for all sysctl values (optional UI shortcut)
    defs.append(
        {
            "id": "sysctl",
            "label": "Enable All Sysctl Settings",
            "description": "Toggle all kernel sysctl tweaks at once",
        }
    )
    return defs
