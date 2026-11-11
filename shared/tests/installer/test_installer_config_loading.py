#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""Regression tests for how the installer loads, settles, and saves configuration.

Covers cisagov/Malcolm#949 and #1110: loading a configuration (existing .env files, the compose
file, an imported settings file) must give back the values that were saved, the dependency rules
must not rewrite loaded values while the load is happening, and an invalid configuration must
never be written.
"""

import json
import os
import sys
from pathlib import Path
from unittest import mock

import pytest

if (_repo_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.append(_repo_root)

from scripts.malcolm_common import SYSTEM_INFO
from scripts.malcolm_constants import PROFILE_HEDGEHOG, PROFILE_MALCOLM, OrchestrationFramework
from scripts.installer.utils.logger_utils import InstallerLogger

InstallerLogger.set_console_output(False)

from scripts.installer.configs.constants.configuration_item_keys import *
from scripts.installer.configs.constants.constants import LOCAL_LOGSTASH_HOST
from scripts.installer.core.dependencies import DEPENDENCY_CONFIG, RuleKind, ValueRule
from scripts.installer.core.dependency_manager import DependencyManager
from scripts.installer.core.install_context import InstallContext
from scripts.installer.core.malcolm_config import LoadSource, MalcolmConfig
from scripts.installer.core.validation import validate_required
from scripts.installer.utils.env_file_utils import restore_raw_env_files, write_configuration_files
from scripts.installer.utils.exceptions import FileOperationError
from scripts.installer.utils.settings_file_handler import SETTINGS_FILE_FORMAT_VERSION, SettingsFileHandler
from scripts.malcolm_utils import base64_encode_files_in_dir


# ---------------------------------------------------------------------------------------------
# helpers


def hedgehog_without_arkime() -> MalcolmConfig:
    """A Hedgehog capturing live traffic with Zeek/Suricata but no PCAP capture method (valid)."""
    cfg = MalcolmConfig()
    cfg.set_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE, PROFILE_HEDGEHOG)
    cfg.set_value(KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST, "192.168.122.118")
    cfg.set_value(KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC, True)
    cfg.set_value(KEY_CONFIG_ITEM_PCAP_IFACE, ["eth1"])
    cfg.set_value(KEY_CONFIG_ITEM_LIVE_ARKIME, False)
    cfg.set_value(KEY_CONFIG_ITEM_PCAP_NETSNIFF, False)
    cfg.set_value(KEY_CONFIG_ITEM_PCAP_TCPDUMP, False)
    return cfg


def env_round_trip(cfg: MalcolmConfig, env_dir) -> MalcolmConfig:
    """Write cfg to .env files in env_dir and load them into a fresh MalcolmConfig."""
    os.makedirs(env_dir, exist_ok=True)
    cfg.generate_env_files(str(env_dir))
    loaded = MalcolmConfig()
    loaded.load_from_env_files(str(env_dir))
    return loaded


def export_settings(cfg: MalcolmConfig, path) -> dict:
    """Export cfg to a settings file (including the raw .env backup if cfg was written) and return it."""
    SettingsFileHandler(cfg, InstallContext()).save_to_file(str(path), config_only=True)
    with open(path) as f:
        return json.load(f)


def import_settings(path, cfg=None) -> MalcolmConfig:
    cfg = cfg or MalcolmConfig()
    SettingsFileHandler(cfg, InstallContext()).load_from_file(str(path), config_only=True)
    return cfg


def write_compose(path, x_malcolm: dict) -> str:
    """Write a minimal compose file with the given x-malcolm extension."""
    lines = ["services:", "  logstash:", "    image: logstash", "x-malcolm:"]
    for section, values in x_malcolm.items():
        lines.append(f"  {section}:")
        for k, v in values.items():
            lines.append(f"    {k}: {json.dumps(v)}")
    Path(path).write_text("\n".join(lines) + "\n")
    return str(path)


# ---------------------------------------------------------------------------------------------
# #949: loading gives back what was saved


def test_env_round_trip_keeps_arkime_off_on_hedgehog(tmp_path):
    loaded = env_round_trip(hedgehog_without_arkime(), tmp_path)
    assert loaded.get_value(KEY_CONFIG_ITEM_LIVE_ARKIME) is False
    assert loaded.get_value(KEY_CONFIG_ITEM_PCAP_NETSNIFF) is False
    assert loaded.get_value(KEY_CONFIG_ITEM_PCAP_TCPDUMP) is False
    assert loaded.get_load_issues() == {}


def test_settings_file_round_trip_keeps_arkime_off_on_hedgehog(tmp_path):
    export_settings(hedgehog_without_arkime(), tmp_path / "settings.json")
    loaded = import_settings(tmp_path / "settings.json")
    assert loaded.get_value(KEY_CONFIG_ITEM_LIVE_ARKIME) is False
    assert loaded.get_load_issues() == {}


def test_settings_file_import_of_default_export_reports_nothing_missing(tmp_path):
    # cisagov/Malcolm#1110
    export_settings(MalcolmConfig(), tmp_path / "default.json")
    missing = SettingsFileHandler(MalcolmConfig(), InstallContext()).load_from_file(
        str(tmp_path / "default.json"), config_only=True
    )
    assert missing["missing_configuration"] == []


def test_loaded_value_survives_unrelated_toggle_after_load(tmp_path):
    loaded = env_round_trip(hedgehog_without_arkime(), tmp_path)
    loaded.set_value(KEY_CONFIG_ITEM_PCAP_TCPDUMP, True)
    loaded.set_value(KEY_CONFIG_ITEM_PCAP_TCPDUMP, False)
    assert loaded.get_value(KEY_CONFIG_ITEM_LIVE_ARKIME) is False


def test_session_set_value_survives_unrelated_toggle():
    # the behavior loaded values now share with values set in this session
    cfg = hedgehog_without_arkime()
    cfg.set_value(KEY_CONFIG_ITEM_PCAP_TCPDUMP, True)
    cfg.set_value(KEY_CONFIG_ITEM_PCAP_TCPDUMP, False)
    assert cfg.get_value(KEY_CONFIG_ITEM_LIVE_ARKIME) is False


def test_custom_zeek_intel_schedule_survives_env_load(tmp_path):
    cfg = MalcolmConfig()
    cfg.set_value(KEY_CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS, True)
    cfg.set_value(KEY_CONFIG_ITEM_ZEEK_INTEL_CRON_EXPRESSION, "0 6 * * 1")
    cfg.set_value(KEY_CONFIG_ITEM_ZEEK_INTEL_ON_STARTUP, False)
    loaded = env_round_trip(cfg, tmp_path)
    assert loaded.get_value(KEY_CONFIG_ITEM_ZEEK_INTEL_CRON_EXPRESSION) == "0 6 * * 1"
    assert loaded.get_value(KEY_CONFIG_ITEM_ZEEK_INTEL_ON_STARTUP) is False


def test_blank_zeek_intel_schedule_survives_settings_file(tmp_path):
    cfg = MalcolmConfig()
    cfg.set_value(KEY_CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS, True)
    cfg.set_value(KEY_CONFIG_ITEM_ZEEK_INTEL_ON_STARTUP, True)
    cfg.set_value(KEY_CONFIG_ITEM_ZEEK_INTEL_CRON_EXPRESSION, "")
    exported = export_settings(cfg, tmp_path / "settings.json")
    assert exported["metadata"]["format_version"] == SETTINGS_FILE_FORMAT_VERSION
    assert exported["configuration"][KEY_CONFIG_ITEM_ZEEK_INTEL_CRON_EXPRESSION] == ""
    loaded = import_settings(tmp_path / "settings.json")
    assert loaded.get_value(KEY_CONFIG_ITEM_ZEEK_INTEL_CRON_EXPRESSION) == ""


def test_derived_setting_is_recomputed_not_protected(tmp_path):
    # "capture live traffic" is computed from the capture methods, so a loaded value doesn't pin it
    loaded = env_round_trip(hedgehog_without_arkime(), tmp_path)
    assert not loaded.is_loaded(KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC)
    loaded.set_value(KEY_CONFIG_ITEM_LIVE_ZEEK, False)
    loaded.set_value(KEY_CONFIG_ITEM_LIVE_SURICATA, False)
    assert loaded.get_value(KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC) is False


def test_loaded_values_are_not_reported_as_modified(tmp_path):
    loaded = env_round_trip(hedgehog_without_arkime(), tmp_path)
    assert loaded.is_loaded(KEY_CONFIG_ITEM_LIVE_ARKIME)
    assert loaded.get_all_config_items(modified_only=True) == {}


# ---------------------------------------------------------------------------------------------
# ISO-installed Hedgehog (prune settings and reachback ACL come from the compose file)


@mock.patch.dict(SYSTEM_INFO, {"malcolm_iso_install": True})
def test_iso_prune_settings_do_not_turn_pcap_management_back_on(tmp_path):
    cfg = hedgehog_without_arkime()
    cfg.set_value(KEY_CONFIG_ITEM_PRUNE_PCAP, True)
    cfg.set_value(KEY_CONFIG_ITEM_PRUNE_LOGS, True)
    cfg.set_value(KEY_CONFIG_ITEM_ARKIME_MANAGE_PCAP, False)
    env_dir = tmp_path / "config"
    env_dir.mkdir()
    cfg.generate_env_files(str(env_dir))
    compose = write_compose(tmp_path / "docker-compose.yml", {"prune": {"pcap": True, "logs": True}})

    loaded = MalcolmConfig()
    with loaded.bulk_load():
        loaded.load_from_env_files(str(env_dir))
        loaded.load_from_orchestration_file(str(env_dir), compose)

    assert loaded.get_value(KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS) is True
    assert loaded.get_value(KEY_CONFIG_ITEM_ARKIME_MANAGE_PCAP) is False


@mock.patch.dict(SYSTEM_INFO, {"malcolm_iso_install": True})
def test_iso_reachback_acl_from_compose_is_kept_until_remote_host_changes(tmp_path):
    env_dir = tmp_path / "config"
    env_dir.mkdir()
    hedgehog_without_arkime().generate_env_files(str(env_dir))
    compose = write_compose(tmp_path / "docker-compose.yml", {"hedgehog": {"request_acl": ["10.0.0.5"]}})

    loaded = MalcolmConfig()
    with loaded.bulk_load():
        loaded.load_from_env_files(str(env_dir))
        loaded.load_from_orchestration_file(str(env_dir), compose)
    assert loaded.get_value(KEY_CONFIG_ITEM_REACHBACK_REQUEST_ACL) == ["10.0.0.5"]

    loaded.set_value(KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST, "192.168.1.20")
    assert loaded.get_value(KEY_CONFIG_ITEM_REACHBACK_REQUEST_ACL) == ["192.168.1.20"]


# ---------------------------------------------------------------------------------------------
# precedence between sources


def test_settings_file_beats_env_files_in_either_load_order(tmp_path):
    from_file = MalcolmConfig()
    from_file.set_value(KEY_CONFIG_ITEM_ZEEK_INTEL_CRON_EXPRESSION, "0 1 * * *")
    export_settings(from_file, tmp_path / "settings.json")

    on_disk = MalcolmConfig()
    on_disk.set_value(KEY_CONFIG_ITEM_ZEEK_INTEL_CRON_EXPRESSION, "0 2 * * *")
    env_dir = tmp_path / "config"
    env_dir.mkdir()
    on_disk.generate_env_files(str(env_dir))

    for env_first in (True, False):
        cfg = MalcolmConfig()
        with cfg.bulk_load():
            if env_first:
                cfg.load_from_env_files(str(env_dir))
            import_settings(tmp_path / "settings.json", cfg)
            if not env_first:
                cfg.load_from_env_files(str(env_dir))
        assert cfg.get_value(KEY_CONFIG_ITEM_ZEEK_INTEL_CRON_EXPRESSION) == "0 1 * * *"


def test_raw_backup_fills_in_what_the_configuration_section_lacks(tmp_path):
    source = MalcolmConfig()
    source.set_value(KEY_CONFIG_ITEM_ZEEK_INTEL_CRON_EXPRESSION, "0 3 * * *")
    source.set_value(KEY_CONFIG_ITEM_LS_WORKERS, 7)
    env_dir = tmp_path / "config"
    env_dir.mkdir()
    source.generate_env_files(str(env_dir))
    settings = export_settings(source, tmp_path / "settings.json")
    assert "raw" in settings

    # an older export without this key, and a configuration-section value that differs from the raw backup
    del settings["configuration"][KEY_CONFIG_ITEM_ZEEK_INTEL_CRON_EXPRESSION]
    settings["configuration"][KEY_CONFIG_ITEM_LS_WORKERS] = 5
    (tmp_path / "edited.json").write_text(json.dumps(settings))

    loaded = import_settings(tmp_path / "edited.json")
    assert loaded.get_value(KEY_CONFIG_ITEM_ZEEK_INTEL_CRON_EXPRESSION) == "0 3 * * *"  # from raw
    assert loaded.get_value(KEY_CONFIG_ITEM_LS_WORKERS) == 5  # configuration section wins


def test_command_line_orchestration_mode_beats_imported_settings(tmp_path):
    export_settings(MalcolmConfig(), tmp_path / "settings.json")  # docker compose
    cfg = MalcolmConfig()
    with cfg.bulk_load():
        cfg.load_value(
            KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE, OrchestrationFramework.KUBERNETES, LoadSource.COMMAND_LINE
        )
        import_settings(tmp_path / "settings.json", cfg)
    assert cfg.get_value(KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE) == OrchestrationFramework.KUBERNETES


def test_compose_storage_path_beats_iso_preseed():
    cfg = MalcolmConfig()
    with cfg.bulk_load():
        cfg.load_value(KEY_CONFIG_ITEM_PCAP_DIR, "/data/pcap-custom", LoadSource.COMPOSE_FILE)
        cfg.load_value(KEY_CONFIG_ITEM_PCAP_DIR, "/data/pcap-iso", LoadSource.PRESEED)
    assert cfg.get_value(KEY_CONFIG_ITEM_PCAP_DIR) == "/data/pcap-custom"


def test_load_value_outside_bulk_load_is_an_error():
    with pytest.raises(RuntimeError):
        MalcolmConfig().load_value(KEY_CONFIG_ITEM_PCAP_DIR, "/data", LoadSource.ENV_FILES)


# ---------------------------------------------------------------------------------------------
# rules after a load


def test_invariant_overrides_contradictory_loaded_value_with_warning():
    cfg = MalcolmConfig()
    with mock.patch.object(InstallerLogger, "warning") as warning:
        with cfg.bulk_load():
            cfg.load_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE, PROFILE_MALCOLM, LoadSource.ENV_FILES)
            cfg.load_value(KEY_CONFIG_ITEM_LOGSTASH_HOST, "10.1.1.1:5044", LoadSource.ENV_FILES)
    assert cfg.get_value(KEY_CONFIG_ITEM_LOGSTASH_HOST) == LOCAL_LOGSTASH_HOST
    assert any(KEY_CONFIG_ITEM_LOGSTASH_HOST in str(call.args[0]) for call in warning.call_args_list)


def test_profile_switch_still_ripples_through_forced_cascades(tmp_path):
    loaded = env_round_trip(hedgehog_without_arkime(), tmp_path)
    loaded.set_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE, PROFILE_MALCOLM)
    assert loaded.get_value(KEY_CONFIG_ITEM_NETBOX_MODE) == "local"
    assert loaded.get_value(KEY_CONFIG_ITEM_LOGSTASH_HOST) == LOCAL_LOGSTASH_HOST


def test_hedgehog_netbox_site_name_is_settable_in_every_netbox_mode():
    for mode in ("disabled", "local", "remote"):
        cfg = MalcolmConfig()
        cfg.set_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE, PROFILE_HEDGEHOG)
        cfg.set_value(KEY_CONFIG_ITEM_NETBOX_MODE, mode)
        assert cfg.is_item_visible(KEY_CONFIG_ITEM_NETBOX_SITE_NAME), mode


def test_rule_updates_stay_reachable_after_their_parent_is_turned_off():
    cfg = MalcolmConfig()
    cfg.set_value(KEY_CONFIG_ITEM_SURICATA_RULE_UPDATE, True)
    cfg.set_value(KEY_CONFIG_ITEM_AUTO_SURICATA, False)
    cfg.set_value(KEY_CONFIG_ITEM_LIVE_SURICATA, False)
    assert cfg.get_value(KEY_CONFIG_ITEM_SURICATA_RULE_UPDATE) is True
    assert cfg.is_item_visible(KEY_CONFIG_ITEM_SURICATA_RULE_UPDATE)
    cfg.set_value(KEY_CONFIG_ITEM_SURICATA_RULE_UPDATE, False)
    assert not cfg.is_item_visible(KEY_CONFIG_ITEM_SURICATA_RULE_UPDATE)


def test_every_value_rule_declares_its_kind():
    for key, spec in DEPENDENCY_CONFIG.items():
        for rule in spec.value_rules:
            assert isinstance(rule.kind, RuleKind), key


def test_value_rule_without_kind_is_rejected():
    manager = DependencyManager(MalcolmConfig())
    with pytest.raises(ValueError):
        manager._register_value_rule(
            KEY_CONFIG_ITEM_LS_WORKERS,
            ValueRule(depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE, condition=True, default_value=3),
        )


# ---------------------------------------------------------------------------------------------
# invalid loaded values block the save until they're dealt with


def test_invalid_loaded_value_is_a_validation_issue_until_set():
    cfg = MalcolmConfig()
    with cfg.bulk_load():
        cfg.load_value(KEY_CONFIG_ITEM_OS_MEMORY, "lots", LoadSource.ENV_FILES)
    assert KEY_CONFIG_ITEM_OS_MEMORY in cfg.get_load_issues()
    assert KEY_CONFIG_ITEM_OS_MEMORY in {issue.key for issue in validate_required(cfg)}

    cfg.set_value(KEY_CONFIG_ITEM_OS_MEMORY, "8g")
    assert KEY_CONFIG_ITEM_OS_MEMORY not in {issue.key for issue in validate_required(cfg)}


def test_invalid_loaded_value_for_hidden_setting_does_not_block():
    cfg = MalcolmConfig()
    cfg.set_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE, PROFILE_HEDGEHOG)  # OpenSearch memory is hidden on Hedgehog
    with cfg.bulk_load():
        cfg.load_value(KEY_CONFIG_ITEM_OS_MEMORY, "lots", LoadSource.ENV_FILES)
    assert KEY_CONFIG_ITEM_OS_MEMORY not in {issue.key for issue in validate_required(cfg)}


def test_good_value_from_higher_precedence_source_clears_lower_precedence_issue():
    cfg = MalcolmConfig()
    with cfg.bulk_load():
        cfg.load_value(KEY_CONFIG_ITEM_OS_MEMORY, "lots", LoadSource.SETTINGS_FILE_RAW)
        cfg.load_value(KEY_CONFIG_ITEM_OS_MEMORY, "12g", LoadSource.SETTINGS_FILE)
    assert cfg.get_load_issues() == {}
    assert cfg.get_value(KEY_CONFIG_ITEM_OS_MEMORY) == "12g"


# ---------------------------------------------------------------------------------------------
# saving is all or nothing


def test_failed_save_leaves_existing_files_untouched(tmp_path):
    out_dir = tmp_path / "config"
    out_dir.mkdir()
    MalcolmConfig().generate_env_files(str(out_dir))
    before = {p.name: p.read_bytes() for p in out_dir.glob("*.env")}

    cfg = hedgehog_without_arkime()
    # make the last environment variable's value impossible to compute, so earlier ones are already done
    env_var = list(cfg.get_env_mapper().env_var_by_map_key.values())[-1]
    with mock.patch.object(env_var, "transform", lambda *_: 1 / 0):
        with pytest.raises(FileOperationError):
            write_configuration_files(cfg, str(out_dir))

    assert {p.name: p.read_bytes() for p in out_dir.glob("*.env")} == before
    assert not [p for p in out_dir.iterdir() if "staging" in p.name]


def test_save_writes_configuration_raw_backup_and_extras(tmp_path):
    out_dir = tmp_path / "config"
    out_dir.mkdir()
    MalcolmConfig().generate_env_files(str(out_dir))
    with open(out_dir / "zeek.env", "a") as f:
        f.write("EXISTING_ONLY_SETTING=keep-me\n")

    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    (backup_dir / "zeek.env").write_text("# a comment from the backup\nBACKUP_ONLY_SETTING=from-backup\n")

    write_configuration_files(
        hedgehog_without_arkime(),
        str(out_dir),
        raw_envs=base64_encode_files_in_dir(str(backup_dir), "*.env"),
        extras=["zeek.env:EXTRA_SETTING=from-extra"],
    )
    zeek_env = (out_dir / "zeek.env").read_text()
    assert "# a comment from the backup" in zeek_env
    assert "BACKUP_ONLY_SETTING=from-backup" in zeek_env
    assert "EXISTING_ONLY_SETTING=keep-me" in zeek_env
    assert "EXTRA_SETTING=from-extra" in zeek_env
    reloaded = MalcolmConfig()
    reloaded.load_from_env_files(str(out_dir))
    assert reloaded.get_value(KEY_CONFIG_ITEM_LIVE_ARKIME) is False
    assert not [p for p in out_dir.iterdir() if "staging" in p.name]


def test_raw_restore_prefers_the_backup_for_variables_in_both(tmp_path):
    target = tmp_path / "config"
    target.mkdir()
    (target / "arkime.env").write_text("SHARED=existing\nONLY_HERE=1\n")
    backup = tmp_path / "backup"
    backup.mkdir()
    (backup / "arkime.env").write_text("SHARED=backup\n")
    assert restore_raw_env_files(base64_encode_files_in_dir(str(backup), "*.env"), str(target)) == 1
    lines = (target / "arkime.env").read_text().splitlines()
    assert "SHARED=backup" in lines and "SHARED=existing" not in lines
    assert "ONLY_HERE=1" in lines


# ---------------------------------------------------------------------------------------------
# smaller fixes made alongside


def test_env_var_lookup_by_item_key():
    cfg = MalcolmConfig()
    names = {env_var.variable_name for env_var in cfg.get_env_var_by_item_key(KEY_CONFIG_ITEM_LIVE_ARKIME)}
    assert "ARKIME_LIVE_CAPTURE" in names


def test_suggested_memory_sizes_survive_env_load_on_kubernetes(tmp_path):
    # a value equal to this host's suggested size used to be skipped on load, which let the
    #   Kubernetes defaults replace it
    cfg = MalcolmConfig()
    cfg.set_value(KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE, OrchestrationFramework.KUBERNETES)
    cfg.set_value(KEY_CONFIG_ITEM_LS_MEMORY, SYSTEM_INFO["suggested_ls_memory"])
    cfg.set_value(KEY_CONFIG_ITEM_OS_MEMORY, SYSTEM_INFO["suggested_os_memory"])
    loaded = env_round_trip(cfg, tmp_path)
    assert loaded.get_value(KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE) == OrchestrationFramework.KUBERNETES
    assert loaded.get_value(KEY_CONFIG_ITEM_LS_MEMORY) == SYSTEM_INFO["suggested_ls_memory"]
    assert loaded.get_value(KEY_CONFIG_ITEM_OS_MEMORY) == SYSTEM_INFO["suggested_os_memory"]


def test_generated_env_files_end_with_a_newline(tmp_path):
    MalcolmConfig().generate_env_files(str(tmp_path))
    env_files = list(tmp_path.glob("*.env"))
    assert env_files
    for env_file in env_files:
        assert env_file.read_bytes().endswith(b"\n"), env_file.name


# ---------------------------------------------------------------------------------------------
# found reviewing the changes as a whole


def test_malformed_value_is_a_load_issue_not_a_failed_load():
    cfg = MalcolmConfig()
    with cfg.bulk_load():
        # a list where a string belongs makes this item's validator raise TypeError
        cfg.load_value(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE, ["opensearch-local"], LoadSource.SETTINGS_FILE)
    assert KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE in cfg.get_load_issues()


def test_hidden_loaded_values_are_not_protected(tmp_path):
    # .env files hold every setting; one hidden because it doesn't apply wasn't chosen by anyone
    loaded = env_round_trip(MalcolmConfig(), tmp_path)  # live capture off, so the capture engines are hidden
    assert not loaded.is_item_visible(KEY_CONFIG_ITEM_PCAP_NETSNIFF)
    assert not loaded.is_loaded(KEY_CONFIG_ITEM_PCAP_NETSNIFF)
    assert loaded.is_loaded(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE)


def test_enabling_live_capture_after_load_picks_the_same_defaults_as_a_fresh_session(tmp_path):
    for profile_settings in ({}, {KEY_CONFIG_ITEM_MALCOLM_PROFILE: PROFILE_HEDGEHOG}):
        saved = MalcolmConfig()
        for key, value in profile_settings.items():
            saved.set_value(key, value)
        fresh = MalcolmConfig()
        for key, value in profile_settings.items():
            fresh.set_value(key, value)
        loaded = env_round_trip(saved, tmp_path / str(len(profile_settings)))

        fresh.set_value(KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC, True)
        loaded.set_value(KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC, True)
        for key in (
            KEY_CONFIG_ITEM_PCAP_NETSNIFF,
            KEY_CONFIG_ITEM_PCAP_TCPDUMP,
            KEY_CONFIG_ITEM_LIVE_ARKIME,
            KEY_CONFIG_ITEM_CAPTURE_STATS,
        ):
            assert loaded.get_value(key) == fresh.get_value(key), (profile_settings, key)


def test_switching_an_existing_malcolm_to_hedgehog_stops_using_local_opensearch(tmp_path):
    loaded = env_round_trip(MalcolmConfig(), tmp_path)
    assert loaded.get_value(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE) == "opensearch-local"
    loaded.set_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE, PROFILE_HEDGEHOG)
    assert loaded.get_value(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE) == "opensearch-remote"


def test_hedgehog_keeps_remote_elasticsearch():
    cfg = MalcolmConfig()
    cfg.set_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE, PROFILE_HEDGEHOG)
    cfg.set_value(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE, "elasticsearch-remote")
    assert cfg.get_value(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE) == "elasticsearch-remote"


def test_password_values_are_masked_in_load_messages():
    cfg = MalcolmConfig()
    cfg.get_item(KEY_CONFIG_ITEM_OS_MEMORY).is_password = True  # no item is a password today; pretend
    with mock.patch.object(InstallerLogger, "debug") as debug:
        with cfg.bulk_load():
            cfg.load_value(KEY_CONFIG_ITEM_OS_MEMORY, "hunter2", LoadSource.ENV_FILES)
            cfg.load_value(KEY_CONFIG_ITEM_LS_MEMORY, "4g", LoadSource.ENV_FILES)
    assert "hunter2" not in cfg.get_load_issues()[KEY_CONFIG_ITEM_OS_MEMORY].message
    assert not any("hunter2" in str(call.args[0]) for call in debug.call_args_list)


# ---------------------------------------------------------------------------------------------
# OT/ICS analysis (#949 reported the ICS setting resetting; pin down that it round-trips)


@pytest.mark.parametrize("profile", [PROFILE_MALCOLM, PROFILE_HEDGEHOG])
@pytest.mark.parametrize("ics, best_guess", [(True, True), (True, False), (False, True), (False, False)])
def test_ics_settings_survive_env_files_and_settings_file(tmp_path, profile, ics, best_guess):
    cfg = MalcolmConfig()
    cfg.set_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE, profile)
    cfg.set_value(KEY_CONFIG_ITEM_MALCOLM_ICS, ics)
    cfg.set_value(KEY_CONFIG_ITEM_ZEEK_ICS_BEST_GUESS, best_guess)

    loaded = env_round_trip(cfg, tmp_path / "config")
    assert loaded.get_value(KEY_CONFIG_ITEM_MALCOLM_ICS) is ics
    assert loaded.get_value(KEY_CONFIG_ITEM_ZEEK_ICS_BEST_GUESS) is best_guess

    export_settings(cfg, tmp_path / "settings.json")
    imported = import_settings(tmp_path / "settings.json")
    assert imported.get_value(KEY_CONFIG_ITEM_MALCOLM_ICS) is ics
    assert imported.get_value(KEY_CONFIG_ITEM_ZEEK_ICS_BEST_GUESS) is best_guess


def test_per_protocol_ics_switches_edited_by_hand_survive_a_save(tmp_path):
    # the per-protocol ZEEK_DISABLE_ICS_* variables aren't installer settings, so a save leaves them be
    MalcolmConfig().generate_env_files(str(tmp_path))
    zeek_env = tmp_path / "zeek.env"
    text = zeek_env.read_text()
    assert "ZEEK_DISABLE_ICS_MODBUS=\n" in text and "ZEEK_DISABLE_ICS_GENISYS=true\n" in text
    zeek_env.write_text(
        text.replace("ZEEK_DISABLE_ICS_MODBUS=\n", "ZEEK_DISABLE_ICS_MODBUS=true\n").replace(
            "ZEEK_DISABLE_ICS_GENISYS=true\n", "ZEEK_DISABLE_ICS_GENISYS=\n"
        )
    )

    loaded = MalcolmConfig()
    loaded.load_from_env_files(str(tmp_path))
    loaded.set_value(KEY_CONFIG_ITEM_MALCOLM_ICS, False)
    loaded.set_value(KEY_CONFIG_ITEM_MALCOLM_ICS, True)
    write_configuration_files(loaded, str(tmp_path))

    lines = zeek_env.read_text().splitlines()
    assert "ZEEK_DISABLE_ICS_MODBUS=true" in lines
    assert "ZEEK_DISABLE_ICS_GENISYS=" in lines


# ---------------------------------------------------------------------------------------------
# index pruning (the prune threshold is the only thing that turns it on)


def _written_prune_limit(env_dir) -> str:
    for line in (env_dir / "dashboards-helper.env").read_text().splitlines():
        if line.startswith("OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT="):
            return line.split("=", 1)[1]
    raise AssertionError("OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT not written")


def test_turning_off_index_cleanup_after_load_turns_off_pruning(tmp_path):
    cfg = MalcolmConfig()
    cfg.set_value(KEY_CONFIG_ITEM_CLEAN_UP_OLD_INDICES, True)
    cfg.set_value(KEY_CONFIG_ITEM_INDEX_PRUNE_THRESHOLD, "500g")
    loaded = env_round_trip(cfg, tmp_path)
    assert loaded.get_value(KEY_CONFIG_ITEM_CLEAN_UP_OLD_INDICES) is True
    assert _written_prune_limit(tmp_path) == "500g"

    loaded.set_value(KEY_CONFIG_ITEM_CLEAN_UP_OLD_INDICES, False)
    loaded.generate_env_files(str(tmp_path))
    assert _written_prune_limit(tmp_path) == "0"


def test_imported_threshold_without_index_cleanup_does_not_prune(tmp_path):
    export_settings(MalcolmConfig(), tmp_path / "settings.json")
    settings = json.loads((tmp_path / "settings.json").read_text())
    settings["configuration"][KEY_CONFIG_ITEM_CLEAN_UP_OLD_INDICES] = False
    settings["configuration"][KEY_CONFIG_ITEM_INDEX_PRUNE_THRESHOLD] = "500g"
    (tmp_path / "settings.json").write_text(json.dumps(settings))

    imported = import_settings(tmp_path / "settings.json")
    env_dir = tmp_path / "config"
    env_dir.mkdir()
    imported.generate_env_files(str(env_dir))
    assert _written_prune_limit(env_dir) == "0"


# ---------------------------------------------------------------------------------------------
# the debug log of loaded values


def test_load_log_says_when_rules_changed_a_loaded_value(tmp_path):
    export_settings(MalcolmConfig(), tmp_path / "settings.json")
    settings = json.loads((tmp_path / "settings.json").read_text())
    settings["configuration"][KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS] = False  # derived from the next line
    settings["configuration"][KEY_CONFIG_ITEM_ARKIME_MANAGE_PCAP] = True
    settings["configuration"][KEY_CONFIG_ITEM_MALCOLM_PROFILE] = PROFILE_MALCOLM
    settings["configuration"][KEY_CONFIG_ITEM_LOGSTASH_HOST] = "10.1.1.1:5044"  # Malcolm always uses its own
    (tmp_path / "settings.json").write_text(json.dumps(settings))

    with mock.patch.object(InstallerLogger, "debug") as debug:
        import_settings(tmp_path / "settings.json")
    lines = {str(c.args[0]).split(" = ")[0].removeprefix("Loaded "): str(c.args[0]) for c in debug.call_args_list}

    assert lines[KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS] == (
        f'Loaded {KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS} = "True" (recomputed; settings file (settings.json) had "False")'
    )
    assert lines[KEY_CONFIG_ITEM_LOGSTASH_HOST] == (
        f'Loaded {KEY_CONFIG_ITEM_LOGSTASH_HOST} = "{LOCAL_LOGSTASH_HOST}" '
        '(changed by a dependency rule; settings file (settings.json) had "10.1.1.1:5044")'
    )
    assert lines[KEY_CONFIG_ITEM_ARKIME_MANAGE_PCAP] == (
        f'Loaded {KEY_CONFIG_ITEM_ARKIME_MANAGE_PCAP} = "True" from settings file (settings.json)'
    )


# ---------------------------------------------------------------------------------------------
# blanks in a settings file (e.g., from a script filling in a template)


def test_blank_in_settings_file_for_a_setting_that_cannot_be_blank_keeps_the_default(tmp_path):
    export_settings(MalcolmConfig(), tmp_path / "settings.json")
    settings = json.loads((tmp_path / "settings.json").read_text())
    defaults = MalcolmConfig()
    for key in (KEY_CONFIG_ITEM_LS_MEMORY, KEY_CONFIG_ITEM_OS_MEMORY, KEY_CONFIG_ITEM_INDEX_MANAGEMENT_SPI_DATA_RETENTION):
        assert not defaults.get_item(key).accept_blank
        settings["configuration"][key] = ""
    settings["configuration"][KEY_CONFIG_ITEM_ZEEK_INTEL_CRON_EXPRESSION] = ""  # this one accepts a blank
    (tmp_path / "settings.json").write_text(json.dumps(settings))

    imported = import_settings(tmp_path / "settings.json")
    assert imported.get_load_issues() == {}
    assert validate_required(imported) == []
    for key in (KEY_CONFIG_ITEM_LS_MEMORY, KEY_CONFIG_ITEM_OS_MEMORY, KEY_CONFIG_ITEM_INDEX_MANAGEMENT_SPI_DATA_RETENTION):
        assert imported.get_value(key) == defaults.get_value(key), key
    assert imported.get_value(KEY_CONFIG_ITEM_ZEEK_INTEL_CRON_EXPRESSION) == ""


# ---------------------------------------------------------------------------------------------
# turning live capture off turns every capture method off


def _written_env(env_dir) -> dict:
    values = {}
    for env_file in env_dir.glob("*.env"):
        for line in env_file.read_text().splitlines():
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key] = value
    return values


def _capturing(profile_settings) -> MalcolmConfig:
    cfg = MalcolmConfig()
    for key, value in profile_settings:
        cfg.set_value(key, value)
    for key, value in (
        (KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC, True),
        (KEY_CONFIG_ITEM_PCAP_IFACE, ["eth0"]),
        (KEY_CONFIG_ITEM_LIVE_ZEEK, True),
        (KEY_CONFIG_ITEM_LIVE_SURICATA, True),
    ):
        cfg.set_value(key, value)
    return cfg


CAPTURE_PROFILES = {
    "malcolm-netsniff": [(KEY_CONFIG_ITEM_PCAP_NETSNIFF, True)],
    "hedgehog-arkime": [
        (KEY_CONFIG_ITEM_MALCOLM_PROFILE, PROFILE_HEDGEHOG),
        (KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST, "10.0.0.9"),
        (KEY_CONFIG_ITEM_LIVE_ARKIME, True),
    ],
}


@pytest.mark.parametrize("profile", sorted(CAPTURE_PROFILES))
def test_turning_off_live_capture_after_load_turns_off_every_capture_method(tmp_path, profile):
    loaded = env_round_trip(_capturing(CAPTURE_PROFILES[profile]), tmp_path / "loaded")
    loaded.set_value(KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC, False)
    out_dir = tmp_path / "saved"
    out_dir.mkdir()
    loaded.generate_env_files(str(out_dir))

    written = _written_env(out_dir)
    for variable in (
        "PCAP_ENABLE_NETSNIFF",
        "PCAP_ENABLE_TCPDUMP",
        "ARKIME_LIVE_CAPTURE",
        "ZEEK_LIVE_CAPTURE",
        "SURICATA_LIVE_CAPTURE",
    ):
        assert written[variable] == "false", variable


DEFAULT_ENGINE = {"malcolm-netsniff": KEY_CONFIG_ITEM_PCAP_NETSNIFF, "hedgehog-arkime": KEY_CONFIG_ITEM_LIVE_ARKIME}


@pytest.mark.parametrize("profile", sorted(CAPTURE_PROFILES))
@pytest.mark.parametrize("loaded", [True, False])
def test_live_capture_off_then_on_brings_back_the_default_engine(tmp_path, profile, loaded):
    # whether the engine was loaded or chosen in this session, turning capture off replaces that
    #   choice, so turning capture back on picks the default engine again
    cfg = _capturing(CAPTURE_PROFILES[profile])
    if loaded:
        cfg = env_round_trip(cfg, tmp_path)
    cfg.set_value(KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC, False)
    cfg.set_value(KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC, True)
    for key in (KEY_CONFIG_ITEM_PCAP_NETSNIFF, KEY_CONFIG_ITEM_PCAP_TCPDUMP, KEY_CONFIG_ITEM_LIVE_ARKIME):
        assert cfg.get_value(key) is (key == DEFAULT_ENGINE[profile]), key
