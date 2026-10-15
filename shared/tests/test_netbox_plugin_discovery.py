"""Offline regression coverage for discovering and registering NetBox plugins."""

import ast
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock


SOURCE = Path(__file__).resolve().parents[2] / "netbox/control-scripts/netbox_install_plugins.py"
SPEC = importlib.util.spec_from_file_location("malcolm_netbox_plugin_installer", SOURCE)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def write_init(parent, name, *, class_name="Plugin", base="PluginConfig"):
    package = parent / name
    package.mkdir(parents=True, exist_ok=True)
    init = package / "__init__.py"
    init.write_text(f"class {class_name}({base}):\n    name = {name!r}\n")
    return init


def test_discover_static_plugin_names_in_sorted_order(tmp_path, monkeypatch):
    paths = [write_init(tmp_path, name) for name in ("zeta", "gamma", "alpha")]
    run = Mock(return_value=(0, list(map(str, paths))))
    monkeypatch.setattr(mod.malcolm_utils, "run_process", run)
    names = mod.discover_plugin_names([str(tmp_path)])
    assert names == ["alpha", "gamma", "zeta"]
    argv = run.call_args.args[0]
    assert all(isinstance(arg, str) for arg in argv)
    assert argv[-1] == str(tmp_path)


def test_discovery_without_valid_locations_does_not_scan_cwd(monkeypatch):
    run = Mock(side_effect=AssertionError("rg must not be launched without locations"))
    monkeypatch.setattr(mod.malcolm_utils, "run_process", run)
    assert mod.discover_plugin_names([]) == []
    run.assert_not_called()


def test_ignore_malformed_and_non_plugin_classes(tmp_path, monkeypatch):
    valid = write_init(tmp_path, "expected", base="plugin_api.PluginConfig")
    other = tmp_path / "irrelevant" / "__init__.py"
    other.parent.mkdir()
    other.write_text('class Fake(OtherBase):\n    name = "ignore"\n')
    wrong_type = tmp_path / "bad_name" / "__init__.py"
    wrong_type.parent.mkdir()
    wrong_type.write_text("class Fake(PluginConfig):\n    name = 123\n")
    syntax_error = tmp_path / "syntax_error" / "__init__.py"
    syntax_error.parent.mkdir()
    syntax_error.write_text("class Something(:\n")
    monkeypatch.setattr(
        mod.malcolm_utils, "run_process", lambda *a, **kw: (0, list(map(str, (valid, other, wrong_type, syntax_error))))
    )
    assert mod.discover_plugin_names([str(tmp_path)]) == ["expected"]


def test_adding_plugins_respects_only_top_level_assignment(tmp_path):
    config = tmp_path / "plugins.py"
    config.write_text('def unrelated():\n    PLUGINS = ["nested"]\n    return PLUGINS\n')
    assert mod.register_plugin_names(str(config), ["zeta", "alpha"]) is True
    tree = ast.parse(config.read_text())
    top_assignments = [node for node in tree.body if isinstance(node, ast.Assign)]
    assert len(top_assignments) == 1
    assert ast.literal_eval(top_assignments[0].value) == ["alpha", "zeta"]
    function = next(x for x in tree.body if isinstance(x, ast.FunctionDef))
    assert ast.literal_eval(function.body[0].value) == ["nested"]


def test_existing_registration_remains_idempotent(tmp_path):
    config = tmp_path / "plugins.py"
    config.write_text('PLUGINS = ["alpha"]\n')
    assert mod.register_plugin_names(str(config), ["alpha", "zeta", "gamma"]) is True
    assert ast.literal_eval(ast.parse(config.read_text()).body[0].value) == ["alpha", "gamma", "zeta"]
    unchanged = config.read_text()
    assert mod.register_plugin_names(str(config), ["gamma", "alpha", "zeta"]) is False
    assert config.read_text() == unchanged


def test_dynamic_plugin_list_remains_untouched(tmp_path):
    config = tmp_path / "plugins.py"
    config.write_text("PLUGINS = base_plugins()\n")
    assert mod.register_plugin_names(str(config), ["new"]) is False
    assert config.read_text() == "PLUGINS = base_plugins()\n"


def test_full_install_flow_only_migrates_for_changes(tmp_path, monkeypatch):
    root = tmp_path / "netbox"
    config = tmp_path / "config"
    custom = tmp_path / "custom"
    package_dir = tmp_path / "installed"
    config.mkdir()
    custom.mkdir()
    package_dir.mkdir()
    (root / "netbox").mkdir(parents=True)
    (config / "plugins.py").write_text("PLUGINS = []\n")
    (custom / "testpackage").mkdir()
    src_b = write_init(package_dir, "beta")
    src_a = write_init(package_dir, "alpha")
    args = SimpleNamespace(netboxDir=str(root), netboxConfigDir=str(config), customPluginsDir=str(custom))
    monkeypatch.setattr(mod, "install_requirements", lambda *a: None)
    monkeypatch.setattr(mod, "get_installed_packages", lambda *a: {"dummy": {"location": str(package_dir)}})
    monkeypatch.setattr(mod, "install_package_dir_if_needed", lambda *a: False)
    monkeypatch.setattr(mod.malcolm_utils, "run_process", lambda *a, **kw: (0, [str(src_b), str(src_a)]))
    migrations = Mock(return_value=True)
    monkeypatch.setattr(mod, "perform_migrations", migrations)
    mod.install_plugins(args)
    assert ast.literal_eval(ast.parse((config / "plugins.py").read_text()).body[0].value) == ["alpha", "beta"]
    migrations.assert_called_once()
    mod.install_plugins(args)
    migrations.assert_called_once()


def test_full_install_does_not_modify_function_local_plugins_assignment(tmp_path, monkeypatch):
    root = tmp_path / "netbox"
    config = tmp_path / "config"
    custom = tmp_path / "custom"
    package_dir = tmp_path / "installed"
    (root / "netbox").mkdir(parents=True)
    config.mkdir()
    custom.mkdir()
    package_dir.mkdir()
    source = write_init(package_dir, "new_plugin")
    (custom / "new_plugin").mkdir()
    config_file = config / "plugins.py"
    config_file.write_text('def something():\n    PLUGINS = ["nested"]\n    return PLUGINS\n')
    args = SimpleNamespace(netboxDir=str(root), netboxConfigDir=str(config), customPluginsDir=str(custom))
    monkeypatch.setattr(mod, "install_requirements", lambda *args: None)
    monkeypatch.setattr(mod, "get_installed_packages", lambda *args: {"pkg": {"location": str(package_dir)}})
    monkeypatch.setattr(mod, "install_package_dir_if_needed", lambda *args: False)
    monkeypatch.setattr(mod.malcolm_utils, "run_process", lambda *a, **kw: (0, [str(source)]))
    monkeypatch.setattr(mod, "perform_migrations", Mock(return_value=True))
    mod.install_plugins(args)
    tree = ast.parse(config_file.read_text())
    toplevel = [node for node in tree.body if isinstance(node, ast.Assign)]
    assert len(toplevel) == 1
    assert ast.literal_eval(toplevel[0].value) == ["new_plugin"]
    local_assignment = next(node for node in tree.body if isinstance(node, ast.FunctionDef)).body[0]
    assert ast.literal_eval(local_assignment.value) == ["nested"]
