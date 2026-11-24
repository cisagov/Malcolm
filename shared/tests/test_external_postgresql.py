"""Exercise application database configuration and backup/restore entry points."""

import gzip
import json
import os
import runpy
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]


def clean_env():
    return {key: value for key, value in os.environ.items() if not key.startswith(('POSTGRES_', 'PG', 'DB_', 'KC_'))}


@pytest.fixture
def db_tools(tmp_path):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    log = tmp_path / 'calls.jsonl'
    probe = f'#!{sys.executable}\n' + '''\
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
with open(os.environ['DB_CALLS'], 'a') as stream:
    stream.write(json.dumps({'tool': name, 'args': sys.argv[1:],
        'password': os.getenv('PGPASSWORD'), 'sslmode': os.getenv('PGSSLMODE'),
        'rootcert': os.getenv('PGSSLROOTCERT')}) + '\\n')
if name == 'pg_dump':
    print('CREATE TABLE example (id integer);')
    sys.exit(int(os.getenv('DUMP_STATUS', '0')))
if name == 'psql':
    print('1')
'''
    for name in ('pg_dump', 'pg_isready', 'psql'):
        executable = bin_dir / name
        executable.write_text(probe)
        executable.chmod(0o755)
    env = clean_env() | {'PATH': f'{bin_dir}:{os.environ["PATH"]}', 'DB_CALLS': str(log)}
    return env, log


def calls(log):
    return [json.loads(line) for line in log.read_text().splitlines()]


def execute(script, env, *args):
    return subprocess.run(
        ['bash', str(ROOT / script), *args], env=env, capture_output=True, text=True, timeout=5, check=False
    )


@pytest.mark.parametrize(
    'host,port,user,database',
    [
        ('postgres', '5432', 'netbox', 'netbox'),
        ('db.example.org', '6432', 'restricted-role', 'custom_inventory'),
        ('2001:db8::10', '5433', 'netbox user', 'inventory with spaces'),
    ],
)
def test_backup_uses_application_endpoint(db_tools, host, port, user, database):
    env, log = db_tools
    env.update(
        POSTGRES_HOST=host,
        PGPORT=port,
        POSTGRES_NETBOX_USER=user,
        POSTGRES_NETBOX_DB=database,
        POSTGRES_NETBOX_PASSWORD='test-password-with-$-characters',
        POSTGRES_DISABLED='true',
        PGSSLMODE='verify-full',
        PGSSLROOTCERT='/ca path/root.crt',
    )
    result = execute('netbox/control-scripts/netbox-backup.sh', env)
    assert result.returncode == 0, result.stderr
    (call,) = calls(log)
    assert call['args'] == ['--no-password', '--host', host, '--port', port, '--username', user, '--dbname', database]
    assert call['password'] == env['POSTGRES_NETBOX_PASSWORD']
    assert call['password'] not in ' '.join(call['args']) + result.stdout + result.stderr
    assert call['sslmode'] == 'verify-full'
    assert call['rootcert'] == '/ca path/root.crt'


def test_backup_defaults_and_legacy_db_environment(db_tools):
    env, log = db_tools
    env.update(
        DB_HOST='legacy-db',
        DB_PORT='5544',
        DB_USER='legacy-user',
        DB_NAME='legacy_inventory',
        DB_PASSWORD='test-password',
        DB_SSLMODE='require',
        PGSSLMODE='prefer',
    )
    result = execute('netbox/control-scripts/netbox-backup.sh', env)
    assert result.returncode == 0
    (call,) = calls(log)
    assert call['args'][-7:] == [
        'legacy-db',
        '--port',
        '5544',
        '--username',
        'legacy-user',
        '--dbname',
        'legacy_inventory',
    ]
    assert call['password'] == 'test-password'
    assert call['sslmode'] == 'require'


def test_backup_propagates_dump_failure(db_tools):
    env, _ = db_tools
    result = execute('netbox/control-scripts/netbox-backup.sh', env | {'DUMP_STATUS': '7'})
    assert result.returncode == 7


@pytest.mark.parametrize(
    'host,port,database,jdbc_host',
    [
        ('postgres', '5432', 'keycloak', 'postgres'),
        ('db.example.org', '6432', 'identity_prod', 'db.example.org'),
        ('2001:db8::10', '5433', 'identity', '[2001:db8::10]'),
    ],
)
def test_keycloak_checks_application_database(db_tools, host, port, database, jdbc_host):
    env, log = db_tools
    properties = '?sslmode=verify-full&sslrootcert=/ca/root.crt'
    env.update(
        NGINX_AUTH_MODE='keycloak',
        POSTGRES_HOST=host,
        PGPORT=port,
        POSTGRES_DB='inaccessible_maintenance',
        POSTGRES_KEYCLOAK_DB=database,
        POSTGRES_KEYCLOAK_USER='restricted',
        POSTGRES_KEYCLOAK_PASSWORD='test-password',
        PGSSLMODE='verify-full',
        PGSSLROOTCERT='/ca/root.crt',
        KC_DB_URL_PROPERTIES=properties,
    )
    result = execute('keycloak/scripts/docker-entrypoint.sh', env, 'bash', '-c', 'printf "JDBC=%s\\n" "$KC_DB_URL"')
    assert result.returncode == 0, result.stderr
    readiness, connection = calls(log)
    assert readiness['tool'] == 'pg_isready'
    assert readiness['args'][readiness['args'].index('-d') + 1] == database
    assert connection['tool'] == 'psql'
    assert connection['args'][connection['args'].index('-d') + 1] == database
    assert connection['args'][-1] == 'SELECT 1'
    assert 'inaccessible_maintenance' not in connection['args']
    assert '-w' in connection['args']
    assert connection['sslmode'] == 'verify-full'
    assert f'JDBC=jdbc:postgresql://{jdbc_host}:{port}/{database}{properties}' in result.stdout
    assert 'test-password' not in result.stdout + result.stderr


def test_remote_keycloak_mode_does_not_contact_database(db_tools):
    env, log = db_tools
    result = execute('keycloak/scripts/docker-entrypoint.sh', env | {'NGINX_AUTH_MODE': 'keycloak_remote'}, 'true')
    assert result.returncode == 0
    assert not log.exists()


@pytest.mark.parametrize(
    'pgmode,dbmode,expected',
    [(None, None, 'prefer'), ('verify-full', None, 'verify-full'), ('prefer', 'require', 'require')],
)
def test_netbox_respects_ssl_environment(monkeypatch, pgmode, dbmode, expected):
    monkeypatch.delenv('PGSSLMODE', raising=False)
    monkeypatch.delenv('DB_SSLMODE', raising=False)
    if pgmode is not None:
        monkeypatch.setenv('PGSSLMODE', pgmode)
    if dbmode is not None:
        monkeypatch.setenv('DB_SSLMODE', dbmode)
    config = runpy.run_path(str(ROOT / 'netbox/config/configuration.py'))
    assert config['DATABASES']['default']['OPTIONS']['sslmode'] == expected


@pytest.fixture
def control_module(monkeypatch, tmp_path):
    import control

    monkeypatch.chdir(tmp_path)
    (tmp_path / 'netbox/media').mkdir(parents=True)
    monkeypatch.setattr(control, 'GetMalcolmPath', lambda: str(tmp_path))
    monkeypatch.setattr(control, 'GetUidGidFromEnv', lambda _: {'PUID': '1000', 'PGID': '1000'})
    monkeypatch.setattr(
        control,
        'args',
        SimpleNamespace(
            configDir=str(tmp_path),
            composeProfile='malcolm',
            noTmpDirOverride=True,
            composeFile='compose.yml',
            namespace='malcolm',
            verbose=20,
        ),
    )
    monkeypatch.setattr(control, 'dockerComposeBin', 'docker-compose')
    return control


@pytest.mark.parametrize('kubernetes', [False, True])
def test_control_backup_runs_inside_netbox(control_module, monkeypatch, tmp_path, kubernetes):
    control = control_module
    recorded = []
    if kubernetes:
        monkeypatch.setattr(control, 'orchMode', control.OrchestrationFramework.KUBERNETES)

        def pod_exec(**kwargs):
            recorded.append(kwargs)
            return {'netbox-pod': {'err': 0, 'output': ['CREATE TABLE example (id integer);']}}

        monkeypatch.setattr(control, 'PodExec', pod_exec)
    else:
        monkeypatch.setattr(control, 'orchMode', control.OrchestrationFramework.DOCKER_COMPOSE)

        def run_process(cmd, **kwargs):
            recorded.append(cmd)
            return 0, ['CREATE TABLE example (id integer);']

        monkeypatch.setattr(control, 'run_process', run_process)
    filename = str(tmp_path / 'requested-name.gz')
    backup, media = control.netboxBackup(filename)
    assert backup == filename
    assert 'CREATE TABLE' in gzip.open(backup, 'rt').read()
    if kubernetes:
        assert recorded[0]['service'] == 'netbox'
        assert recorded[0]['container'] == 'netbox-container'
        assert recorded[0]['command'] == ['/usr/local/bin/netbox-backup.sh']
        assert media is None
    else:
        assert recorded[0][-2:] == ['netbox', '/usr/local/bin/netbox-backup.sh']
        assert Path(media).is_file()


def test_control_backup_rejects_failed_dump(control_module, monkeypatch, tmp_path):
    control = control_module
    monkeypatch.setattr(control, 'orchMode', control.OrchestrationFramework.DOCKER_COMPOSE)
    monkeypatch.setattr(control, 'run_process', lambda *a, **k: (1, ['partial output']))
    filename = str(tmp_path / 'failed.gz')
    with pytest.raises(Exception, match='Error creating NetBox'):
        control.netboxBackup(filename)
    assert not Path(filename).exists()


@pytest.fixture
def restore_module():
    # These are the runtime dependencies of the initializer, also in test requirements.
    import netbox_init

    return netbox_init


def restore_args():
    return SimpleNamespace(
        postgres_host='db.example.org',
        postgres_port=6432,
        postgres_user='restricted',
        postgres_db='inventory_prod',
        postgres_password='test-password',
    )


@pytest.mark.parametrize(
    'override,expected', [(None, 'verify-full'), ('require', 'require'), ('verify-ca', 'verify-ca')]
)
def test_restore_targets_custom_database(restore_module, monkeypatch, tmp_path, override, expected):
    monkeypatch.setenv('PGSSLMODE', 'verify-full')
    monkeypatch.delenv('DB_SSLMODE', raising=False)
    if override is not None:
        monkeypatch.setenv('DB_SSLMODE', override)
    module = restore_module
    records = []

    def run_process(cmd, **kwargs):
        records.append((cmd, kwargs))
        return 0, ['OK']

    monkeypatch.setattr(module.malcolm_utils, 'run_process', run_process)
    monkeypatch.setattr(module.magic, 'from_file', lambda *a, **k: 'text/plain')
    sql = tmp_path / 'restore.sql'
    sql.write_text('CREATE TABLE example (id integer);')
    assert module.execute_restore_commands(restore_args(), str(sql))
    sql_calls = [cmd for cmd, _ in records if cmd[0] == 'psql']
    assert len(sql_calls) == 3
    for cmd in sql_calls:
        assert cmd[cmd.index('-d') + 1] == 'inventory_prod'
        assert '--no-password' in cmd
        assert 'ON_ERROR_STOP=1' in cmd
    assert all(kwargs['env']['PGPASSWORD'] == 'test-password' for _, kwargs in records)
    assert all(kwargs['env']['PGSSLMODE'] == expected for _, kwargs in records)


def test_restore_stops_after_sql_error(restore_module, monkeypatch, tmp_path):
    module = restore_module
    records = []

    def run_process(cmd, **kwargs):
        records.append(cmd)
        return (3, ['SQL error']) if cmd[0] == 'psql' else (0, ['OK'])

    monkeypatch.setattr(module.malcolm_utils, 'run_process', run_process)
    monkeypatch.setattr(module.magic, 'from_file', lambda *a, **k: 'text/plain')
    sql = tmp_path / 'bad.sql'
    sql.write_text('INVALID SQL;')
    with pytest.raises(Exception, match='loading NetBox database'):
        module.execute_restore_commands(restore_args(), str(sql))
    assert len(records) == 3
