"""Regression coverage for opt-in standalone Hedgehog authentication setup."""

from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import control
import dotenv
import pytest


@pytest.fixture
def configured_sensor(tmp_path, monkeypatch):
    config_dir = tmp_path / 'config'
    config_dir.mkdir()
    (config_dir / 'filebeat.env').write_text('FILEBEAT_MAIN_LOGS=true\nOTHER=true\n')
    (config_dir / 'opensearch.env').write_text('OPENSEARCH_URL=https://example.invalid:9200\nOTHER=true\n')
    cert_dir = tmp_path / 'filebeat' / 'certs'
    cert_dir.mkdir(parents=True)
    monkeypatch.setattr(control, 'GetMalcolmPath', lambda: str(tmp_path))
    monkeypatch.setattr(control, 'getNginxAuthMethod', lambda: 'basic')
    monkeypatch.setattr(control, 'dotenvImported', dotenv)
    monkeypatch.setattr(control, 'which', lambda name: None)
    monkeypatch.setattr(control, 'MainDialog', None)

    class AuthArgs(SimpleNamespace):
        def __getattr__(self, name):
            return False

    monkeypatch.setattr(
        control,
        'args',
        AuthArgs(configDir=str(config_dir), composeProfile=control.PROFILE_HEDGEHOG),
    )
    return config_dir, cert_dir


def test_standalone_files_keep_existing_certificates_and_other_settings(configured_sensor):
    config_dir, cert_dir = configured_sensor
    existing = cert_dir / 'client.crt'
    existing.write_bytes(b'existing certificate')
    control.prepareStandaloneHedgehog(str(config_dir), str(cert_dir))
    control.prepareStandaloneHedgehog(str(config_dir), str(cert_dir))
    assert dotenv.dotenv_values(config_dir / 'filebeat.env') == {'FILEBEAT_MAIN_LOGS': 'false', 'OTHER': 'true'}
    assert dotenv.dotenv_values(config_dir / 'opensearch.env') == {'OPENSEARCH_URL': '', 'OTHER': 'true'}
    assert existing.read_bytes() == b'existing certificate'
    assert (cert_dir / 'ca.crt').read_bytes() == b''
    assert (cert_dir / 'client.key').read_bytes() == b''


@pytest.mark.parametrize('answer', [False, True])
def test_standalone_is_explicitly_opt_in(configured_sensor, monkeypatch, answer):
    config_dir, cert_dir = configured_sensor
    monkeypatch.setattr(control, 'ChooseOne', lambda *a, **kw: 'all')
    prompts = []

    def yes_or_no(prompt, **kwargs):
        prompts.append(prompt)
        return answer if 'standalone' in prompt.lower() else False

    monkeypatch.setattr(control, 'YesOrNo', yes_or_no)
    control.authSetup()
    assert any('standalone' in prompt.lower() for prompt in prompts)
    assert (cert_dir / 'ca.crt').exists() is answer
    assert dotenv.dotenv_values(config_dir / 'filebeat.env')['FILEBEAT_MAIN_LOGS'] == ('false' if answer else 'true')


def test_receiving_certificates_does_not_prompt_for_standalone(configured_sensor, monkeypatch):
    _, cert_dir = configured_sensor
    monkeypatch.setattr(control, 'which', lambda name: name)
    monkeypatch.setattr(control, 'ChooseOne', lambda *a, **kw: 'all')
    prompts = []

    def yes_or_no(prompt, **kwargs):
        prompts.append(prompt)
        return 'Receive client certificates' in prompt

    monkeypatch.setattr(control, 'YesOrNo', yes_or_no)
    monkeypatch.setattr(control, 'DisplayMessage', Mock())
    monkeypatch.setattr(control, 'AskForStrings', lambda **kwargs: ('192.0.2.1', 'one-time-phrase'))
    process = Mock()
    process.stdout.readline.return_value = b''
    process.poll.return_value = 0
    transfer = MagicMock()
    transfer.__enter__.return_value = process
    monkeypatch.setattr(control, 'Popen', Mock(return_value=transfer))
    control.authSetup()
    assert control.Popen.called
    assert not any('standalone' in prompt.lower() for prompt in prompts)
    assert not (cert_dir / 'ca.crt').exists()
