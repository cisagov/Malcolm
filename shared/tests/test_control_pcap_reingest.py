"""Safety and integration regressions for opt-in PCAP re-ingestion."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

import control_reingest as replay

PCAP_MAGIC = b'\xd4\xc3\xb2\xa1'
PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def paths(tmp_path):
    processed = tmp_path / 'processed'
    upload = tmp_path / 'upload'
    processed.mkdir()
    upload.mkdir()
    return processed, upload


def capture(directory, name='first.pcap', payload=PCAP_MAGIC + b'X' * 30):
    path = directory / name
    path.write_bytes(payload)
    return path


def test_preview_selects_only_real_pcap_content_in_name_order(paths):
    processed, upload = paths
    z = capture(processed, 'z.cap')
    capture(processed, 'a.pcapng', PCAPNG_MAGIC + b'Y' * 32)
    capture(processed, 'notpcap.pcap', b'not a packet capture')
    capture(processed, 'truncated.pcap', PCAP_MAGIC + b'1')
    capture(processed, 'reingest_deadbeef_original.pcap')
    (processed / 'folder').mkdir()
    (processed / 'symlink.pcap').symlink_to(z)
    result = replay.find_processed_pcaps(processed, upload, max_files=20)
    assert [p.name for p in result] == ['a.pcapng', 'z.cap']
    assert sorted(p.name for p in upload.iterdir()) == []


def test_preview_limit_is_deterministic(paths):
    processed, upload = paths
    for name in ('c.pcap', 'b.pcap', 'a.pcap'):
        capture(processed, name)
    result = replay.find_processed_pcaps(processed, upload, max_files=2)
    assert [p.name for p in result] == ['a.pcap', 'b.pcap']


@pytest.mark.parametrize('invalid', [0, -1, 101, 1.5, '2'])
def test_reingest_limit_must_be_bounded_integer(paths, invalid):
    processed, upload = paths
    with pytest.raises(ValueError, match='limit'):
        replay.find_processed_pcaps(processed, upload, max_files=invalid)


def test_source_and_destination_directories_must_be_distinct_and_real(paths, tmp_path):
    processed, upload = paths
    with pytest.raises(ValueError):
        replay.find_processed_pcaps(processed, processed, max_files=1)
    with pytest.raises(ValueError):
        replay.find_processed_pcaps(processed, tmp_path / 'missing', max_files=1)
    with pytest.raises(ValueError):
        replay.find_processed_pcaps(tmp_path / 'missing', upload, max_files=1)
    link = tmp_path / 'other_upload'
    link.symlink_to(upload, target_is_directory=True)
    with pytest.raises(ValueError):
        replay.find_processed_pcaps(processed, link, max_files=1)


def test_apply_publishes_complete_copy_with_new_name_without_removing_original(paths):
    processed, upload = paths
    source = capture(processed, 'incident.pcap')
    result = replay.publish_processed_pcaps(replay.find_processed_pcaps(processed, upload, 5), upload)
    assert len(result) == 1
    new_path = result[0]
    assert new_path.parent == upload
    assert new_path.name.startswith('reingest_')
    assert new_path.name.endswith('_incident.pcap')
    assert new_path.read_bytes() == source.read_bytes()
    assert source.exists()
    assert not list(processed.parent.glob('.malcolm-reingest-*'))


def test_apply_stages_outside_watch_directories_until_complete(paths, monkeypatch):
    processed, upload = paths
    source = capture(processed)
    originals = replay.shutil.copyfileobj

    def check_staging(source_f, dest_f, length=0):
        assert not list(upload.iterdir())
        assert source_f.read(4) == PCAP_MAGIC
        source_f.seek(0)
        return originals(source_f, dest_f, length or 1024 * 1024)

    monkeypatch.setattr(replay.shutil, 'copyfileobj', check_staging)
    result = replay.publish_processed_pcaps([source], upload)
    assert len(result) == 1
    assert result[0].stat().st_size == source.stat().st_size


def test_existing_upload_collision_does_not_overwrite(paths, monkeypatch):
    processed, upload = paths
    original = capture(processed)
    (upload / 'reingest_aaaaaaaa_first.pcap').write_bytes(b'keep')
    tokens = iter(['aaaaaaaa', 'bbbbbbbb'])
    monkeypatch.setattr(replay.secrets, 'token_hex', lambda _: next(tokens))
    result = replay.publish_processed_pcaps([original], upload)
    assert result[0].name == 'reingest_bbbbbbbb_first.pcap'
    assert (upload / 'reingest_aaaaaaaa_first.pcap').read_bytes() == b'keep'


def test_changed_source_during_copy_never_publishes_partial(paths, monkeypatch):
    processed, upload = paths
    source = capture(processed)
    original_copy = replay.shutil.copyfileobj

    def mutate_after_copy(src, dst, length=0):
        original_copy(src, dst, length or 1024 * 1024)
        source.write_bytes(PCAP_MAGIC + b'changed' * 10)

    monkeypatch.setattr(replay.shutil, 'copyfileobj', mutate_after_copy)
    with pytest.raises(ValueError, match='changed'):
        replay.publish_processed_pcaps([source], upload)
    assert not list(upload.iterdir())
    assert not list(processed.parent.glob('.malcolm-reingest-*'))


def test_source_replaced_by_symlink_is_rejected_before_copy(paths, tmp_path):
    processed, upload = paths
    source = capture(processed)
    candidates = replay.find_processed_pcaps(processed, upload, 2)
    source.unlink()
    outside = capture(tmp_path, 'other.pcap')
    source.symlink_to(outside)
    with pytest.raises((ValueError, OSError)):
        replay.publish_processed_pcaps(candidates, upload)
    assert not list(upload.iterdir())


def test_empty_publish_has_no_side_effects(paths):
    processed, upload = paths
    assert replay.publish_processed_pcaps([], upload) == []
    assert not list(processed.parent.glob('.malcolm-reingest-*'))


def control(*args, cwd=ROOT):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    return subprocess.run(
        [sys.executable, str(ROOT / 'scripts' / 'control.py'), *args],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )


def compose_fixture(tmp_path):
    path = tmp_path / 'compose.yml'
    path.write_text(
        f'services:\n  pcap-monitor:\n    volumes:\n      - type: bind\n        source: {tmp_path}\n        target: /pcap\n'
    )
    return path


def test_control_preview_is_read_only_without_docker_or_config_bootstrap(paths, tmp_path):
    processed, upload = paths
    capture(processed, 'preview.pcap')
    compose = compose_fixture(tmp_path)
    # The test is allowed to show the configured bind path only, not invoke Docker.
    result = control('--file', str(compose), '--reingest-pcaps')
    assert result.returncode == 0, result.stderr
    assert 'preview.pcap' in result.stdout
    assert 'dry run' in result.stdout.lower()
    assert not list(upload.iterdir())


def test_control_rejects_wipe_and_reingest_combination(paths, tmp_path):
    compose = compose_fixture(tmp_path)
    result = control('--file', str(compose), '--wipe', '--reingest-pcaps', '--reingest-apply')
    assert result.returncode != 0
    assert not list(paths[1].iterdir())
    assert 'cannot be combined' in result.stderr.lower()


def test_apply_requires_explicit_reingest_request(paths, tmp_path):
    result = control('--reingest-apply', '--file', str(compose_fixture(tmp_path)))
    assert result.returncode != 0
    assert '--reingest-pcaps' in result.stderr


def test_control_apply_requires_flag_and_keeps_source(paths, tmp_path):
    processed, upload = paths
    source = capture(processed)
    compose = compose_fixture(tmp_path)
    result = control('--file', str(compose), '--reingest-pcaps', '--reingest-apply')
    assert result.returncode == 0, result.stderr
    assert source.exists()
    published = list(upload.iterdir())
    assert len(published) == 1
    assert published[0].read_bytes() == source.read_bytes()


def test_cli_invalid_limit_is_rejected_without_publishing(paths, tmp_path):
    processed, upload = paths
    capture(processed)
    result = control(
        '--file', str(compose_fixture(tmp_path)), '--reingest-pcaps', '--reingest-apply', '--reingest-limit', '101'
    )
    assert result.returncode != 0
    assert 'limit' in result.stderr.lower()
    assert list(upload.iterdir()) == []


def test_cli_replay_does_not_replay_prior_generated_copies(paths, tmp_path):
    processed, upload = paths
    capture(processed)
    fixture = compose_fixture(tmp_path)
    first = control('--file', str(fixture), '--reingest-pcaps', '--reingest-apply')
    assert first.returncode == 0, first.stderr
    staged = next(upload.iterdir())
    staged.rename(processed / staged.name)
    result = control('--file', str(fixture), '--reingest-pcaps')
    assert result.returncode == 0
    assert 'Dry run: 1 PCAP(s)' in result.stdout
    assert 'first.pcap' in result.stdout


def test_reingest_staging_cleanup_when_publishing_link_fails(paths, monkeypatch):
    processed, upload = paths
    source = capture(processed)

    def link_error(*args, **kwargs):
        raise OSError(18, 'Cross-device link')

    monkeypatch.setattr(replay.os, 'link', link_error)
    with pytest.raises(OSError, match='share a filesystem'):
        replay.publish_processed_pcaps([source], upload)
    assert source.exists()
    assert not list(upload.iterdir())
    assert not list(processed.parent.glob('.malcolm-reingest-*'))
