import hashlib

import pytest

from fleet_rollout.backup import BackupCorrupt, BackupEntry, BackupStore
from fleet_rollout.validation import ValidationError


def test_objects_are_content_addressed_and_verified(tmp_path):
    store = BackupStore(tmp_path / "backups")
    sha = store.put(b"original greeting\n")
    assert sha == hashlib.sha256(b"original greeting\n").hexdigest()
    assert store.get(sha) == b"original greeting\n"


def test_identical_content_is_stored_once(tmp_path):
    store = BackupStore(tmp_path / "backups")
    first = store.put(b"same")
    second = store.put(b"same")
    assert first == second
    assert len(list((tmp_path / "backups" / "objects").rglob("*"))) == 2  # fan-out dir + file


def test_a_tampered_backup_is_detected_before_it_is_restored(tmp_path):
    store = BackupStore(tmp_path / "backups")
    sha = store.put(b"original")
    store.object_path(sha).write_bytes(b"tampered")
    with pytest.raises(BackupCorrupt, match="checksum"):
        store.get(sha)


def test_a_missing_backup_is_an_error_not_an_empty_file(tmp_path):
    store = BackupStore(tmp_path / "backups")
    with pytest.raises(BackupCorrupt, match="missing"):
        store.get("0" * 64)


def test_manifest_records_entries_in_order_including_absent_files(tmp_path):
    store = BackupStore(tmp_path / "backups")
    manifest = store.manifest("r-20261012t100000z-ab12", "agent-01")
    assert manifest.entries() == []
    manifest.record(BackupEntry(step=0, path="/srv/agent/config/a.txt", sha_before="a" * 64))
    manifest.record(BackupEntry(step=1, path="/srv/agent/config/new.txt", sha_before=None))
    reopened = store.manifest("r-20261012t100000z-ab12", "agent-01")
    assert reopened.entries() == [
        BackupEntry(0, "/srv/agent/config/a.txt", "a" * 64),
        BackupEntry(1, "/srv/agent/config/new.txt", None)]


def test_a_torn_final_line_from_a_crash_is_ignored(tmp_path):
    store = BackupStore(tmp_path / "backups")
    manifest = store.manifest("r-1", "agent-01")
    manifest.record(BackupEntry(step=0, path="/srv/agent/a.txt", sha_before=None))
    with manifest.path.open("ab") as handle:
        handle.write(b'{"step": 1, "path": "/srv/ag')
    assert len(manifest.entries()) == 1


def test_corruption_in_the_middle_of_a_manifest_is_fatal(tmp_path):
    store = BackupStore(tmp_path / "backups")
    manifest = store.manifest("r-1", "agent-01")
    manifest.record(BackupEntry(step=0, path="/srv/agent/a.txt", sha_before=None))
    with manifest.path.open("ab") as handle:
        handle.write(b"garbage\n")
    manifest.record(BackupEntry(step=1, path="/srv/agent/b.txt", sha_before=None))
    with pytest.raises(BackupCorrupt, match="line 2"):
        manifest.entries()


def test_run_ids_and_target_names_cannot_escape_the_backup_dir(tmp_path):
    store = BackupStore(tmp_path / "backups")
    with pytest.raises(ValidationError):
        store.manifest("../../etc", "agent-01")
    with pytest.raises(ValidationError):
        store.manifest("r-1", "../agent")
