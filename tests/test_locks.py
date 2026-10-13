import json
from datetime import UTC, datetime, timedelta

import pytest

from fleet_rollout.locks import (
    LocalRunLock,
    LockHeld,
    LockOwner,
    acquire,
    force_release,
    lock_path,
    probe,
    release,
)
from fleet_rollout.testing import FakeExecutor

ROOT = "/srv/agent"
T0 = datetime(2026, 10, 12, 10, 0, tzinfo=UTC)


def owner(run="r-1", at=T0):
    return LockOwner(run_id=run, operator="ops.oncall", patch="support-greeting-v2",
                     acquired_at=at.isoformat())


@pytest.fixture
def fx():
    f = FakeExecutor("agent-01")
    f.mkdir(ROOT)
    return f


def test_acquire_writes_the_owner_into_the_target(fx):
    acquire(fx, ROOT, owner())
    data = json.loads(fx.files[lock_path(ROOT)])
    assert data["run_id"] == "r-1" and data["operator"] == "ops.oncall"
    assert lock_path(ROOT) == "/srv/agent/.fleet-rollout/lock"


def test_a_held_lock_refuses_a_second_run_and_names_the_holder(fx):
    acquire(fx, ROOT, owner("r-1"))
    with pytest.raises(LockHeld) as err:
        acquire(fx, ROOT, owner("r-2"), now=T0 + timedelta(minutes=5))
    assert err.value.holder.run_id == "r-1"
    assert not err.value.stale
    assert "r-1" in str(err.value)


def test_a_stale_lock_is_reported_as_stale_but_never_broken_automatically(fx):
    acquire(fx, ROOT, owner("r-1"))
    later = T0 + timedelta(hours=3)
    assert probe(fx, ROOT, now=later).state == "stale"
    with pytest.raises(LockHeld) as err:
        acquire(fx, ROOT, owner("r-2", later), now=later)
    assert err.value.stale and "unlock" in str(err.value)
    assert json.loads(fx.files[lock_path(ROOT)])["run_id"] == "r-1"


def test_probe_reports_free_and_held(fx):
    assert probe(fx, ROOT, now=T0).state == "free"
    acquire(fx, ROOT, owner())
    state = probe(fx, ROOT, now=T0 + timedelta(minutes=1))
    assert state.state == "held" and state.owner.run_id == "r-1" and state.age_seconds == 60


def test_unreadable_lock_content_counts_as_held(fx):
    fx.put(lock_path(ROOT), b"\x00garbage")
    state = probe(fx, ROOT, now=T0)
    assert state.state == "held" and state.owner is None


@pytest.mark.parametrize("stamp", ["2026-10-12T10:00:00", "not-a-date"])
def test_a_lock_with_an_unusable_timestamp_is_held_without_guessing_its_age(fx, stamp):
    data = LockOwner("r-1", "ops.oncall", "support-greeting-v2", stamp).to_bytes()
    fx.put(lock_path(ROOT), data)
    state = probe(fx, ROOT, now=T0 + timedelta(hours=3))
    assert state.state == "held" and state.age_seconds is None
    with pytest.raises(LockHeld) as err:
        acquire(fx, ROOT, owner("r-2"), now=T0 + timedelta(hours=3))
    assert not err.value.stale
    assert fx.files[lock_path(ROOT)] == data


@pytest.mark.parametrize("stamp", ["2026-10-12T10:00:00", "not-a-date"])
def test_a_local_lock_with_an_unusable_timestamp_still_refuses_another_run(tmp_path, stamp):
    lock = LocalRunLock(tmp_path / "run.lock")
    data = LockOwner("r-1", "ops.oncall", "support-greeting-v2", stamp).to_bytes()
    lock.path.write_bytes(data)
    with pytest.raises(LockHeld) as err:
        lock.acquire(owner("r-2"), now=T0 + timedelta(hours=3))
    assert err.value.age_seconds is None and not err.value.stale
    assert lock.path.read_bytes() == data


def test_release_only_removes_our_own_lock(fx):
    acquire(fx, ROOT, owner("r-1"))
    assert release(fx, ROOT, "r-2") is False
    assert lock_path(ROOT) in fx.files
    assert release(fx, ROOT, "r-1") is True
    assert lock_path(ROOT) not in fx.files


def test_force_release_is_the_break_glass(fx):
    acquire(fx, ROOT, owner("r-1"))
    assert force_release(fx, ROOT).run_id == "r-1"
    assert probe(fx, ROOT, now=T0).state == "free"


def test_local_run_lock_is_exclusive(tmp_path):
    first = LocalRunLock(tmp_path / "run.lock")
    first.acquire(owner("r-1"))
    with pytest.raises(LockHeld, match="r-1"):
        LocalRunLock(tmp_path / "run.lock").acquire(owner("r-2"), now=T0)
    first.release("r-1")
    LocalRunLock(tmp_path / "run.lock").acquire(owner("r-3"))


def test_local_run_lock_reports_staleness(tmp_path):
    LocalRunLock(tmp_path / "run.lock").acquire(owner("r-1"))
    with pytest.raises(LockHeld) as err:
        LocalRunLock(tmp_path / "run.lock").acquire(owner("r-2"), now=T0 + timedelta(hours=5))
    assert err.value.stale
