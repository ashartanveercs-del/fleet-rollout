"""Locks: one per target (on the target itself) and one per state directory (local).

The target lock lives at `<root>/.fleet-rollout/lock` and is taken with an atomic
exclusive create, so two operators, two CI jobs, or a rollout and a manual rollback can
never mutate the same agent at once, even from different machines.

A crashed run leaves its lock behind. That is the safe failure: the lock is reported as
STALE after a while, with the holder's run id and a break-glass command, but it is never
broken automatically. A tool that "helpfully" steals old locks is how two runs end up
interleaving writes to the same file.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from .executors.base import Executor
from .validation import RESERVED_DIR

STALE_AFTER_SECONDS = 2 * 3600


@dataclass(frozen=True)
class LockOwner:
    run_id: str
    operator: str
    patch: str
    acquired_at: str      # ISO 8601, UTC

    def to_bytes(self) -> bytes:
        return json.dumps(asdict(self), sort_keys=True).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> LockOwner | None:
        try:
            doc = json.loads(data)
            return cls(run_id=str(doc["run_id"]), operator=str(doc["operator"]),
                       patch=str(doc["patch"]), acquired_at=str(doc["acquired_at"]))
        except (ValueError, KeyError, TypeError):
            return None


@dataclass(frozen=True)
class LockState:
    state: str                    # "free" | "held" | "stale"
    owner: LockOwner | None = None
    age_seconds: int | None = None


class LockHeld(RuntimeError):
    def __init__(self, where: str, holder: LockOwner | None, age_seconds: int | None,
                 stale: bool, unlock_hint: str) -> None:
        self.holder, self.age_seconds, self.stale = holder, age_seconds, stale
        who = (f"run {holder.run_id} ({holder.operator}, patch {holder.patch})"
               if holder else "an unreadable lock file")
        age = f" for {age_seconds}s" if age_seconds is not None else ""
        message = f"{where} is locked by {who}{age}"
        if stale:
            message += (f"; the lock is STALE. If that run is really dead, break it with "
                        f"`{unlock_hint}`")
        super().__init__(message)


def _now(now: datetime | None) -> datetime:
    return now or datetime.now(UTC)


def _age(owner: LockOwner | None, now: datetime) -> int | None:
    if owner is None:
        return None
    try:
        acquired = datetime.fromisoformat(owner.acquired_at)
        if acquired.tzinfo is None:
            return None  # do not guess a zone, a staleness age, or permission to break it
        return int((now - acquired).total_seconds())
    except ValueError:
        return None


def lock_path(root: str) -> str:
    return f"{root}/{RESERVED_DIR}/lock"


def probe(executor: Executor, root: str, *, now: datetime | None = None,
          stale_after: int = STALE_AFTER_SECONDS) -> LockState:
    data = executor.read(lock_path(root))
    if data is None:
        return LockState("free")
    owner = LockOwner.from_bytes(data)
    age = _age(owner, _now(now))
    stale = age is not None and age > stale_after
    return LockState("stale" if stale else "held", owner, age)


def acquire(executor: Executor, root: str, owner: LockOwner, *, now: datetime | None = None,
            stale_after: int = STALE_AFTER_SECONDS) -> None:
    if executor.create_exclusive(lock_path(root), owner.to_bytes()):
        return
    state = probe(executor, root, now=now, stale_after=stale_after)
    raise LockHeld(f"target {executor.name}", state.owner, state.age_seconds,
                   state.state == "stale",
                   f"fleet-rollout unlock {executor.name} --ticket <id>")


def release(executor: Executor, root: str, run_id: str) -> bool:
    """Remove the lock only if this run holds it."""
    data = executor.read(lock_path(root))
    owner = LockOwner.from_bytes(data) if data is not None else None
    if owner is None or owner.run_id != run_id:
        return False
    executor.remove(lock_path(root))
    return True


def force_release(executor: Executor, root: str) -> LockOwner | None:
    """Break-glass: remove whatever lock is there and return who held it."""
    data = executor.read(lock_path(root))
    executor.remove(lock_path(root))
    return LockOwner.from_bytes(data) if data is not None else None


class LocalRunLock:
    """One rollout per state directory, so ledger appends never interleave."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def acquire(self, owner: LockOwner, *, now: datetime | None = None,
                stale_after: int = STALE_AFTER_SECONDS) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            holder = self.holder()
            age = _age(holder, _now(now))
            raise LockHeld(f"state directory {self.path.parent}", holder, age,
                           age is not None and age > stale_after,
                           "fleet-rollout unlock --run-lock") from None
        with os.fdopen(fd, "wb") as handle:
            handle.write(owner.to_bytes())
            handle.flush()
            os.fsync(handle.fileno())

    def holder(self) -> LockOwner | None:
        try:
            return LockOwner.from_bytes(self.path.read_bytes())
        except OSError:
            return None

    def release(self, run_id: str) -> bool:
        holder = self.holder()
        if holder is None or holder.run_id != run_id:
            return False
        self.path.unlink()
        return True

    def force_release(self) -> LockOwner | None:
        holder = self.holder()
        self.path.unlink(missing_ok=True)
        return holder
