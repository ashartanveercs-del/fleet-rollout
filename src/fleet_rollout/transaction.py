"""One target, one patch, all or nothing.

    preflight (read-only)  ->  for each step:
        jail re-check on the target (symlinks, real paths)
        back up the current bytes (checksummed, logged *before* the mutation)
        re-check the pre-state (the file may have changed since preflight)
        stage the new bytes next to the file, read them back, run the syntax gate
        atomic rename over the live file, read the live file back
    ->  health gate (status AND body)  ->  verify assertions  ->  applied marker (last)

Any failure, at any point, restores every file this transaction backed up, newest
first, proving each restore by checksum, re-runs the agent reload if the patch has
one, and re-checks health. A restore that cannot be proven is reported as a partial
failure with the exact files that are still wrong; it is never reported as success.
"""

from __future__ import annotations

import contextlib
import json
import posixpath
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime

from . import scripts
from .backup import BackupCorrupt, BackupEntry, BackupStore, Manifest
from .executors.base import Executor, ExecutorError, PathInfo
from .fleet import Target
from .health import HealthResult, check_health
from .locks import probe as probe_lock
from .spec import AppendBlock, Patch, RunCommand, SqlUpsert, Step, WriteFile, sha256
from .syntax import check_staged
from .validation import RESERVED_DIR, join_root

MIN_FREE_BYTES = 64 * 1024 * 1024


def marker_path(root: str, patch_id: str) -> str:
    return f"{root}/{RESERVED_DIR}/applied/{patch_id}.json"


class StepFailed(Exception):
    def __init__(self, label: str, detail: str) -> None:
        super().__init__(detail)
        self.label = label
        self.detail = detail

    def __str__(self) -> str:
        return self.detail


@dataclass(frozen=True)
class StepReport:
    label: str
    ok: bool
    detail: str


@dataclass(frozen=True)
class RestoreReport:
    ok: bool
    restored: tuple[str, ...]
    failed: tuple[str, ...]
    health: HealthResult | None
    detail: str


@dataclass(frozen=True)
class PreflightReport:
    target: str
    ok: bool
    already_applied: bool
    problems: tuple[str, ...]
    notes: tuple[str, ...]


@dataclass(frozen=True)
class TargetOutcome:
    target: str
    ok: bool
    steps: tuple[StepReport, ...]
    failed_step: str | None = None
    error: str | None = None
    restore: RestoreReport | None = None
    health: HealthResult | None = None


class TargetTransaction:
    def __init__(self, target: Target, executor: Executor, patch: Patch, store: BackupStore,
                 *, run_id: str, operator: str, clock: Callable[[], datetime],
                 sleep: Callable[[float], None] = time.sleep, allow_drift: bool = False,
                 min_free_bytes: int = MIN_FREE_BYTES) -> None:
        self.target = target
        self.ex = executor
        self.patch = patch
        self.store = store
        self.run_id = run_id
        self.operator = operator
        self.clock = clock
        self.sleep = sleep
        self.allow_drift = allow_drift
        self.min_free_bytes = min_free_bytes
        self._root_real: str | None = None
        self._recorded: list[BackupEntry] = []

    @property
    def root(self) -> str:
        return self.target.root

    @property
    def recorded(self) -> list[BackupEntry]:
        """Backups taken by the most recent `apply()` (what a restore would undo)."""
        return list(self._recorded)

    def path(self, rel: str) -> str:
        return join_root(self.root, rel)

    # -- the jail, re-checked against the real filesystem ------------------------------

    def _root_realpath(self) -> str:
        if self._root_real is None:
            info = self.ex.inspect(self.root)
            if not info.is_dir:
                raise StepFailed("workspace", f"workspace root {self.root} is not a directory "
                                              f"on {self.target.name}")
            self._root_real = info.realpath or self.root
        return self._root_real

    def _inside(self, real: str) -> bool:
        return real.startswith(self._root_realpath() + "/")

    def _jail_check(self, path: str, label: str, *, allow_dir: bool = False) -> PathInfo:
        """A validated path string proves nothing about the disk: refuse symlinks, and
        refuse anything whose resolved location is outside the workspace."""
        info = self.ex.inspect(path)
        if info.is_symlink:
            raise StepFailed(label, f"{path} is a symlink; refusing to write through it")
        if info.is_dir and not allow_dir:
            raise StepFailed(label, f"{path} is a directory")
        if info.realpath:
            if not self._inside(info.realpath):
                raise StepFailed(label, f"{path} resolves to {info.realpath}, outside the "
                                        f"workspace {self.root}")
            return info
        ancestor = posixpath.dirname(path)      # unresolvable: check the nearest real parent
        while ancestor not in ("", "/"):
            parent = self.ex.inspect(ancestor)
            if parent.exists:
                real = parent.realpath
                if not (real == self._root_realpath() or self._inside(real)):
                    raise StepFailed(label, f"{ancestor} resolves to {real}, outside the "
                                            f"workspace {self.root}")
                break
            ancestor = posixpath.dirname(ancestor)
        return info

    def _require_parent(self, path: str, label: str) -> None:
        parent = posixpath.dirname(path)
        if not self.ex.inspect(parent).is_dir:
            raise StepFailed(label, f"parent directory {parent} does not exist; add a "
                                    "make_dirs step before this one")

    # -- backup, drift guard and install -------------------------------------------------

    def _backup(self, step_index: int, path: str, manifest: Manifest) -> bytes | None:
        current = self.ex.read(path)
        entry = BackupEntry(step_index, path,
                            self.store.put(current) if current is not None else None)
        manifest.record(entry)              # durable *before* anything is mutated
        self._recorded.append(entry)
        return current

    def _drift_guard(self, step: WriteFile | AppendBlock, path: str, current: bytes | None,
                     label: str) -> str | None:
        expect = step.expect_sha256
        if not expect:
            return None
        actual = sha256(current) if current is not None else "absent"
        if actual == expect:
            return None
        if isinstance(step, WriteFile) and actual == step.content_sha256:
            return "already holds the shipped bytes (resumed apply)"
        if isinstance(step, AppendBlock) and current and step.marker.encode() in current:
            return "already holds the marker (resumed apply)"
        message = (f"pre-state drift on {path}: sha256 {actual[:12]} is not the expected "
                   f"{expect[:12]}; it was changed after the patch was written")
        if self.allow_drift:
            return f"DRIFT OVERRIDE: {message}"
        raise StepFailed(label, message + " (refusing to overwrite it; --allow-drift overrides)")

    def _staged_path(self, path: str) -> str:
        directory, name = posixpath.split(path)
        return f"{directory}/.{name[:100]}.rollout-{self.patch.id}.tmp"

    def _stage(self, path: str, data: bytes, label: str) -> str:
        staged = self._staged_path(path)
        self.ex.remove(staged)              # debris from a crash, or a planted symlink
        if not self.ex.create_exclusive(staged, data):
            raise StepFailed(label, f"staging path {staged} appeared concurrently")
        return staged

    def _swap_in(self, path: str, data: bytes, label: str,
                 gate: Callable[[str, bytes], str | None] | None = None) -> None:
        """Stage `data` next to `path`, prove the staged bytes, run the optional gate,
        rename over `path`, then prove the live bytes. Used for installs and restores."""
        staged = self._stage(path, data, label)
        try:
            back = self.ex.read(staged)
            if back is None or sha256(back) != sha256(data):
                raise StepFailed(label, "the staged copy did not read back intact "
                                        "(corrupted in transit?)")
            problem = gate(staged, back) if gate else None
            if problem:
                raise StepFailed(label, problem)
            self.ex.rename(staged, path)
        except BaseException:
            with contextlib.suppress(ExecutorError):
                self.ex.remove(staged)
            raise
        live = self.ex.read(path)
        if live is None or sha256(live) != sha256(data):
            raise StepFailed(label, f"read-back of {path} after the swap does not match "
                                    "what was written")

    def _install(self, path: str, data: bytes, *, rel: str, needs_compile: bool,
                 label: str) -> None:
        def syntax_gate(staged: str, back: bytes) -> str | None:
            problem = check_staged(self.ex, staged, rel, back, needs_compile=needs_compile)
            return f"syntax gate: {problem}" if problem else None

        self._swap_in(path, data, label, syntax_gate)

    # -- step kinds -------------------------------------------------------------------

    def _write_file(self, step: WriteFile, manifest: Manifest) -> str:
        path = self.path(step.dest)
        self._jail_check(path, step.label)
        self._require_parent(path, step.label)
        current = self._backup(step.index, path, manifest)
        note = self._drift_guard(step, path, current, step.label)
        if current == step.content:
            return note or "already holds the shipped bytes (no change)"
        self._install(path, step.content, rel=step.dest, needs_compile=step.needs_compile,
                      label=step.label)
        return note or f"swapped in {len(step.content)} bytes ({step.content_sha256[:12]})"

    def _append_block(self, step: AppendBlock, manifest: Manifest) -> str:
        path = self.path(step.dest)
        self._jail_check(path, step.label)
        self._require_parent(path, step.label)
        current = self._backup(step.index, path, manifest)
        note = self._drift_guard(step, path, current, step.label)
        marker = step.marker.encode("utf-8")
        count = (current or b"").count(marker)
        if count > 1:
            raise StepFailed(step.label, f"{path} already contains the marker {count} times; "
                                         "refusing to append to a file in an unknown state")
        if count == 1:
            return note or "marker already present (no change)"
        self._install(path, step.appended_to(current or b""), rel=step.dest,
                      needs_compile=step.needs_compile, label=step.label)
        found = (self.ex.read(path) or b"").count(marker)
        if found != 1:
            raise StepFailed(step.label, f"expected exactly one marker after the append, "
                                         f"found {found}")
        return note or "appended"

    def _sql_upsert(self, step: SqlUpsert, manifest: Manifest) -> str:
        path = self.path(step.db)
        info = self._jail_check(path, step.label)
        if not info.is_file:
            raise StepFailed(step.label, f"database {path} does not exist")
        if self.ex.read(path + "-wal"):
            raise StepFailed(step.label, f"{path} has a non-empty write-ahead log, so a byte "
                                         "backup would not be a consistent snapshot; "
                                         "checkpoint it first")
        self._backup(step.index, path, manifest)
        result = self.ex.run(["python3", "-c", scripts.SQL_UPSERT],
                             stdin=json.dumps(step.payload(path)).encode("utf-8"))
        if not result.ok:
            reasons = {3: f"database {path} does not exist",
                       4: f"table {step.table!r} does not exist",
                       5: "an identifier was refused by the on-target check",
                       6: "the row did not read back as written"}
            raise StepFailed(step.label, reasons.get(result.returncode, result.summary()))
        try:
            row = json.loads(result.stdout).get("row")
        except (ValueError, AttributeError):
            raise StepFailed(step.label, "the upsert returned an unreadable read-back") from None
        if row != dict(step.values):
            raise StepFailed(step.label, f"read-back {row!r} != {dict(step.values)!r}")
        return f"upserted {step.table} row {step.key_column}={step.key!r}"

    def _run(self, step: RunCommand, manifest: Manifest) -> str:
        paths = [self.path(rel) for rel in step.command.args]
        for path in paths:
            self._jail_check(path, step.label, allow_dir=True)
        result = self.ex.run(step.command.argv(self.root))
        if not result.ok:
            raise StepFailed(step.label, f"{step.command.name} failed: {result.summary()}")
        verify = step.command.spec.verify
        for path in paths:
            if verify == "is_dir" and not self.ex.inspect(path).is_dir:
                raise StepFailed(step.label, f"{path} is not a directory afterwards")
            if verify == "is_executable" and not self.ex.run(["test", "-x", path]).ok:
                raise StepFailed(step.label, f"{path} is not executable afterwards")
        return f"ran {step.command.name}"

    _STEPS: dict[type, Callable[..., str]] = {
        WriteFile: _write_file, AppendBlock: _append_block, SqlUpsert: _sql_upsert,
        RunCommand: _run,
    }

    # -- finishing ----------------------------------------------------------------------

    def _verify_assertions(self) -> None:
        for check in self.patch.verify:
            data = self.ex.read(self.path(check.file))
            if data is None or check.text.encode("utf-8") not in data:
                raise StepFailed("verify", f"{check.file} does not contain {check.text!r}")

    def _write_marker(self) -> None:
        path = marker_path(self.root, self.patch.id)
        data = json.dumps({"patch": self.patch.id, "digest": self.patch.digest,
                           "run": self.run_id, "operator": self.operator,
                           "applied_at": self.clock().isoformat()}, sort_keys=True).encode()
        self.ex.remove(path)
        if not self.ex.create_exclusive(path, data) or self.ex.read(path) != data:
            raise StepFailed("applied marker", f"could not record {path}")

    # -- public API ----------------------------------------------------------------------

    def apply(self) -> TargetOutcome:
        manifest = self.store.manifest(self.run_id, self.target.name)
        self._recorded = []
        reports: list[StepReport] = []
        label = "workspace"
        health: HealthResult | None = None
        try:
            self._root_realpath()
            for step in self.patch.steps:
                label = step.label
                reports.append(StepReport(label, True, self._STEPS[type(step)](self, step,
                                                                                manifest)))
            label = "health gate"
            health = check_health(self.ex, self.target.health, sleep=self.sleep)
            if not health.ok:
                raise StepFailed(label, health.detail)
            reports.append(StepReport(label, True, health.detail))
            label = "verify"
            self._verify_assertions()
            label = "applied marker"
            self._write_marker()
        except KeyboardInterrupt:
            self.restore(self._recorded)
            raise
        except Exception as exc:  # any failure at all must end in a restore
            failed = exc.label if isinstance(exc, StepFailed) else label
            detail = str(exc) if isinstance(exc, StepFailed | ExecutorError | BackupCorrupt) \
                else f"{type(exc).__name__}: {exc}"
            reports.append(StepReport(failed, False, detail))
            return TargetOutcome(self.target.name, False, tuple(reports), failed, detail,
                                 self.restore(self._recorded), health)
        return TargetOutcome(self.target.name, True, tuple(reports), health=health)

    def restore(self, entries: Iterable[BackupEntry]) -> RestoreReport:
        restored: list[str] = []
        failed: list[str] = []
        marker = marker_path(self.root, self.patch.id)
        try:  # first: an uncleared marker would make the next run skip this target
            self.ex.remove(marker)
            if self.ex.read(marker) is not None:
                failed.append(f"applied marker {marker} is still present")
        except ExecutorError as exc:
            failed.append(f"applied marker {marker}: {exc}")
        first: dict[str, BackupEntry] = {}
        for entry in entries:
            first.setdefault(entry.path, entry)     # the earliest record is the pre-state
        for entry in sorted(first.values(), key=lambda e: e.step, reverse=True):
            try:
                self._restore_one(entry)
                restored.append(entry.path)
            except (ExecutorError, BackupCorrupt, StepFailed) as exc:
                failed.append(f"{entry.path}: {exc}")
        for step in self.patch.steps:
            if isinstance(step, RunCommand) and step.command.spec.rerun_on_restore:
                try:
                    result = self.ex.run(step.command.argv(self.root))
                    if not result.ok:
                        failed.append(f"{step.command.name} after restore: {result.summary()}")
                except ExecutorError as exc:
                    failed.append(f"{step.command.name} after restore: {exc}")
        health = check_health(self.ex, self.target.health, sleep=self.sleep)
        ok = not failed and health.ok
        if ok:
            detail = f"restored {len(restored)} file(s), each verified by checksum; healthy"
        else:
            parts = []
            if failed:
                parts.append(f"COULD NOT RESTORE: {'; '.join(failed)}")
            if not health.ok:
                parts.append(f"unhealthy after restore: {health.detail}")
            detail = "PARTIAL RESTORE - " + " | ".join(parts)
        return RestoreReport(ok, tuple(restored), tuple(failed), health, detail)

    def _restore_one(self, entry: BackupEntry) -> None:
        if entry.sha_before is None:            # the transaction created this file
            self.ex.remove(entry.path)
            if self.ex.inspect(entry.path).exists:
                raise StepFailed("restore", "the file this patch created could not be removed")
            return
        info = self.ex.inspect(entry.path)
        if info.is_symlink:
            raise StepFailed("restore", "the path became a symlink; not restoring through it")
        current = self.ex.read(entry.path) if info.exists else None
        if current is not None and sha256(current) == entry.sha_before:
            return                              # never changed: already the pre-state
        data = self.store.get(entry.sha_before)     # refuses a backup that fails its checksum
        self._swap_in(entry.path, data, "restore")

    def preflight(self) -> PreflightReport:
        """Read-only checks; run against every target before any target is touched."""
        problems: list[str] = []
        notes: list[str] = []
        already = False
        try:
            self._root_realpath()
            lock = probe_lock(self.ex, self.root, now=self.clock())
            if lock.state != "free":
                holder = (f"run {lock.owner.run_id} ({lock.owner.operator})" if lock.owner
                          else "an unreadable lock file")
                problems.append(f"target lock is {lock.state.upper()}, held by {holder}")
            raw = self.ex.read(marker_path(self.root, self.patch.id))
            if raw is not None:
                try:
                    digest = json.loads(raw).get("digest")
                except (ValueError, AttributeError):
                    digest = None
                if digest == self.patch.digest:
                    already = True
                else:
                    problems.append(f"an applied marker for {self.patch.id} records different "
                                    f"content (digest {str(digest)[:12]}); a patch id must "
                                    "never be reused for new content")
            if not already:
                free = self.ex.free_bytes(self.root)
                payload = sum(len(s.content) if isinstance(s, WriteFile) else
                              len(s.block) if isinstance(s, AppendBlock) else 0
                              for s in self.patch.steps)
                needed = max(self.min_free_bytes, 2 * payload)
                if free < needed:
                    problems.append(f"only {free} bytes free under {self.root}; need {needed}")
                for step in self.patch.steps:
                    self._preflight_step(step, problems, notes)
            health = check_health(self.ex, self.target.health, sleep=self.sleep)
            if not health.ok:
                problems.append(f"unhealthy before we touched it: {health.detail}")
        except (ExecutorError, StepFailed) as exc:
            problems.append(f"unreachable or unreadable: {exc}")
        return PreflightReport(self.target.name, not problems, already, tuple(problems),
                               tuple(notes))

    def _preflight_step(self, step: Step, problems: list[str], notes: list[str]) -> None:
        try:
            if isinstance(step, RunCommand):
                for rel in step.command.args:
                    self._jail_check(self.path(rel), step.label, allow_dir=True)
                return
            path = self.path(step.dest)
            self._jail_check(path, step.label)
            if isinstance(step, WriteFile | AppendBlock) and step.expect_sha256:
                note = self._drift_guard(step, path, self.ex.read(path), step.label)
                if note:
                    notes.append(f"{step.label}: {note}")
        except StepFailed as exc:
            problems.append(f"{exc.label}: {exc.detail}")
