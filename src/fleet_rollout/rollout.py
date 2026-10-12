"""Rollouts across the fleet: plan the waves, check every gate, then go one target at
a time and stop at the first red.

    canary  ->  one target per remaining cohort  ->  everything else

Before the first byte is written anywhere:
  * customer-owned targets are held back unless explicitly included, and an included
    one needs two distinct approvals for this exact patch digest;
  * the change ticket must be valid, unexpired and cover every target;
  * the state directory's run lock is taken and the ledger must verify;
  * a halted patch, or a patch id reused for different content, is refused;
  * interrupted transactions from a crashed run are undone from their backup log;
  * every remaining target is preflighted (reachable, healthy, unlocked, no drift).

Then each target runs as a transaction under its own lock, bracketed by `started` and a
terminal ledger record. The first failure rolls that target back, writes a `halt` record
and stops the rollout; later targets are never touched.
"""

from __future__ import annotations

import contextlib
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .consent import ApprovalStore, consent_problem
from .drift import golden_lag
from .executors.base import Executor, ExecutorError
from .fleet import Fleet, Target
from .health import check_health
from .ledger import LedgerCorrupt, LedgerRecord
from .locks import LockHeld, LockOwner, acquire, force_release, release
from .spec import Patch
from .state import StateDir
from .tickets import Ticket, ticket_problem
from .transaction import PreflightReport, RestoreReport, TargetOutcome, TargetTransaction
from .validation import ValidationError, person_name, single_line

ExecutorFactory = Callable[[Target], Executor]
Clock = Callable[[], datetime]


class RolloutError(ValueError):
    """Refused before anything was touched."""


def new_run_id(now: datetime) -> str:
    return f"r-{now.astimezone(UTC):%Y%m%dt%H%M%Sz}-{secrets.token_hex(2)}"


# -- planning --------------------------------------------------------------------------


@dataclass(frozen=True)
class Wave:
    name: str
    targets: tuple[Target, ...]


def _internal_first(targets: Sequence[Target]) -> list[Target]:
    return sorted(targets, key=lambda t: t.customer_owned)     # stable: keeps fleet order


def plan_waves(targets: Sequence[Target], *, canary: str | None = None) -> list[Wave]:
    """Canary, then one lead per cohort the canary does not cover, then the rest.
    Internal targets go before customer-owned ones within every wave."""
    targets = list(targets)
    if not targets:
        return []
    if canary is not None:
        chosen = next((t for t in targets if t.name == canary), None)
        if chosen is None:
            raise RolloutError(f"canary {canary!r} is not one of the targets in this rollout")
        if chosen.customer_owned:
            raise RolloutError(f"canary {canary!r} is customer-owned; the canary is the target "
                               "you are willing to break")
    else:
        chosen = (next((t for t in targets if t.canary and not t.customer_owned), None)
                  or next((t for t in targets if not t.customer_owned), None))
        if chosen is None:
            raise RolloutError("every selected target is customer-owned, so there is no canary "
                               "you are willing to break; include an internal target")
    seen = {chosen.cohort}
    leads = []
    for t in targets:
        if t.cohort in seen:
            continue
        seen.add(t.cohort)
        cohort = [c for c in targets if c.cohort == t.cohort]
        leads.append(next((c for c in cohort if not c.customer_owned), cohort[0]))
    used = {chosen.name} | {t.name for t in leads}
    waves = [Wave("canary", (chosen,)), Wave("cohort leads", tuple(_internal_first(leads))),
             Wave("remaining", tuple(_internal_first([t for t in targets if t.name not in used])))]
    return [w for w in waves if w.targets]


@dataclass(frozen=True)
class RolloutPlan:
    patch: Patch
    waves: tuple[Wave, ...]
    held_back: tuple[tuple[str, str], ...] = ()
    blocked: tuple[tuple[str, str], ...] = ()
    warnings: tuple[str, ...] = ()
    approvals: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def targets(self) -> tuple[Target, ...]:
        return tuple(t for wave in self.waves for t in wave.targets)

    @property
    def executable(self) -> bool:
        return bool(self.targets) and not self.blocked


def build_plan(fleet: Fleet, patch: Patch, *, approvals: ApprovalStore, now: datetime,
               names: Sequence[str] | None = None, canary: str | None = None,
               include_customer: bool = False) -> RolloutPlan:
    held, blocked, eligible = [], [], []
    approved: dict[str, tuple[str, ...]] = {}
    for target in fleet.select(names):
        problem = consent_problem(target, digest=patch.digest, store=approvals, now=now,
                                  include_customer=include_customer)
        if target.customer_owned and not include_customer:
            held.append((target.name, problem or ""))
            continue
        if problem:
            blocked.append((target.name, problem))
        elif target.customer_owned:
            approved[target.name] = tuple(sorted(
                a.approver for a in approvals.valid(digest=patch.digest, target=target.name,
                                                    now=now)))
        eligible.append(target)
    warnings: list[str] = []
    if fleet.golden_dir is not None:
        for target in eligible:
            for warning in golden_lag(fleet.golden_dir, patch, target):
                if warning not in warnings:
                    warnings.append(warning)
    return RolloutPlan(patch=patch, waves=tuple(plan_waves(eligible, canary=canary)),
                       held_back=tuple(held), blocked=tuple(blocked),
                       warnings=tuple(warnings), approvals=approved)


# -- running ---------------------------------------------------------------------------


@dataclass
class TargetRun:
    target: str
    status: str               # "verified" | "skipped" | "rolled_back" | "rollback_failed"
    detail: str
    outcome: TargetOutcome | None = None


@dataclass
class RolloutReport:
    run_id: str
    patch: str
    ok: bool = False
    refused: bool = False      # stopped by a gate before anything (even the ledger) changed
    aborted: str | None = None
    halted_at: str | None = None
    preflight: list[PreflightReport] = field(default_factory=list)
    results: list[TargetRun] = field(default_factory=list)
    recovered: list[str] = field(default_factory=list)


class Rollout:
    def __init__(self, fleet: Fleet, plan: RolloutPlan, *, executor_for: ExecutorFactory,
                 state: StateDir, operator: str, ticket: Ticket, clock: Clock,
                 sleep: Callable[[float], None] = time.sleep, allow_drift: bool = False,
                 bake_seconds: float = 0.0, run_id: str | None = None) -> None:
        self.fleet = fleet
        self.plan = plan
        self.patch = plan.patch
        self.executor_for = executor_for
        self.state = state
        self.ledger = state.ledger()
        self.operator = person_name(operator, where="operator")
        self.ticket = ticket
        self.clock = clock
        self.sleep = sleep
        self.allow_drift = allow_drift
        self.bake_seconds = bake_seconds
        self.run_id = run_id or new_run_id(clock())
        self._executors: dict[str, Executor] = {}

    # -- plumbing ---------------------------------------------------------------------

    def _ex(self, target: Target) -> Executor:
        if target.name not in self._executors:
            self._executors[target.name] = self.executor_for(target)
        return self._executors[target.name]

    def _tx(self, target: Target) -> TargetTransaction:
        return TargetTransaction(target, self._ex(target), self.patch, self.state.backups(),
                                 run_id=self.run_id, operator=self.operator, clock=self.clock,
                                 sleep=self.sleep, allow_drift=self.allow_drift)

    def _owner(self) -> LockOwner:
        return LockOwner(self.run_id, self.operator, self.patch.id, self.clock().isoformat())

    def _log(self, event: str, target: str | None = None, detail: str = "",
             halt: bool = False, extra: dict | None = None) -> LedgerRecord:
        return self.ledger.append(run=self.run_id, event=event, operator=self.operator,
                                  ts=self.clock(), patch=self.patch.id,
                                  digest=self.patch.digest, target=target, detail=detail,
                                  halt=halt, ticket=self.ticket.id, extra=extra)

    def _refuse(self, report: RolloutReport, message: str) -> RolloutReport:
        report.aborted = message
        report.refused = True
        return report

    def _abort(self, report: RolloutReport, message: str, *, halt: bool = False,
               target: str | None = None) -> RolloutReport:
        report.aborted = message
        try:
            self._log("run_aborted", target, message, halt=halt)
        except (OSError, LedgerCorrupt) as exc:
            report.aborted += f" (and the abort could not be recorded in the ledger: {exc})"
        return report

    # -- the run ------------------------------------------------------------------------

    def run(self) -> RolloutReport:
        report = RolloutReport(self.run_id, self.patch.id)
        if not self.plan.targets:
            return self._refuse(report, "no targets selected")
        if self.plan.blocked:
            return self._refuse(report, "consent missing: "
                                + "; ".join(reason for _, reason in self.plan.blocked))
        problem = ticket_problem(self.ticket, self.plan.targets, self.clock())
        if problem:
            return self._refuse(report, problem)
        run_lock = self.state.run_lock()
        try:
            run_lock.acquire(self._owner(), now=self.clock())
        except LockHeld as exc:
            return self._refuse(report, str(exc))
        try:
            return self._run_locked(report)
        except (OSError, LedgerCorrupt) as exc:
            report.aborted = (f"the ledger could not be written ({exc}); stopping. Targets "
                              "already handled keep the state the ledger shows for them")
            return report
        except BaseException as exc:
            if not isinstance(exc, Exception):          # Ctrl-C, SystemExit, ...
                with contextlib.suppress(Exception):
                    self._log("run_aborted", detail=f"interrupted by {type(exc).__name__}")
            raise
        finally:
            run_lock.release(self.run_id)

    def _run_locked(self, report: RolloutReport) -> RolloutReport:
        check = self.ledger.verify()
        if not check.ok:
            return self._refuse(report, f"the ledger does not verify ({check.problem}); nothing "
                                        "runs until a human has looked at it")
        halt = self.ledger.halt_record(self.patch.id)
        if halt is not None:
            return self._refuse(report, f"{self.patch.id} is halted: {halt.event} on "
                                        f"{halt.target or 'the fleet'} in run {halt.run} "
                                        f"({halt.detail}). Investigate, then `fleet-rollout "
                                        "clear-halt`.")
        digests = self.ledger.digests_for(self.patch.id)
        if digests and self.patch.digest not in digests:
            return self._refuse(report, f"the ledger already records {self.patch.id} with "
                                        "different content; a patch id must never be reused "
                                        "for new content, so give this change a new id")
        states = self.ledger.target_states(self.patch.id)
        planned = {t.name for t in self.plan.targets}
        # `skipped` means "already had it": a later run must keep treating it as done.
        done = {n for n, r in states.items()
                if r.event in ("verified", "skipped") and r.digest == self.patch.digest}
        # Another patch's half-done transaction would be backed up as this patch's
        # "pre-state" and then never undone. It must be dealt with first.
        foreign = [r for r in self.ledger.interrupted()
                   if r.patch != self.patch.id and r.target in planned - done]
        if foreign:
            return self._refuse(report, _interrupted_message(foreign))
        self._log("run_started", detail=f"{len(self.plan.targets)} target(s) in "
                                        f"{len(self.plan.waves)} wave(s)")
        interrupted = {n: r.run for n, r in states.items()
                       if r.event == "started" and n in planned}

        for target in self.plan.targets:                      # 1. undo crashed transactions
            if target.name in interrupted and not self._recover(
                    target, interrupted[target.name], report):
                return report

        pending = [t for t in self.plan.targets if t.name not in done]
        report.preflight = [self._tx(t).preflight() for t in pending]       # 2. read-only
        failed = [p for p in report.preflight if not p.ok]
        if failed:
            return self._abort(report, "preflight failed before any target was touched: "
                               + " | ".join(f"{p.target}: {'; '.join(p.problems)}"
                                            for p in failed))
        marked = {p.target for p in report.preflight if p.already_applied}

        patched: list[Target] = []
        for index, wave in enumerate(self.plan.waves):          # 3. the waves
            for target in wave.targets:
                if target.name in done or target.name in marked:
                    reason = ("already verified for this patch" if target.name in done
                              else "applied marker already present on the target")
                    report.results.append(TargetRun(target.name, "skipped", reason))
                    self._log("skipped", target.name, reason)
                    continue
                result = self._apply_one(target, report)
                if result is None:
                    return report
                report.results.append(result)
                if result.status != "verified":
                    report.halted_at = target.name
                    return report
                patched.append(target)
            last_wave = index == len(self.plan.waves) - 1
            if self.bake_seconds and patched and not last_wave and not self._bake(patched,
                                                                                    report):
                return report
        self._log("run_finished", detail=f"{len(report.results)} target(s) handled")
        report.ok = True
        return report

    def _apply_one(self, target: Target, report: RolloutReport) -> TargetRun | None:
        executor = self._ex(target)
        try:
            acquire(executor, target.root, self._owner(), now=self.clock())
        except (LockHeld, ExecutorError) as exc:
            self._abort(report, f"{target.name}: {exc}")
            return None
        try:
            approvers = self.plan.approvals.get(target.name)
            try:
                self._log("started", target.name,
                          extra={"approvals": list(approvers)} if approvers else None)
            except (OSError, LedgerCorrupt) as exc:
                self._abort(report, f"could not write the ledger before touching "
                                    f"{target.name} ({exc}); nothing was changed on it")
                return None
            tx = self._tx(target)
            try:
                outcome = tx.apply()
            except BaseException as exc:    # interrupted: apply() restored before re-raising
                self._log_interrupted(target, tx.interrupted, exc)
                raise
            if outcome.ok:
                detail = outcome.health.detail if outcome.health else "applied"
                try:
                    self._log("verified", target.name, detail)
                except (OSError, LedgerCorrupt) as exc:
                    restore = tx.restore(tx.recorded)
                    self._abort(report, f"{target.name} was patched but the ledger could not "
                                        f"record it ({exc}); the target was restored so no "
                                        f"change goes unaudited: {restore.detail}",
                                halt=True, target=target.name)
                    return None
                return TargetRun(target.name, "verified", detail, outcome)
            restore_ok = outcome.restore is not None and outcome.restore.ok
            event = "rolled_back" if restore_ok else "rollback_failed"
            detail = (f"{outcome.failed_step}: {outcome.error}; "
                      f"{outcome.restore.detail if outcome.restore else 'no restore ran'}")
            try:
                self._log(event, target.name, detail, halt=True)
            except (OSError, LedgerCorrupt) as exc:
                detail += f"; THE HALT RECORD COULD NOT BE WRITTEN ({exc})"
            return TargetRun(target.name, event, detail, outcome)
        finally:
            # If this fails the lock goes stale and the next preflight reports it.
            with contextlib.suppress(ExecutorError):
                release(executor, target.root, self.run_id)

    def _log_interrupted(self, target: Target, restore: RestoreReport | None,
                         exc: BaseException) -> None:
        """Give an interrupted transaction its terminal record, so the ledger never shows
        `started` for a target that was put back. A clean restore is `rolled_back` without
        a halt (the run was stopped, the patch did not fail); anything less halts."""
        clean = restore is not None and restore.ok
        detail = (f"interrupted by {type(exc).__name__}; "
                  f"{restore.detail if restore else 'no restore ran'}")
        with contextlib.suppress(Exception):   # the interruption is what must propagate
            self._log("rolled_back" if clean else "rollback_failed", target.name, detail,
                      halt=not clean)

    def _recover(self, target: Target, old_run: str, report: RolloutReport) -> bool:
        """Undo a transaction a crashed run left half-done, from its backup log."""
        executor = self._ex(target)
        try:
            acquire(executor, target.root, self._owner(), now=self.clock())
        except (LockHeld, ExecutorError) as exc:
            self._abort(report, f"{target.name} has an interrupted transaction from run "
                                f"{old_run} and cannot be locked ({exc}). If run {old_run} is "
                                f"dead, break its lock with `fleet-rollout unlock "
                                f"{target.name}`.")
            return False
        try:
            entries = self.state.backups().manifest(old_run, target.name).entries()
            tx = self._tx(target)
            try:
                changed = tx.conflicts(entries)
            except ExecutorError as exc:
                changed = [f"cannot read the target ({exc})"]
            if changed:
                self._abort(report, f"{target.name} has an interrupted transaction of "
                                    f"{self.patch.id} from run {old_run}, but "
                                    f"{'; '.join(changed)}. Nothing was changed. Inspect the "
                                    "target; `fleet-rollout rollback --force` puts the recorded "
                                    "pre-state back over that change.")
                return False
            restore = tx.restore(entries)
            if restore.ok:
                self._log("recovered", target.name,
                          f"undid interrupted run {old_run}: {restore.detail}")
                report.recovered.append(target.name)
                return True
            self._log("rollback_failed", target.name,
                      f"could not undo interrupted run {old_run}: {restore.detail}", halt=True)
            report.halted_at = target.name
            report.aborted = f"{target.name}: could not undo interrupted run {old_run}"
            return False
        finally:
            with contextlib.suppress(ExecutorError):
                release(executor, target.root, self.run_id)

    def _bake(self, patched: list[Target], report: RolloutReport) -> bool:
        """Wait, then re-check every target this run has patched so far."""
        self.sleep(self.bake_seconds)
        for target in patched:
            result = check_health(self._ex(target), target.health, sleep=self.sleep)
            if not result.ok:
                report.halted_at = target.name
                self._abort(report, f"{target.name} became unhealthy during the "
                                    f"{self.bake_seconds:g}s bake: {result.detail}. It is still "
                                    "patched; investigate, then `fleet-rollout rollback` or "
                                    "`fleet-rollout clear-halt`.", halt=True, target=target.name)
                return False
        return True


# -- operator actions outside a rollout ------------------------------------------------


def _interrupted_message(records: Sequence[LedgerRecord]) -> str:
    found = "; ".join(f"{r.target} has an interrupted transaction of {r.patch} from run "
                      f"{r.run}" for r in records)
    first = records[0]
    return (f"{found}. Undo it before anything else touches that target: `fleet-rollout "
            f"rollback {first.patch}.yaml --target {first.target}` restores its recorded "
            "pre-state (re-running that patch's apply also recovers it first)")


def rollback_target(fleet: Fleet, patch: Patch, target_name: str, *,
                    executor_for: ExecutorFactory, state: StateDir, operator: str,
                    ticket: Ticket, clock: Clock, sleep: Callable[[float], None] = time.sleep,
                    include_customer: bool = False, run_id: str | None = None,
                    force: bool = False) -> RestoreReport:
    """Put one target back to the pre-state recorded by the latest run of `patch` on it.
    A rollback is a mutation: same ticket, consent and lock rules as a rollout.

    It undoes this patch only. If a file or row it wrote has changed since (a later
    patch, a hand edit, the agent itself), the rollback is refused before anything is
    touched; `force` restores the recorded pre-state over that change."""
    target = fleet.target(target_name)
    now = clock()
    problem = ticket_problem(ticket, [target], now) or consent_problem(
        target, digest=patch.digest, store=state.approvals(), now=now,
        include_customer=include_customer)
    if problem:
        raise RolloutError(problem)
    ledger = state.ledger()
    foreign = [r for r in ledger.interrupted()
               if r.target == target.name and r.patch != patch.id]
    if foreign:
        raise RolloutError(_interrupted_message(foreign))
    runs = [r.run for r in ledger.records()
            if r.patch == patch.id and r.target == target.name and r.event == "started"]
    if not runs:
        raise RolloutError(f"no recorded run of {patch.id} on {target.name}; nothing to roll back")
    source = runs[-1]
    entries = state.backups().manifest(source, target.name).entries()
    run_id = run_id or new_run_id(now)
    owner = LockOwner(run_id, person_name(operator, where="operator"), patch.id,
                      now.isoformat())
    run_lock = state.run_lock()
    try:
        run_lock.acquire(owner, now=now)
    except LockHeld as exc:
        raise RolloutError(str(exc)) from None
    try:
        executor = executor_for(target)
        try:
            acquire(executor, target.root, owner, now=now)
        except LockHeld as exc:
            raise RolloutError(str(exc)) from None
        try:
            tx = TargetTransaction(target, executor, patch, state.backups(), run_id=run_id,
                                   operator=operator, clock=clock, sleep=sleep)
            changed = [] if force else tx.conflicts(entries)
            if changed:
                raise RolloutError(
                    f"refusing to roll back {patch.id} on {target.name}: {'; '.join(changed)}. "
                    "Nothing was changed. Roll back the later change first, or pass --force "
                    "to put the recorded pre-state back over it")
            restore = tx.restore(entries, force=force)
        finally:
            release(executor, target.root, run_id)
        how = "forced: " if force else ""
        ledger.append(run=run_id, event="manual_rollback" if restore.ok else "rollback_failed",
                      operator=operator, ts=clock(), patch=patch.id, digest=patch.digest,
                      target=target.name, halt=not restore.ok, ticket=ticket.id,
                      detail=f"{how}restored the pre-state recorded by run {source}: "
                             f"{restore.detail}")
        return restore
    finally:
        run_lock.release(run_id)


@contextlib.contextmanager
def _holding_run_lock(state: StateDir, operator: str, what: str, now: datetime):
    """Serialize an out-of-band ledger write with any rollout using the same state dir."""
    run_id = new_run_id(now)
    run_lock = state.run_lock()
    try:
        run_lock.acquire(LockOwner(run_id, operator, what, now.isoformat()), now=now)
    except LockHeld as exc:
        raise RolloutError(str(exc)) from None
    try:
        yield run_id
    finally:
        run_lock.release(run_id)


def break_lock(fleet: Fleet, target_name: str, *, executor_for: ExecutorFactory,
               state: StateDir, operator: str, ticket: Ticket, now: datetime) -> LockOwner | None:
    """Break-glass: remove a target's lock (normally a stale one from a dead run)."""
    target = fleet.target(target_name)
    operator = person_name(operator, where="operator")
    problem = ticket_problem(ticket, [target], now)
    if problem:
        raise RolloutError(problem)
    with _holding_run_lock(state, operator, "unlock", now) as run_id:
        holder = force_release(executor_for(target), target.root)
        detail = (f"broke the lock held by run {holder.run_id} ({holder.operator}, patch "
                  f"{holder.patch}, since {holder.acquired_at})" if holder
                  else "no lock was held")
        state.ledger().append(run=run_id, event="lock_broken", operator=operator, ts=now,
                              patch=holder.patch if holder else None, target=target.name,
                              detail=detail, ticket=ticket.id)
    return holder


def break_run_lock(state: StateDir, *, operator: str, ticket: Ticket,
                   now: datetime) -> LockOwner | None:
    """Break-glass for the state directory's own lock, left behind by a dead run."""
    operator = person_name(operator, where="operator")
    problem = ticket_problem(ticket, [], now)
    if problem:
        raise RolloutError(problem)
    holder = state.run_lock().force_release()
    detail = (f"broke the state-directory lock held by run {holder.run_id} ({holder.operator}, "
              f"since {holder.acquired_at})" if holder else "no state-directory lock was held")
    state.ledger().append(run=new_run_id(now), event="lock_broken", operator=operator, ts=now,
                          patch=holder.patch if holder else None, detail=detail,
                          ticket=ticket.id)
    return holder


def clear_halt(state: StateDir, patch_id: str, *, operator: str, reason: str,
               now: datetime) -> LedgerRecord:
    operator = person_name(operator, where="operator")
    try:
        reason = single_line(reason, where="reason", max_len=300)
    except ValidationError as exc:
        raise RolloutError(str(exc)) from None
    with _holding_run_lock(state, operator, "clear-halt", now) as run_id:
        ledger = state.ledger()
        halt = ledger.halt_record(patch_id)
        if halt is None:
            raise RolloutError(f"{patch_id} is not halted")
        return ledger.append(run=run_id, event="halt_cleared", operator=operator, ts=now,
                             patch=patch_id, detail=f"cleared the halt from run {halt.run} on "
                                                    f"{halt.target or 'the fleet'}: {reason}")
