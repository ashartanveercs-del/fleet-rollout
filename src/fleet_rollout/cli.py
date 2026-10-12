"""`fleet-rollout`: validate, plan, apply and audit patch rollouts across a fleet of agents.

Exit codes: 0 success, 1 a rollout/check failed (or found drift), 2 invalid input,
3 refused by a gate (ticket, consent, halt, lock) before anything was touched.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import textwrap
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TextIO

from . import __version__
from .backup import BackupCorrupt
from .consent import REQUIRED_APPROVALS
from .drift import check_drift
from .executors.base import Executor, ExecutorError
from .executors.container import make_executor
from .fleet import Fleet, Target, load_fleet
from .ledger import LedgerCorrupt
from .locks import LockHeld
from .locks import probe as probe_lock
from .rollout import (
    Rollout,
    RolloutError,
    RolloutPlan,
    break_lock,
    break_run_lock,
    build_plan,
    clear_halt,
    rollback_target,
)
from .spec import Patch, load_patch
from .state import StateDir
from .tickets import load_ticket
from .validation import ValidationError, person_name, target_name

EXIT_OK, EXIT_FAILED, EXIT_INVALID, EXIT_REFUSED = 0, 1, 2, 3


class _UsageError(Exception):
    pass


class _Exit(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(status)
        self.status = status


class _Parser(argparse.ArgumentParser):
    """argparse that reports errors to main() instead of exiting the interpreter."""

    def error(self, message: str) -> Any:
        raise _UsageError(f"{self.prog}: {message}")

    def exit(self, status: int = 0, message: str | None = None) -> Any:
        if status and message:
            raise _UsageError(message.strip())
        raise _Exit(status)


def _parser() -> _Parser:
    parser = _Parser(prog="fleet-rollout", description=__doc__.split("\n")[0])
    parser.add_argument("--version", action="version", version=f"fleet-rollout {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def fleet_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--fleet", type=Path, default=Path("fleet.yaml"),
                       help="fleet file (default: ./fleet.yaml)")
        p.add_argument("--state", type=Path, help="state directory (default: from the fleet file)")

    def selection(p: argparse.ArgumentParser) -> None:
        p.add_argument("--targets", help="comma-separated subset of targets (default: all)")
        p.add_argument("--canary", help="target to patch first (default: the flagged canary)")
        p.add_argument("--include-customer", action="store_true",
                       help="include customer-owned targets (each needs 2 approvals)")

    p = sub.add_parser("validate", help="validate a patch spec (no fleet contact)")
    p.add_argument("patch", type=Path)

    p = sub.add_parser("plan", help="show the waves, gates and warnings (no fleet contact)")
    p.add_argument("patch", type=Path)
    fleet_args(p)
    selection(p)

    p = sub.add_parser("apply", help="roll a patch out, canary first, stopping at the first red")
    p.add_argument("patch", type=Path)
    fleet_args(p)
    selection(p)
    p.add_argument("--ticket", required=True, help="change ticket id, e.g. CHG-1042")
    p.add_argument("--operator", help="who is running this (default: $FLEET_ROLLOUT_OPERATOR)")
    p.add_argument("--allow-drift", action="store_true",
                   help="overwrite files whose pre-state no longer matches expect_sha256")
    p.add_argument("--bake", type=float, default=0.0, metavar="SECONDS",
                   help="wait between waves, then re-check every patched target")

    p = sub.add_parser("rollback", help="restore one target to its recorded pre-state")
    p.add_argument("patch", type=Path)
    fleet_args(p)
    p.add_argument("--target", required=True)
    p.add_argument("--ticket", required=True)
    p.add_argument("--operator")
    p.add_argument("--include-customer", action="store_true")

    p = sub.add_parser("status", help="per-target state of a patch, from the ledger")
    p.add_argument("patch", type=Path)
    fleet_args(p)

    p = sub.add_parser("drift", help="diff every target against the golden template")
    fleet_args(p)
    p.add_argument("--targets")

    p = sub.add_parser("approve", help="record one approval for a customer-owned target")
    p.add_argument("patch", type=Path)
    fleet_args(p)
    p.add_argument("--target", required=True)
    p.add_argument("--approver", required=True)
    p.add_argument("--note", required=True)
    p.add_argument("--ttl-hours", type=float, default=24.0)

    p = sub.add_parser("ledger", help="verify the hash chain, or show the records")
    p.add_argument("action", choices=("verify", "show"))
    fleet_args(p)

    p = sub.add_parser("clear-halt", help="unfreeze a halted patch after investigating")
    p.add_argument("patch_id")
    fleet_args(p)
    p.add_argument("--operator")
    p.add_argument("--reason", required=True)

    p = sub.add_parser("unlock", help="break-glass: remove a stale lock")
    p.add_argument("target", nargs="?")
    fleet_args(p)
    p.add_argument("--run-lock", action="store_true", help="break the state directory's lock")
    p.add_argument("--ticket", required=True)
    p.add_argument("--operator")

    p = sub.add_parser("locks", help="show which targets are locked, and by whom")
    fleet_args(p)
    p.add_argument("--targets")
    return parser


@dataclass
class _Ctx:
    args: argparse.Namespace
    executor_factory: Callable[[Target], Executor]
    clock: Callable[[], datetime]
    sleep: Callable[[float], None]
    out: TextIO
    err: TextIO
    _fleet: Fleet | None = field(default=None, init=False)

    def say(self, text: str = "") -> None:
        print(text, file=self.out)

    def fleet(self) -> Fleet:
        if self._fleet is None:
            self._fleet = load_fleet(self.args.fleet)
        return self._fleet

    def state(self) -> StateDir:
        return StateDir(self.args.state or self.fleet().state_dir)

    def patch(self) -> Patch:
        return load_patch(self.args.patch)

    def names(self) -> list[str] | None:
        raw = getattr(self.args, "targets", None)
        if not raw:
            return None
        return [target_name(n.strip(), where="--targets") for n in raw.split(",") if n.strip()]

    def operator(self) -> str:
        raw = (self.args.operator or os.environ.get("FLEET_ROLLOUT_OPERATOR")
               or getpass.getuser().lower())
        return person_name(raw, where="operator (pass --operator)")


def _describe(target: Target) -> str:
    owner = f"customer: {target.customer}" if target.customer else target.owner
    return f"{target.name:<12} {owner:<26} {target.container}@{target.host}  cohort {target.cohort}"


def _print_patch(ctx: _Ctx, patch: Patch) -> None:
    ctx.say(f"{patch.id} (digest {patch.short_digest}): {patch.description}")
    for i, step in enumerate(patch.steps, start=1):
        ctx.say(f"  {i}. {step.label}")
    for check in patch.verify:
        ctx.say(f"  verify: {check.file} contains {check.text!r}")


def _print_plan(ctx: _Ctx, plan: RolloutPlan) -> None:
    ctx.say("\nWaves (one target at a time; the first failure halts the rollout):")
    for wave in plan.waves:
        for i, target in enumerate(wave.targets):
            ctx.say(f"  {wave.name if i == 0 else '':<13} {_describe(target)}")
    if plan.held_back:
        ctx.say("\nHeld back (customer-owned; add --include-customer):")
        for name, _reason in plan.held_back:
            ctx.say(f"  {name}")
    if plan.blocked:
        ctx.say("\nBlocked:")
        for name, reason in plan.blocked:
            ctx.say(f"  {name}: {reason}")
    if plan.warnings:
        ctx.say("\nWarnings:")
        for warning in plan.warnings:
            ctx.say(f"  {warning}")


# -- commands ------------------------------------------------------------------------


def _validate(ctx: _Ctx) -> int:
    patch = ctx.patch()
    _print_patch(ctx, patch)
    ctx.say(f"\nOK: {len(patch.steps)} step(s), digest {patch.digest}")
    return EXIT_OK


def _build_plan(ctx: _Ctx, patch: Patch) -> RolloutPlan:
    return build_plan(ctx.fleet(), patch, approvals=ctx.state().approvals(), now=ctx.clock(),
                      names=ctx.names(), canary=ctx.args.canary,
                      include_customer=ctx.args.include_customer)


def _plan(ctx: _Ctx) -> int:
    patch = ctx.patch()
    plan = _build_plan(ctx, patch)
    _print_patch(ctx, patch)
    _print_plan(ctx, plan)
    if not plan.targets:
        ctx.say("\nNo targets selected.")
        return EXIT_FAILED
    if plan.blocked:
        ctx.say("\nPlan is BLOCKED: record the missing approvals with `fleet-rollout approve`.")
        return EXIT_FAILED
    ctx.say(f"\nPlan is ready: {len(plan.targets)} target(s) in {len(plan.waves)} wave(s). "
            "Apply it with `fleet-rollout apply ... --ticket <id>`.")
    return EXIT_OK


def _apply(ctx: _Ctx) -> int:
    fleet, patch, state = ctx.fleet(), ctx.patch(), ctx.state()
    ticket = load_ticket(fleet.tickets_dir, ctx.args.ticket)
    operator = ctx.operator()
    plan = _build_plan(ctx, patch)
    runner = Rollout(fleet, plan, executor_for=ctx.executor_factory, state=state,
                     operator=operator, ticket=ticket, clock=ctx.clock, sleep=ctx.sleep,
                     allow_drift=ctx.args.allow_drift, bake_seconds=ctx.args.bake)
    report = runner.run()
    if report.refused:
        print(f"refused: {report.aborted}", file=ctx.err)
        return EXIT_REFUSED
    ctx.say(f"run {report.run_id}: {patch.id} (digest {patch.short_digest}), ticket {ticket.id}, "
            f"operator {operator}")
    for name in report.recovered:
        ctx.say(f"  recovered    {name}: undid an interrupted transaction from an earlier run")
    for check in report.preflight:
        for note in check.notes:
            ctx.say(f"  note         {check.target}: {note}")
    wave_of = {t.name: w.name for w in plan.waves for t in w.targets}
    for result in report.results:
        ctx.say(f"  {wave_of.get(result.target, ''):<14}{result.target:<12} {result.status:<16}"
                f"{result.detail}")
    if report.ok:
        verified = sum(r.status == "verified" for r in report.results)
        skipped = sum(r.status == "skipped" for r in report.results)
        head = state.ledger().verify().head
        ctx.say(f"done: {verified} verified, {skipped} skipped; ledger head {head[:16]}")
        return EXIT_OK
    if report.halted_at:
        failed = next((r for r in report.results if r.target == report.halted_at), None)
        why = report.aborted or (f"{failed.status}" if failed else "see above")
        ctx.say(f"HALTED at {report.halted_at} ({why}). No later target was touched. The patch "
                f"stays frozen until someone investigates and runs "
                f"`fleet-rollout clear-halt {patch.id}`.")
    else:
        ctx.say(f"ABORTED: {report.aborted}")
    return EXIT_FAILED


def _rollback(ctx: _Ctx) -> int:
    fleet, patch, state = ctx.fleet(), ctx.patch(), ctx.state()
    restore = rollback_target(fleet, patch, ctx.args.target, executor_for=ctx.executor_factory,
                              state=state, operator=ctx.operator(),
                              ticket=load_ticket(fleet.tickets_dir, ctx.args.ticket),
                              clock=ctx.clock, sleep=ctx.sleep,
                              include_customer=ctx.args.include_customer)
    ctx.say(f"rollback of {patch.id} on {ctx.args.target}: {restore.detail}")
    return EXIT_OK if restore.ok else EXIT_FAILED


def _status(ctx: _Ctx) -> int:
    fleet, patch = ctx.fleet(), ctx.patch()
    ledger = ctx.state().ledger()
    states = ledger.target_states(patch.id)
    ctx.say(f"{patch.id} (digest {patch.short_digest})")
    halt = ledger.halt_record(patch.id)
    if halt is not None:
        ctx.say(f"HALTED: {halt.event} on {halt.target or 'the fleet'} in run {halt.run}: "
                f"{halt.detail}")
    for target in fleet.targets:
        record = states.get(target.name)
        if record is None:
            ctx.say(f"  {target.name:<12} {'not applied':<16}")
        else:
            ctx.say(f"  {target.name:<12} {record.event:<16} run {record.run}  {record.ts}")
    return EXIT_OK


def _drift(ctx: _Ctx) -> int:
    fleet = ctx.fleet()
    if fleet.golden_dir is None:
        raise ValidationError(f"{fleet.source} sets no `golden` template directory")
    reports = check_drift(fleet.golden_dir, fleet.select(ctx.names()), ctx.executor_factory)
    for report in reports:
        if not report.drifted:
            ctx.say(f"{report.target}: in sync ({len(report.files)} files)")
            continue
        ctx.say(f"{report.target}: DRIFTED")
        for item in report.files:
            if item.state == "in_sync":
                continue
            ctx.say(f"  {item.state}: {item.path}" + (f" ({item.detail})" if item.detail else ""))
            if item.diff:
                ctx.say(textwrap.indent(item.diff.rstrip("\n"), "    "))
    return EXIT_FAILED if any(r.drifted for r in reports) else EXIT_OK


def _approve(ctx: _Ctx) -> int:
    fleet, patch, state = ctx.fleet(), ctx.patch(), ctx.state()
    target = fleet.target(ctx.args.target)
    now = ctx.clock()
    approval = state.approvals().add(patch_id=patch.id, digest=patch.digest, target=target.name,
                                     approver=ctx.args.approver, note=ctx.args.note, now=now,
                                     ttl=timedelta(hours=ctx.args.ttl_hours))
    count = len(state.approvals().valid(digest=patch.digest, target=target.name, now=now))
    ctx.say(f"recorded approval by {approval.approver} for {patch.id} on {target.name} "
            f"(expires {approval.expires})")
    note = "" if target.customer_owned else " (internal target: approvals are not required)"
    ctx.say(f"{target.name} has {count} of {REQUIRED_APPROVALS} required approvals for this "
            f"patch version{note}")
    return EXIT_OK


def _ledger(ctx: _Ctx) -> int:
    ledger = ctx.state().ledger()
    report = ledger.verify()
    if ctx.args.action == "show" and report.ok:
        for r in ledger.records():
            where = f" {r.target}" if r.target else ""
            ctx.say(f"{r.seq:>5} {r.ts} {r.run} {r.event}{where}"
                    + (" [HALT]" if r.halt else "") + (f": {r.detail}" if r.detail else ""))
    if report.ok:
        ctx.say(f"ledger OK: {report.count} record(s), head {report.head}")
        return EXIT_OK
    ctx.say(f"ledger BROKEN after {report.count} good record(s): {report.problem}")
    return EXIT_FAILED


def _clear_halt(ctx: _Ctx) -> int:
    record = clear_halt(ctx.state(), ctx.args.patch_id, operator=ctx.operator(),
                        reason=ctx.args.reason, now=ctx.clock())
    ctx.say(f"halt cleared for {ctx.args.patch_id}: {record.detail}")
    return EXIT_OK


def _unlock(ctx: _Ctx) -> int:
    fleet = ctx.fleet()
    ticket = load_ticket(fleet.tickets_dir, ctx.args.ticket)
    if ctx.args.run_lock:
        holder = break_run_lock(ctx.state(), operator=ctx.operator(), ticket=ticket,
                                now=ctx.clock())
        where = "the state directory"
    else:
        if not ctx.args.target:
            raise ValidationError("unlock: name a target, or pass --run-lock")
        holder = break_lock(fleet, ctx.args.target, executor_for=ctx.executor_factory,
                            state=ctx.state(), operator=ctx.operator(), ticket=ticket,
                            now=ctx.clock())
        where = ctx.args.target
    ctx.say(f"broke the lock on {where} held by run {holder.run_id} ({holder.operator})"
            if holder else f"no lock was held on {where}")
    return EXIT_OK


def _locks(ctx: _Ctx) -> int:
    fleet = ctx.fleet()
    for target in fleet.select(ctx.names()):
        try:
            state = probe_lock(ctx.executor_factory(target), target.root, now=ctx.clock())
        except ExecutorError as exc:
            ctx.say(f"  {target.name:<12} UNKNOWN  {exc}")
            continue
        holder = (f"run {state.owner.run_id} ({state.owner.operator}, patch {state.owner.patch})"
                  f", {state.age_seconds}s" if state.owner else "")
        ctx.say(f"  {target.name:<12} {state.state.upper():<7} {holder}")
    holder = ctx.state().run_lock().holder()
    ctx.say(f"  state dir    {'HELD' if holder else 'FREE':<7} "
            + (f"run {holder.run_id} ({holder.operator})" if holder else ""))
    return EXIT_OK


_HANDLERS: dict[str, Callable[[_Ctx], int]] = {
    "validate": _validate, "plan": _plan, "apply": _apply, "rollback": _rollback,
    "status": _status, "drift": _drift, "approve": _approve, "ledger": _ledger,
    "clear-halt": _clear_halt, "unlock": _unlock, "locks": _locks,
}


def main(argv: Sequence[str] | None = None, *,
         executor_factory: Callable[[Target], Executor] | None = None,
         clock: Callable[[], datetime] | None = None,
         sleep: Callable[[float], None] | None = None,
         stdout: TextIO | None = None, stderr: TextIO | None = None) -> int:
    out, err = stdout or sys.stdout, stderr or sys.stderr
    try:
        args = _parser().parse_args(argv)
    except _UsageError as exc:
        print(exc, file=err)
        return EXIT_INVALID
    except _Exit as exc:
        return exc.status
    ctx = _Ctx(args, executor_factory or make_executor,
               clock or (lambda: datetime.now(UTC)), sleep or time.sleep, out, err)
    try:
        return _HANDLERS[args.command](ctx)
    except (ValidationError, BackupCorrupt) as exc:
        print(f"error: {exc}", file=err)
        return EXIT_INVALID
    except (RolloutError, LockHeld) as exc:
        print(f"refused: {exc}", file=err)
        return EXIT_REFUSED
    except LedgerCorrupt as exc:
        print(f"ledger error: {exc}", file=err)
        return EXIT_FAILED
    except ExecutorError as exc:
        print(f"target error: {exc}", file=err)
        return EXIT_FAILED
    except OSError as exc:
        print(f"error: {exc}", file=err)
        return EXIT_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
