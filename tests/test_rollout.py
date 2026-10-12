"""Waves, gates and the rollout driver, end to end against five fake agents."""

from datetime import timedelta

import pytest
from fakes import (
    ROOT,
    T0,
    WORKSPACE,
    Clock,
    agent,
    five_targets,
    make_fleet,
    make_patch,
    make_target,
    write_ticket,
)

from fleet_rollout.backup import BackupEntry
from fleet_rollout.ledger import Ledger
from fleet_rollout.locks import LockOwner, acquire, lock_path
from fleet_rollout.rollout import Rollout as RolloutRunner
from fleet_rollout.rollout import (
    RolloutError,
    break_lock,
    build_plan,
    clear_halt,
    plan_waves,
    rollback_target,
)
from fleet_rollout.state import StateDir
from fleet_rollout.testing import healthy
from fleet_rollout.tickets import load_ticket

GREETING_V2 = b"Thanks for reaching out to Example Bakery support!\n"
ORIGINAL = WORKSPACE["config/greeting.txt"]


def names(waves):
    return [[t.name for t in w.targets] for w in waves]


# -- wave planning -------------------------------------------------------------------


def test_canary_then_one_target_per_cohort_then_the_rest():
    waves = plan_waves(five_targets())
    assert [w.name for w in waves] == ["canary", "cohort leads", "remaining"]
    assert names(waves) == [["agent-01"], ["agent-04", "agent-05"], ["agent-02", "agent-03"]]


def test_cohort_leads_prefer_internal_targets_and_customers_go_last():
    waves = plan_waves(five_targets())
    assert waves[1].targets[0].name == "agent-04"          # not the customer-owned agent-03
    assert waves[2].targets[-1].customer_owned


def test_an_explicit_canary_wins_and_its_cohort_needs_no_lead():
    waves = plan_waves(five_targets(), canary="agent-02")
    assert names(waves) == [["agent-02"], ["agent-04", "agent-05"], ["agent-01", "agent-03"]]


def test_a_customer_owned_canary_is_refused():
    with pytest.raises(RolloutError, match="customer-owned"):
        plan_waves(five_targets(), canary="agent-03")


def test_an_unknown_canary_is_refused():
    with pytest.raises(RolloutError, match="agent-09"):
        plan_waves(five_targets(), canary="agent-09")


def test_without_a_flagged_canary_the_first_internal_target_is_used():
    targets = [make_target("agent-03", owner="customer"), make_target("agent-04")]
    assert plan_waves(targets)[0].targets[0].name == "agent-04"


def test_a_fleet_slice_with_no_internal_target_has_no_safe_canary():
    with pytest.raises(RolloutError, match="willing to break"):
        plan_waves([make_target("agent-03", owner="customer")])


# -- the rollout environment ---------------------------------------------------------


class Env:
    def __init__(self, tmp_path, targets=None, steps=None, files=None, pid="greeting-v2"):
        self.tmp_path = tmp_path
        self.fleet = make_fleet(tmp_path, targets or five_targets())
        self.agents = {t.name: agent(t.name) for t in self.fleet.targets}
        self.state = StateDir(self.fleet.state_dir)
        self.clock = Clock()
        self.slept = []
        self.patch = make_patch(tmp_path / pid, steps or [
            {"kind": "write_file", "source": "files/greeting.txt",
             "dest": "config/greeting.txt"}],
            files=files or {"files/greeting.txt": GREETING_V2}, pid=pid)
        # `*` never covers customer-owned targets, so the one customer target is named.
        write_ticket(self.fleet, targets=("*", "agent-03"))

    def executor_for(self, target):
        return self.agents[target.name]

    def approve(self, target, *people):
        for person in people:
            self.state.approvals().add(patch_id=self.patch.id, digest=self.patch.digest,
                                       target=target, approver=person, note="looks right",
                                       now=self.clock(), ttl=timedelta(hours=24))

    def plan(self, **kw):
        return build_plan(self.fleet, self.patch, approvals=self.state.approvals(),
                          now=self.clock(), **kw)

    def ticket(self, tid="CHG-1042"):
        return load_ticket(self.fleet.tickets_dir, tid)

    def run(self, plan=None, ticket="CHG-1042", **kw):
        kw.setdefault("run_id", f"r-{len(self.ledger_records()) + 1:04d}")
        return RolloutRunner(self.fleet, plan or self.plan(), executor_for=self.executor_for,
                             state=self.state, operator="ops.oncall", ticket=self.ticket(ticket),
                             clock=self.clock, sleep=self.slept.append, **kw).run()

    def ledger_records(self):
        return Ledger(self.state.root / "ledger.jsonl").records() \
            if (self.state.root / "ledger.jsonl").exists() else []

    def events(self, run=None):
        return [(r.event, r.target) for r in self.ledger_records() if run in (None, r.run)]

    def greeting(self, name):
        return self.agents[name].files[f"{ROOT}/config/greeting.txt"]

    def untouched(self, *names_):
        return all(not self.agents[n].mutations for n in names_)


# -- planning gates --------------------------------------------------------------------


def test_customer_targets_are_held_back_visibly_without_the_flag(tmp_path):
    env = Env(tmp_path)
    plan = env.plan()
    assert [t.name for t in plan.targets] == ["agent-01", "agent-04", "agent-05", "agent-02"]
    assert plan.held_back[0][0] == "agent-03" and "--include-customer" in plan.held_back[0][1]
    assert plan.executable


def test_an_included_customer_target_without_two_approvals_blocks_the_plan(tmp_path):
    env = Env(tmp_path)
    env.approve("agent-03", "ops.oncall")
    plan = env.plan(include_customer=True)
    assert not plan.executable
    assert plan.blocked[0][0] == "agent-03" and "have 1: ops.oncall" in plan.blocked[0][1]
    env.approve("agent-03", "eng.lead")
    assert env.plan(include_customer=True).executable


def test_golden_lag_is_reported_in_the_plan(tmp_path):
    golden = tmp_path / "golden" / "config"
    golden.mkdir(parents=True)
    (golden / "greeting.txt").write_bytes(ORIGINAL)
    env = Env(tmp_path)
    env.fleet = make_fleet(tmp_path, five_targets(), golden=tmp_path / "golden")
    assert any("config/greeting.txt" in w for w in env.plan().warnings)


# -- the happy path ----------------------------------------------------------------------


def test_a_clean_rollout_patches_every_target_in_wave_order(tmp_path):
    env = Env(tmp_path)
    report = env.run()
    assert report.ok, report.aborted
    assert [r.target for r in report.results] == ["agent-01", "agent-04", "agent-05", "agent-02"]
    assert all(env.greeting(n) == GREETING_V2 for n in ("agent-01", "agent-02", "agent-04",
                                                         "agent-05"))
    assert env.greeting("agent-03") == ORIGINAL and env.untouched("agent-03")
    events = env.events()
    assert events[0] == ("run_started", None) and events[-1] == ("run_finished", None)
    started = [t for e, t in events if e == "started"]
    verified = [t for e, t in events if e == "verified"]
    assert started == verified == ["agent-01", "agent-04", "agent-05", "agent-02"]
    assert all(lock_path(ROOT) not in fx.files for fx in env.agents.values())
    assert not (env.state.root / "run.lock").exists()
    assert env.ledger_records()[1].ticket == "CHG-1042"


def test_customer_targets_go_through_with_two_approvals_recorded_in_the_ledger(tmp_path):
    env = Env(tmp_path)
    env.approve("agent-03", "ops.oncall", "eng.lead")
    report = env.run(plan=env.plan(include_customer=True))
    assert report.ok
    assert env.greeting("agent-03") == GREETING_V2
    [started] = [r for r in env.ledger_records() if r.event == "started"
                 and r.target == "agent-03"]
    assert started.extra["approvals"] == ["eng.lead", "ops.oncall"]   # sorted, deterministic


# -- refusals before anything is touched -----------------------------------------------


def test_one_unhealthy_target_aborts_the_rollout_before_any_target_is_mutated(tmp_path):
    env = Env(tmp_path)
    env.agents["agent-05"].health = healthy(b'{"status":"degraded"}')
    report = env.run()
    assert not report.ok and "preflight" in report.aborted and "agent-05" in report.aborted
    assert env.untouched(*env.agents)
    assert ("run_aborted", None) in env.events()
    assert env.state.ledger().halt_record(env.patch.id) is None   # an abort is not a halt


def test_a_ticket_that_does_not_cover_every_target_is_refused(tmp_path):
    env = Env(tmp_path)
    write_ticket(env.fleet, "CHG-2000", targets=("agent-01",))
    report = env.run(ticket="CHG-2000")
    assert not report.ok and "does not cover agent-04" in report.aborted
    assert env.untouched(*env.agents) and env.events() == []


def test_an_expired_ticket_is_refused(tmp_path):
    env = Env(tmp_path)
    write_ticket(env.fleet, "CHG-2001", expires="2026-10-01T00:00:00Z")
    report = env.run(ticket="CHG-2001")
    assert not report.ok and "expired" in report.aborted


def test_a_blocked_plan_is_refused(tmp_path):
    env = Env(tmp_path)
    report = env.run(plan=env.plan(include_customer=True))
    assert not report.ok and "approvals" in report.aborted
    assert env.untouched(*env.agents)


def test_a_concurrent_rollout_from_the_same_state_dir_is_refused(tmp_path):
    env = Env(tmp_path)
    env.state.run_lock().acquire(LockOwner("r-other", "eng.lead", "other", T0.isoformat()))
    report = env.run()
    assert not report.ok and "r-other" in report.aborted
    assert env.untouched(*env.agents)


def test_a_target_locked_by_someone_else_fails_preflight(tmp_path):
    env = Env(tmp_path)
    acquire(env.agents["agent-04"], ROOT, LockOwner("r-other", "eng.lead", "other-patch",
                                                    T0.isoformat()))
    locked_by_test = len(env.agents["agent-04"].mutations)
    report = env.run()
    assert not report.ok and "r-other" in report.aborted
    assert env.untouched("agent-01", "agent-02", "agent-03", "agent-05")
    assert len(env.agents["agent-04"].mutations) == locked_by_test


def test_reusing_a_patch_id_for_different_content_is_refused(tmp_path):
    env = Env(tmp_path)
    assert env.run().ok
    env2 = Env(tmp_path / "v2", files={"files/greeting.txt": b"Different text!\n"})
    env2.fleet, env2.agents, env2.state = env.fleet, env.agents, env.state
    report = env2.run()
    assert not report.ok and "different content" in report.aborted


# -- failure, halt, resume -----------------------------------------------------------


def test_a_failure_rolls_back_that_target_halts_and_leaves_later_targets_untouched(tmp_path):
    env = Env(tmp_path)
    env.agents["agent-04"].fail("rename", "config/greeting.txt", error="Read-only file system")
    report = env.run()
    assert not report.ok and report.halted_at == "agent-04"
    assert env.greeting("agent-01") == GREETING_V2                   # canary stays patched
    assert env.greeting("agent-04") == ORIGINAL                      # restored
    assert env.untouched("agent-05", "agent-02", "agent-03")
    halt = env.state.ledger().halt_record(env.patch.id)
    assert halt.event == "rolled_back" and halt.target == "agent-04"
    assert "Read-only" in halt.detail
    assert lock_path(ROOT) not in env.agents["agent-04"].files      # lock released


def test_a_halted_patch_refuses_to_run_until_the_halt_is_cleared(tmp_path):
    env = Env(tmp_path)
    env.agents["agent-04"].fail("rename", "config/greeting.txt")
    assert not env.run().ok
    report = env.run()
    assert not report.ok and "halted" in report.aborted
    clear_halt(env.state, env.patch.id, operator="ops.oncall", reason="disk remounted rw",
               now=env.clock())
    calls_before = len(env.agents["agent-01"].calls)
    report = env.run()
    assert report.ok, report.aborted
    assert [r.status for r in report.results] == ["skipped", "verified", "verified", "verified"]
    assert len(env.agents["agent-01"].calls) == calls_before        # resume: not even probed
    assert env.greeting("agent-04") == GREETING_V2


def test_targets_stay_done_across_any_number_of_resumed_runs(tmp_path):
    # Regression: the second run records `skipped`, which used to stop the third run from
    # recognising those targets as done, so it probed them all again.
    env = Env(tmp_path)
    assert env.run().ok
    assert env.run().ok
    calls = {n: len(fx.calls) for n, fx in env.agents.items()}
    report = env.run()
    assert report.ok and {r.status for r in report.results} == {"skipped"}
    assert {n: len(fx.calls) for n, fx in env.agents.items()} == calls


def test_a_rollback_that_cannot_restore_health_is_ledgered_as_rollback_failed(tmp_path):
    env = Env(tmp_path)
    wedged = {"yes": False}

    def health(f):
        if f.files[f"{ROOT}/config/greeting.txt"] == GREETING_V2:
            wedged["yes"] = True            # the agent wedged itself on the new greeting
        return healthy(b'{"status":"degraded"}' if wedged["yes"] else b'{"status":"ok"}')(f)

    env.agents["agent-04"].health = health
    report = env.run()
    assert not report.ok and report.halted_at == "agent-04"
    assert env.state.ledger().halt_record(env.patch.id).event == "rollback_failed"


def test_an_applied_marker_without_a_ledger_record_is_skipped_not_reapplied(tmp_path):
    env = Env(tmp_path)
    assert env.run().ok
    (env.state.root / "ledger.jsonl").unlink()       # e.g. a different operator machine
    before = {n: len(fx.mutations) for n, fx in env.agents.items()}
    report = env.run()
    assert report.ok and {r.status for r in report.results} == {"skipped"}
    assert {n: len(fx.mutations) for n, fx in env.agents.items()} == before


# -- crash recovery ----------------------------------------------------------------------


def crashed_state(env):
    """What a SIGKILL halfway through agent-01's transaction leaves behind."""
    fx = env.agents["agent-01"]
    store = env.state.backups()
    store.manifest("r-crashed", "agent-01").record(
        BackupEntry(0, f"{ROOT}/config/greeting.txt", store.put(ORIGINAL)))
    fx.put(f"{ROOT}/config/greeting.txt", b"half-applied junk\n")
    ledger = env.state.ledger()
    for event, target in (("run_started", None), ("started", "agent-01")):
        ledger.append(run="r-crashed", event=event, operator="ops.oncall", ts=T0,
                      patch=env.patch.id, digest=env.patch.digest, target=target)
    acquire(fx, ROOT, LockOwner("r-crashed", "ops.oncall", env.patch.id, T0.isoformat()))


def test_an_interrupted_transaction_is_undone_from_its_log_before_anything_else(tmp_path):
    env = Env(tmp_path)
    crashed_state(env)
    report = env.run()
    assert not report.ok and "r-crashed" in report.aborted       # its lock is still there
    assert env.greeting("agent-01") == b"half-applied junk\n"
    env.clock.advance(hours=3)
    owner = break_lock(env.fleet, "agent-01", executor_for=env.executor_for, state=env.state,
                       operator="ops.oncall", ticket=env.ticket(), now=env.clock())
    assert owner.run_id == "r-crashed"
    report = env.run(run_id="r-after")
    assert report.ok, report.aborted
    events = env.events(run="r-after")
    assert events.index(("recovered", "agent-01")) < events.index(("started", "agent-01"))
    assert env.greeting("agent-01") == GREETING_V2
    recovered = [r for r in env.ledger_records() if r.event == "recovered"][0]
    assert "r-crashed" in recovered.detail


# -- bake checks and ledger failures ----------------------------------------------------


def test_a_target_that_degrades_during_the_bake_halts_the_next_wave(tmp_path):
    env = Env(tmp_path)

    def bake_sleep(seconds):
        env.slept.append(seconds)
        if seconds == 30:
            env.agents["agent-01"].health = healthy(b'{"status":"degraded"}')

    report = RolloutRunner(env.fleet, env.plan(), executor_for=env.executor_for,
                           state=env.state, operator="ops.oncall", ticket=env.ticket(),
                           clock=env.clock, sleep=bake_sleep, bake_seconds=30,
                           run_id="r-bake").run()
    assert not report.ok and report.halted_at == "agent-01"
    assert env.untouched("agent-04", "agent-05", "agent-02")
    assert env.state.ledger().halt_record(env.patch.id) is not None
    assert 30 in env.slept


def test_a_ledger_append_failure_after_apply_restores_the_target(tmp_path, monkeypatch):
    env = Env(tmp_path)
    real_append = Ledger.append

    def failing_append(self, **kw):
        if kw.get("event") == "verified":
            raise OSError("No space left on device")
        return real_append(self, **kw)

    monkeypatch.setattr(Ledger, "append", failing_append)
    report = env.run()
    assert not report.ok and "ledger" in report.aborted
    assert env.greeting("agent-01") == ORIGINAL
    assert env.untouched("agent-04", "agent-05", "agent-02", "agent-03")


def test_a_ledger_that_cannot_be_written_stops_the_run_cleanly(tmp_path, monkeypatch):
    env = Env(tmp_path)

    def broken_append(self, **kw):
        raise OSError("Read-only file system")

    monkeypatch.setattr(Ledger, "append", broken_append)
    report = env.run()
    assert not report.ok and "ledger could not be written" in report.aborted
    assert env.untouched(*env.agents)                      # nothing mutated without a record
    assert not (env.state.root / "run.lock").exists()


# -- manual rollback and break-glass -------------------------------------------------


def test_a_manual_rollback_restores_the_recorded_pre_state(tmp_path):
    env = Env(tmp_path)
    assert env.run().ok
    result = rollback_target(env.fleet, env.patch, "agent-02", executor_for=env.executor_for,
                             state=env.state, operator="ops.oncall", ticket=env.ticket(),
                             clock=env.clock, sleep=lambda s: None)
    assert result.ok, result.detail
    assert env.greeting("agent-02") == ORIGINAL
    assert env.state.ledger().target_states(env.patch.id)["agent-02"].event == "manual_rollback"


def test_a_manual_rollback_needs_a_covering_ticket_and_consent(tmp_path):
    env = Env(tmp_path)
    env.approve("agent-03", "ops.oncall", "eng.lead")
    assert env.run(plan=env.plan(include_customer=True)).ok
    write_ticket(env.fleet, "CHG-3000", targets=("agent-01",))
    with pytest.raises(RolloutError, match="does not cover"):
        rollback_target(env.fleet, env.patch, "agent-02", executor_for=env.executor_for,
                        state=env.state, operator="ops.oncall", ticket=env.ticket("CHG-3000"),
                        clock=env.clock, sleep=lambda s: None)
    with pytest.raises(RolloutError, match="include-customer"):
        rollback_target(env.fleet, env.patch, "agent-03", executor_for=env.executor_for,
                        state=env.state, operator="ops.oncall", ticket=env.ticket(),
                        clock=env.clock, sleep=lambda s: None)


def test_rolling_back_a_target_the_patch_never_touched_is_refused(tmp_path):
    env = Env(tmp_path)
    with pytest.raises(RolloutError, match="no recorded run"):
        rollback_target(env.fleet, env.patch, "agent-02", executor_for=env.executor_for,
                        state=env.state, operator="ops.oncall", ticket=env.ticket(),
                        clock=env.clock, sleep=lambda s: None)


def test_breaking_a_lock_is_ledgered(tmp_path):
    env = Env(tmp_path)
    acquire(env.agents["agent-02"], ROOT, LockOwner("r-dead", "eng.lead", "x", T0.isoformat()))
    break_lock(env.fleet, "agent-02", executor_for=env.executor_for, state=env.state,
               operator="ops.oncall", ticket=env.ticket(), now=env.clock())
    [record] = [r for r in env.ledger_records() if r.event == "lock_broken"]
    assert record.target == "agent-02" and "r-dead" in record.detail
