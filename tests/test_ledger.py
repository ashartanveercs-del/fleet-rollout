import hashlib
import json
from datetime import UTC, datetime

import pytest

from fleet_rollout.ledger import GENESIS, Ledger, LedgerCorrupt

TS = datetime(2026, 10, 12, 10, 0, tzinfo=UTC)


def add(ledger, event, target=None, **kw):
    kw.setdefault("patch", "support-greeting-v2")
    kw.setdefault("digest", "d" * 64)
    return ledger.append(run="r-1", event=event, operator="ops.oncall", target=target,
                         ts=TS, **kw)


@pytest.fixture
def ledger(tmp_path):
    return Ledger(tmp_path / "ledger.jsonl")


def test_records_are_hash_chained(ledger):
    first = add(ledger, "run_started")
    second = add(ledger, "started", "agent-01")
    lines = ledger.path.read_bytes().splitlines()
    assert first.seq == 1 and first.prev == GENESIS
    assert second.seq == 2 and second.prev == hashlib.sha256(lines[0]).hexdigest()
    assert [r.event for r in ledger.records()] == ["run_started", "started"]


def test_verify_passes_on_an_untouched_ledger_and_reports_the_head(ledger):
    add(ledger, "run_started")
    add(ledger, "verified", "agent-01")
    report = ledger.verify()
    assert report.ok and report.count == 2
    assert report.head == hashlib.sha256(ledger.path.read_bytes().splitlines()[-1]).hexdigest()


def rewrite(ledger, mutate):
    lines = ledger.path.read_bytes().splitlines()
    mutate(lines)
    ledger.path.write_bytes(b"\n".join(lines) + b"\n")


def test_editing_a_past_record_is_detected(ledger):
    for event in ("run_started", "rolled_back", "run_finished"):
        add(ledger, event, "agent-01" if event == "rolled_back" else None,
            halt=event == "rolled_back")

    def soften(lines):
        doc = json.loads(lines[1])
        doc["halt"] = False          # someone tries to quietly un-halt the rollout
        lines[1] = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()

    rewrite(ledger, soften)
    report = ledger.verify()
    assert not report.ok and "record 3" in report.problem


def test_deleting_or_reordering_records_is_detected(ledger):
    for event in ("run_started", "started", "verified", "run_finished"):
        add(ledger, event, "agent-01")
    rewrite(ledger, lambda lines: lines.pop(1))
    assert not ledger.verify().ok
    other = Ledger(ledger.path.parent / "other.jsonl")
    for event in ("run_started", "started", "verified"):
        add(other, event, "agent-01")
    rewrite(other, lambda lines: lines.reverse())
    assert not other.verify().ok


def test_editing_the_last_record_changes_the_head(ledger):
    add(ledger, "run_started")
    add(ledger, "verified", "agent-01")
    pinned = ledger.verify().head

    def edit_tail(lines):
        doc = json.loads(lines[-1])
        doc["detail"] = "nothing to see"
        lines[-1] = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()

    rewrite(ledger, edit_tail)
    assert ledger.verify().head != pinned


def test_appending_to_a_corrupt_ledger_is_refused(ledger):
    add(ledger, "run_started")
    add(ledger, "started", "agent-01")
    rewrite(ledger, lambda lines: lines.pop(0))
    with pytest.raises(LedgerCorrupt):
        add(ledger, "verified", "agent-01")


def test_unknown_events_are_refused(ledger):
    with pytest.raises(ValueError, match="unknown ledger event"):
        add(ledger, "looks_fine")


def test_halt_is_sticky_until_explicitly_cleared(ledger):
    assert ledger.halt_record("support-greeting-v2") is None
    add(ledger, "rolled_back", "agent-02", halt=True, detail="health body degraded")
    assert ledger.halt_record("support-greeting-v2").target == "agent-02"
    assert ledger.halt_record("other-patch") is None
    add(ledger, "halt_cleared", detail="config fixed upstream")
    assert ledger.halt_record("support-greeting-v2") is None
    add(ledger, "rollback_failed", "agent-03", halt=True)
    assert ledger.halt_record("support-greeting-v2").target == "agent-03"


def test_latest_state_per_target(ledger):
    add(ledger, "started", "agent-01")
    add(ledger, "verified", "agent-01")
    add(ledger, "started", "agent-02")
    states = ledger.target_states("support-greeting-v2")
    assert states["agent-01"].event == "verified"
    assert states["agent-02"].event == "started"


def test_audit_only_events_do_not_change_a_targets_transaction_state(ledger):
    # Regression: breaking a crashed run's lock hid its interrupted `started` record.
    add(ledger, "started", "agent-01")
    add(ledger, "lock_broken", "agent-01", detail="broke the lock held by run r-crashed")
    add(ledger, "run_aborted", "agent-01", detail="bake failed", halt=True)
    assert ledger.target_states("support-greeting-v2")["agent-01"].event == "started"


def test_digests_seen_for_a_patch(ledger):
    add(ledger, "started", "agent-01", digest="a" * 64)
    add(ledger, "verified", "agent-01", digest="a" * 64)
    assert ledger.digests_for("support-greeting-v2") == {"a" * 64}
