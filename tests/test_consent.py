from datetime import UTC, datetime, timedelta

import pytest

from fleet_rollout.consent import ApprovalStore, consent_problem
from fleet_rollout.fleet import HealthCheck, Target
from fleet_rollout.validation import ValidationError

NOW = datetime(2026, 10, 12, 10, 0, tzinfo=UTC)
DIGEST = "d" * 64
HC = HealthCheck(port=8080, path="/healthz", expect_body="ok")


def target(name="agent-02", owner="customer"):
    return Target(name=name, host="edge-1.example.com", container=name, executor="ssh",
                  root="/srv/agent", owner=owner, cohort="bakeries", health=HC,
                  customer="Example Bakery" if owner == "customer" else None)


@pytest.fixture
def store(tmp_path):
    return ApprovalStore(tmp_path / "approvals.jsonl")


def approve(store, approver, *, digest=DIGEST, target_name="agent-02", at=NOW, ttl_hours=24):
    return store.add(patch_id="support-greeting-v2", digest=digest, target=target_name,
                     approver=approver, note="reviewed the diff", now=at,
                     ttl=timedelta(hours=ttl_hours))


def problem(store, t=None, include_customer=True, now=NOW):
    return consent_problem(t or target(), digest=DIGEST, store=store, now=now,
                           include_customer=include_customer)


def test_internal_targets_need_no_consent(store):
    assert problem(store, target("agent-01", "internal"), include_customer=False) is None


def test_customer_targets_are_held_back_without_the_explicit_flag(store):
    approve(store, "ops.oncall")
    approve(store, "eng.lead")
    assert "--include-customer" in problem(store, include_customer=False)


def test_one_approval_is_not_enough(store):
    approve(store, "ops.oncall")
    message = problem(store)
    assert "2 distinct approvals" in message and "ops.oncall" in message


def test_the_same_person_approving_twice_counts_once(store):
    approve(store, "ops.oncall")
    approve(store, "ops.oncall")
    assert problem(store) is not None


def test_two_distinct_approvers_unlock_the_target(store):
    approve(store, "ops.oncall")
    approve(store, "eng.lead")
    assert problem(store) is None


def test_approvals_are_bound_to_the_patch_digest(store):
    approve(store, "ops.oncall", digest="e" * 64)   # approved an earlier version of the patch
    approve(store, "eng.lead")
    assert problem(store) is not None


def test_approvals_are_bound_to_the_target(store):
    approve(store, "ops.oncall", target_name="agent-04")
    approve(store, "eng.lead")
    assert problem(store) is not None


def test_expired_approvals_do_not_count(store):
    approve(store, "ops.oncall", at=NOW - timedelta(hours=30))
    approve(store, "eng.lead")
    assert problem(store) is not None


def test_approver_ids_are_canonical_lowercase(store):
    with pytest.raises(ValidationError):
        approve(store, "Ops.Oncall")


def test_the_store_is_append_only_jsonl(store):
    approve(store, "ops.oncall")
    approve(store, "eng.lead")
    assert len(store.path.read_text().splitlines()) == 2
    assert [a.approver for a in store.all()] == ["ops.oncall", "eng.lead"]
