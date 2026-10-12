"""The `fleet-rollout` CLI, end to end, with simulated agents behind the executor seam."""

import hashlib
import io
import json

import pytest
from fakes import Clock

from fleet_rollout.cli import main
from fleet_rollout.fleet import load_fleet
from fleet_rollout.locks import LockOwner, acquire, lock_path
from fleet_rollout.testing import json_config_health, simulate_fleet

OLD_GREETING = b"Hello! You are chatting with the Example Bakery assistant.\n"
NEW_GREETING = b"Thanks for reaching out to Example Bakery support!\n"

FLEET = """\
fleet: support-agents
golden: golden
tickets_dir: tickets
state_dir: state
defaults:
  executor: ssh
  root: /srv/agent
  health: {port: 8080, path: /healthz, expect_json: {status: ok}, retries: 1}
targets:
  - {name: agent-01, host: edge-1.example.com, owner: internal, cohort: staff, canary: true}
  - {name: agent-02, host: edge-1.example.com, owner: internal, cohort: staff}
  - {name: agent-03, host: edge-2.example.com, owner: customer, cohort: bakeries,
     customer: Example Bakery}
  - {name: agent-04, host: edge-2.example.com, owner: internal, cohort: bakeries}
  - {name: agent-05, host: edge-3.example.com, owner: internal, cohort: cafes}
"""

PATCH = f"""\
id: greeting-v2
description: Friendlier support greeting
steps:
  - kind: write_file
    source: files/greeting.txt
    dest: config/greeting.txt
    expect_sha256: {hashlib.sha256(OLD_GREETING).hexdigest()}
verify:
  - file: config/greeting.txt
    contains: Thanks for reaching out
"""


class Project:
    def __init__(self, root):
        self.root = root
        (root / "fleet.yaml").write_text(FLEET)
        golden = root / "golden" / "config"
        golden.mkdir(parents=True)
        (golden / "greeting.txt").write_bytes(OLD_GREETING)
        (golden / "agent.json").write_text('{"agent_id": "{{ fleet.target.name }}", '
                                           '"enabled": true}\n')
        (root / "tickets").mkdir()
        (root / "tickets" / "CHG-1042.yaml").write_text(
            "id: CHG-1042\nsummary: greeting v2\ntargets: ['*', agent-03]\n"
            "expires: 2099-01-01T00:00:00Z\napproved_by: [ops.oncall, eng.lead]\n")
        patches = root / "patches"
        (patches / "files").mkdir(parents=True)
        (patches / "files" / "greeting.txt").write_bytes(NEW_GREETING)
        (patches / "greeting-v2.yaml").write_text(PATCH)
        self.fleet = load_fleet(root / "fleet.yaml")
        self.agents = simulate_fleet(self.fleet, health_for=lambda t: json_config_health(
            f"{t.root}/config/agent.json", require={"enabled": True}))
        self.clock = Clock()

    def run(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = main(list(argv), executor_factory=lambda t: self.agents[t.name],
                    clock=self.clock, sleep=lambda s: None, stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    @property
    def patch(self):
        return str(self.root / "patches" / "greeting-v2.yaml")

    @property
    def fleet_file(self):
        return str(self.root / "fleet.yaml")

    def greeting(self, name):
        return self.agents[name].files["/srv/agent/config/greeting.txt"]


@pytest.fixture
def project(tmp_path):
    return Project(tmp_path)


def test_validate_prints_the_digest_and_steps(project):
    code, out, _ = project.run("validate", project.patch)
    assert code == 0
    assert "greeting-v2" in out and "write_file config/greeting.txt" in out
    assert "digest" in out


def test_validate_refuses_hostile_input_with_exit_2(project):
    (project.root / "patches" / "evil.yaml").write_text(
        "id: evil\ndescription: x\nsteps:\n  - kind: write_file\n    source: files/greeting.txt\n"
        "    dest: ../../etc/cron.d/backdoor\n")
    code, _, err = project.run("validate", str(project.root / "patches" / "evil.yaml"))
    assert code == 2 and "steps[0].dest" in err


def test_plan_shows_waves_held_back_targets_and_golden_lag(project):
    code, out, _ = project.run("plan", project.patch, "--fleet", project.fleet_file)
    assert code == 0
    assert out.index("agent-01") < out.index("agent-04") < out.index("agent-02")
    assert "held back" in out.lower() and "agent-03" in out
    assert "golden" in out.lower()                       # golden template not updated
    assert all(not a.calls for a in project.agents.values())   # planning touches nothing


def test_plan_with_customers_is_blocked_until_two_people_approve(project):
    code, out, _ = project.run("plan", project.patch, "--fleet", project.fleet_file,
                               "--include-customer")
    assert code == 1 and "BLOCKED" in out
    for approver in ("ops.oncall", "eng.lead"):
        code, out, _ = project.run("approve", project.patch, "--fleet", project.fleet_file,
                                   "--target", "agent-03", "--approver", approver,
                                   "--note", "reviewed the greeting text")
        assert code == 0
    assert "2 of 2" in out
    code, out, _ = project.run("plan", project.patch, "--fleet", project.fleet_file,
                               "--include-customer")
    assert code == 0 and "BLOCKED" not in out


def test_apply_requires_a_ticket(project):
    code, _, err = project.run("apply", project.patch, "--fleet", project.fleet_file,
                               "--operator", "ops.oncall")
    assert code == 2 and "--ticket" in err


def test_apply_rolls_out_and_the_ledger_verifies(project):
    code, out, _ = project.run("apply", project.patch, "--fleet", project.fleet_file,
                               "--ticket", "CHG-1042", "--operator", "ops.oncall")
    assert code == 0, out
    assert all(project.greeting(n) == NEW_GREETING
               for n in ("agent-01", "agent-02", "agent-04", "agent-05"))
    assert project.greeting("agent-03") == OLD_GREETING
    assert out.count("verified") >= 4
    code, out, _ = project.run("ledger", "verify", "--fleet", project.fleet_file)
    assert code == 0 and "head" in out
    code, out, _ = project.run("status", project.patch, "--fleet", project.fleet_file)
    assert code == 0
    assert "agent-01" in out and "verified" in out and "agent-03" in out


def test_a_failed_rollout_exits_1_and_says_where_it_halted(project):
    project.agents["agent-04"].fail("rename", "config/greeting.txt")
    code, out, _ = project.run("apply", project.patch, "--fleet", project.fleet_file,
                               "--ticket", "CHG-1042", "--operator", "ops.oncall")
    assert code == 1
    assert "HALTED at agent-04" in out and "rolled_back" in out
    assert project.greeting("agent-04") == OLD_GREETING
    code, out, _ = project.run("status", project.patch, "--fleet", project.fleet_file)
    assert "HALTED" in out
    code, _, err = project.run("apply", project.patch, "--fleet", project.fleet_file,
                               "--ticket", "CHG-1042", "--operator", "ops.oncall")
    assert code == 3 and "halted" in err
    code, out, _ = project.run("clear-halt", "greeting-v2", "--fleet", project.fleet_file,
                               "--operator", "ops.oncall", "--reason", "disk remounted rw")
    assert code == 0
    code, _, err = project.run("clear-halt", "greeting-v2", "--fleet", project.fleet_file,
                               "--operator", "ops.oncall", "--reason", "again")
    assert code == 3 and "not halted" in err
    code, out, _ = project.run("apply", project.patch, "--fleet", project.fleet_file,
                               "--ticket", "CHG-1042", "--operator", "ops.oncall")
    assert code == 0 and "skipped" in out


def test_rollback_restores_one_target(project):
    project.run("apply", project.patch, "--fleet", project.fleet_file, "--ticket", "CHG-1042",
                "--operator", "ops.oncall")
    code, out, _ = project.run("rollback", project.patch, "--fleet", project.fleet_file,
                               "--target", "agent-02", "--ticket", "CHG-1042",
                               "--operator", "ops.oncall")
    assert code == 0, out
    assert project.greeting("agent-02") == OLD_GREETING


def test_rollback_refuses_to_overwrite_a_later_change_unless_forced(project):
    project.run("apply", project.patch, "--fleet", project.fleet_file, "--ticket", "CHG-1042",
                "--operator", "ops.oncall")
    project.agents["agent-02"].put("/srv/agent/config/greeting.txt", b"edited later by hand\n")
    argv = ["rollback", project.patch, "--fleet", project.fleet_file, "--target", "agent-02",
            "--ticket", "CHG-1042", "--operator", "ops.oncall"]
    code, _, err = project.run(*argv)
    assert code == 3 and "changed since" in err and "--force" in err
    assert project.greeting("agent-02") == b"edited later by hand\n"
    code, out, _ = project.run(*argv, "--force")
    assert code == 0, out
    assert project.greeting("agent-02") == OLD_GREETING


def test_drift_shows_unified_diffs_and_exits_1(project):
    code, out, _ = project.run("drift", "--fleet", project.fleet_file)
    assert code == 0 and "in sync" in out
    project.agents["agent-05"].put("/srv/agent/config/greeting.txt", b"hand edited\n")
    code, out, _ = project.run("drift", "--fleet", project.fleet_file)
    assert code == 1
    assert "agent-05" in out and "+hand edited" in out and "-Hello!" in out


def test_unlock_breaks_a_stale_lock_with_a_ticket(project):
    acquire(project.agents["agent-02"], "/srv/agent",
            LockOwner("r-dead", "eng.lead", "greeting-v2", "2026-10-12T07:00:00+00:00"))
    code, out, _ = project.run("locks", "--fleet", project.fleet_file)
    assert code == 0 and "STALE" in out and "r-dead" in out
    code, out, _ = project.run("unlock", "agent-02", "--fleet", project.fleet_file,
                               "--ticket", "CHG-1042", "--operator", "ops.oncall")
    assert code == 0 and "r-dead" in out
    assert lock_path("/srv/agent") not in project.agents["agent-02"].files


def test_a_tampered_ledger_fails_verification(project):
    project.run("apply", project.patch, "--fleet", project.fleet_file, "--ticket", "CHG-1042",
                "--operator", "ops.oncall")
    ledger = project.root / "state" / "ledger.jsonl"
    lines = ledger.read_bytes().splitlines()
    doc = json.loads(lines[1])
    doc["operator"] = "someone.else"
    lines[1] = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    ledger.write_bytes(b"\n".join(lines) + b"\n")
    code, out, _ = project.run("ledger", "verify", "--fleet", project.fleet_file)
    assert code == 1 and "BROKEN" in out


@pytest.mark.parametrize("argv, message", [
    (["apply", "{patch}", "--fleet", "{fleet}", "--ticket", "CHG-1042", "--operator", "Bad Name"],
     "operator"),
    (["plan", "{patch}", "--fleet", "{fleet}", "--targets", "agent-09"], "agent-09"),
    (["plan", "{patch}", "--fleet", "{fleet}", "--canary", "agent-03", "--include-customer"],
     "customer-owned"),
    (["apply", "{patch}", "--fleet", "{fleet}", "--ticket", "CHG-9999", "--operator", "ops.oncall"],
     "no such ticket"),
])
def test_bad_input_is_reported_not_raised(project, argv, message):
    argv = [a.format(patch=project.patch, fleet=project.fleet_file) for a in argv]
    code, _, err = project.run(*argv)
    assert code in (2, 3) and message in err


def test_commands_that_write_state_always_use_the_fleets_state_dir(project, tmp_path_factory):
    # Regression: `apply --state <dir>` read approvals from, checked halts in, and wrote the
    # ledger to whatever directory it was given, so two forged approvals in a private
    # directory patched a customer-owned target and the real ledger never saw it.
    elsewhere = tmp_path_factory.mktemp("elsewhere")
    as_ops = ["--operator", "ops.oncall"]
    for argv in (["apply", project.patch, "--ticket", "CHG-1042", "--include-customer", *as_ops],
                 ["rollback", project.patch, "--target", "agent-02", "--ticket", "CHG-1042",
                  *as_ops],
                 ["unlock", "agent-02", "--ticket", "CHG-1042", *as_ops],
                 ["unlock", "--run-lock", "--ticket", "CHG-1042", *as_ops],
                 ["approve", project.patch, "--target", "agent-03", "--approver", "eng.lead",
                  "--note", "looks right"],
                 ["clear-halt", "greeting-v2", "--reason", "fixed", *as_ops]):
        code, _, err = project.run(*argv, "--fleet", project.fleet_file,
                                   "--state", str(elsewhere))
        assert code == 2 and "state directory" in err, (argv, err)
    assert list(elsewhere.iterdir()) == []
    assert all(not agent.mutations for agent in project.agents.values())


def test_the_fleets_own_state_dir_may_be_named_explicitly(project):
    code, _, _ = project.run("apply", project.patch, "--fleet", project.fleet_file,
                             "--ticket", "CHG-1042", "--operator", "ops.oncall",
                             "--state", str(project.root / "state"))
    assert code == 0 and (project.root / "state" / "ledger.jsonl").is_file()


def test_read_only_commands_can_inspect_another_state_dir(project, tmp_path_factory):
    project.run("apply", project.patch, "--fleet", project.fleet_file, "--ticket", "CHG-1042",
                "--operator", "ops.oncall")
    copy = tmp_path_factory.mktemp("copy") / "state"
    copy.mkdir()
    (copy / "ledger.jsonl").write_bytes((project.root / "state" / "ledger.jsonl").read_bytes())
    code, out, _ = project.run("status", project.patch, "--fleet", project.fleet_file,
                               "--state", str(copy))
    assert code == 0 and "verified" in out
    code, out, _ = project.run("ledger", "verify", "--fleet", project.fleet_file,
                               "--state", str(copy))
    assert code == 0 and "ledger OK" in out


def test_long_options_must_be_spelled_out(project):
    # argparse accepts unique prefixes by default (`--fle` for `--fleet`), which let a
    # command line say one thing to a reviewer or the guard and another to the CLI.
    code, _, err = project.run("apply", project.patch, "--fle", project.fleet_file,
                               "--ticket", "CHG-1042", "--operator", "ops.oncall")
    assert code == 2 and "--fle" in err
    assert all(not agent.mutations for agent in project.agents.values())
