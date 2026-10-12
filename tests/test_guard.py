"""The PreToolUse guard, driven through its real entry point with hook payloads."""

import io
import json
import subprocess
import sys
from datetime import UTC, datetime

import pytest

from fleet_rollout.guard.hook import main

NOW = datetime(2026, 10, 12, 10, 0, tzinfo=UTC)

FLEET = """\
fleet: support-agents
tickets_dir: tickets
state_dir: .fleet-state
defaults:
  executor: ssh
  root: /srv/agent
  health: {port: 8080, path: /healthz, expect_json: {status: ok}}
targets:
  - {name: agent-01, host: edge-1.example.com, owner: internal, cohort: staff, canary: true}
  - {name: agent-02, host: edge-1.example.com, owner: internal, cohort: staff}
  - {name: agent-03, host: edge-2.example.com, owner: customer, cohort: bakeries,
     customer: Example Bakery}
  - {name: agent-04, host: edge-2.example.com, owner: internal, cohort: bakeries,
     container: support-agent-04}
  - {name: agent-05, host: edge-3.example.com, owner: internal, cohort: cafes}
"""

TICKETS = {
    "CHG-1042": ("['*', agent-03]", "[ops.oncall, eng.lead]", "2099-01-01T00:00:00Z"),
    "CHG-2001": ("[agent-01]", "[ops.oncall]", "2099-01-01T00:00:00Z"),
    "CHG-3003": ("[agent-03]", "[ops.oncall]", "2099-01-01T00:00:00Z"),
    "CHG-0999": ("['*']", "[ops.oncall]", "2026-01-01T00:00:00Z"),
}


@pytest.fixture
def project(tmp_path):
    (tmp_path / "fleet.yaml").write_text(FLEET)
    tickets = tmp_path / "tickets"
    tickets.mkdir()
    for tid, (targets, approvers, expires) in TICKETS.items():
        (tickets / f"{tid}.yaml").write_text(
            f"id: {tid}\nsummary: test ticket\ntargets: {targets}\nexpires: {expires}\n"
            f"approved_by: {approvers}\n")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "restart-all.sh").write_text(
        "#!/bin/sh\nfor c in agent-01 agent-02; do\n  docker restart agent-01\ndone\n")
    (tmp_path / "scripts" / "report.sh").write_text("#!/bin/sh\ndocker ps\ndf -h\n")
    # Two scripts with the same name: which one runs depends on the working directory.
    (tmp_path / "status.sh").write_text("#!/bin/sh\ndocker ps\n")
    (tmp_path / "scripts" / "status.sh").write_text("#!/bin/sh\ndocker restart agent-01\n")
    return tmp_path


def hook(project, payload, *extra_args):
    out = io.StringIO()
    stdin = io.StringIO(payload if isinstance(payload, str) else json.dumps(payload))
    code = main(["--fleet", str(project / "fleet.yaml"), *extra_args], stdin=stdin, stdout=out,
                now=NOW)
    assert code == 0
    text = out.getvalue().strip()
    return json.loads(text) if text else None


def bash(project, command):
    return hook(project, {"session_id": "s", "hook_event_name": "PreToolUse",
                          "tool_name": "Bash", "cwd": str(project),
                          "tool_input": {"command": command}})


def denied(result):
    if result is None:
        return None
    out = result["hookSpecificOutput"]
    assert out["hookEventName"] == "PreToolUse" and out["permissionDecision"] == "deny"
    return out["permissionDecisionReason"]


ALLOW = [
    "docker ps -a",
    "docker inspect agent-01",
    "docker logs --tail 50 agent-02",
    "docker restart my-postgres",                       # not a fleet container
    "docker exec agent-01 cat /srv/agent/config/agent.json",
    "docker exec -it agent-01 sh -c 'cat /srv/agent/x | grep model'",
    "docker exec agent-01 sqlite3 /srv/agent/data/settings.db 'SELECT * FROM settings'",
    "docker exec agent-01 curl -s http://127.0.0.1:8080/healthz",
    "docker cp agent-01:/srv/agent/logs/app.log ./app.log",
    "docker compose ps",
    "ssh edge-1.example.com 'docker logs agent-01 | tail -n 20'",
    "ssh edge-1.example.com uptime",
    "ssh -p 2222 ops@edge-2.example.com docker ps",
    "ssh build.example.org make release",               # not a fleet host
    "scp edge-1.example.com:/var/log/syslog ./syslog",
    "echo 'docker restart agent-01'",                   # text, never executed
    "git commit -m 'fix agent-02 greeting'",
    "grep -r agent-03 notes/",
    "CHANGE_TICKET=CHG-1042 docker restart agent-01",
    "CHANGE_TICKET=CHG-1042 ssh edge-1.example.com docker restart agent-02",
    "CHANGE_TICKET=CHG-2001 docker kill -s HUP agent-01",
    "CHANGE_TICKET=CHG-1042 docker restart agent-03",   # customer: ticket names it, 2 approvers
    "CHANGE_TICKET=CHG-1042 docker restart support-agent-04",
    "CHANGE_TICKET=CHG-1042 python manage.py restart agent-02",
    "fleet-rollout plan patches/greeting-v2.yaml --fleet fleet.yaml",
    "fleet-rollout validate patches/greeting-v2.yaml",
    "fleet-rollout apply patches/greeting-v2.yaml --fleet fleet.yaml --ticket CHG-1042",
    "python -m fleet_rollout drift --fleet fleet.yaml",
    "cat tickets/CHG-1042.yaml",
    "ls -la .fleet-state",
    "bash scripts/report.sh",
    "pytest -q && ruff check src tests",
]


@pytest.mark.parametrize("command", ALLOW)
def test_allowed_commands(project, command):
    assert bash(project, command) is None


DENY = [
    ("docker restart agent-01", "CHANGE_TICKET"),
    ("docker rm -f agent-02", "agent-02"),
    ("docker container stop agent-01", "agent-01"),
    ("docker -H ssh://edge-1.example.com restart agent-01", "agent-01"),
    ("docker -H ssh://edge-1.example.com restart edge-proxy", "edge-1.example.com"),
    ("DOCKER_HOST=ssh://edge-1.example.com docker restart edge-proxy", "edge-1.example.com"),
    ("env DOCKER_HOST=ssh://ops@edge-2.example.com docker stop edge-proxy", "agent-04"),
    ("sudo docker restart agent-01", "agent-01"),
    ("env FOO=1 docker kill agent-05", "agent-05"),
    ("timeout 30 docker restart agent-05", "agent-05"),
    ("docker restart support-agent-04", "agent-04"),
    ("docker exec agent-01 rm -rf /srv/agent/cache", "agent-01"),
    ("docker exec agent-01 sh -c 'echo x > /srv/agent/config/greeting.txt'", "agent-01"),
    ("docker exec agent-01 sqlite3 /srv/agent/data/settings.db 'UPDATE settings SET v=1'",
     "agent-01"),
    ("docker exec agent-01 curl -X POST http://127.0.0.1:8080/admin/reload", "agent-01"),
    ("docker exec -i agent-01 sh < local-script.sh", "agent-01"),
    ("docker cp ./greeting.txt agent-01:/srv/agent/config/greeting.txt", "agent-01"),
    ("docker rm -f $(docker ps -aq)", "computed at run time"),
    ("for c in agent-01 agent-02; do docker restart $c; done", "computed at run time"),
    ("docker ps -q | xargs docker restart", "computed at run time"),
    ("find . -name '*.pid' -exec docker restart {} \\;", "computed at run time"),
    ("docker compose down", "name the services"),
    ("ssh edge-1.example.com docker restart agent-01", "agent-01"),
    ("ssh edge-1.example.com reboot", "agent-02"),       # every target on that host
    ("ssh edge-1.example.com", "interactive"),
    ("ssh edge-2.example.com <<'EOF'\ndocker restart agent-04\nEOF", "agent-04"),
    ("ssh build.example.org docker restart agent-01", "agent-01"),
    ("scp greeting.txt edge-1.example.com:/srv/agent/config/", "edge-1.example.com"),
    ("rsync -a ./golden/ ops@edge-3.example.com:/srv/agent/", "agent-05"),
    ("bash -c 'docker restart agent-01'", "agent-01"),
    ("bash <<'EOF'\ndocker restart agent-01\nEOF", "agent-01"),
    ("eval 'docker restart agent-01'", "agent-01"),
    ("echo 'docker restart agent-01' | bash", "pipe"),
    ("bash scripts/restart-all.sh", "agent-01"),
    ("C='docker restart agent-01'; $C", "computed at run time"),
    ("strace -f docker restart agent-01", "agent-01"),
    ("python manage.py restart agent-02", "agent-02"),
    ("CHANGE_TICKET=CHG-2001 docker restart agent-02", "does not cover agent-02"),
    ("CHANGE_TICKET=CHG-0999 docker restart agent-02", "expired"),
    ("CHANGE_TICKET=CHG-7777 docker restart agent-02", "no such ticket"),
    ("CHANGE_TICKET=../../etc/passwd docker restart agent-02", "ticket id"),
    ("CHANGE_TICKET=$T docker restart agent-02", "CHANGE_TICKET"),
    ("CHANGE_TICKET=CHG-3003 docker restart agent-03", "2 different people"),
    ("CHANGE_TICKET=CHG-1042 docker restart agent-01 && docker restart agent-02", "agent-02"),
    ("fleet-rollout apply patches/greeting-v2.yaml --fleet fleet.yaml", "CHANGE_TICKET"),
    ("fleet-rollout apply p.yaml --fleet fleet.yaml --ticket CHG-2001", "does not cover"),
    ("fleet-rollout approve p.yaml --target agent-03 --approver ops.oncall", "people"),
    ("fleet-rollout clear-halt greeting-v2 --reason fixed", "human"),
    ("CHANGE_TICKET=CHG-1042 fleet-rollout rollback p.yaml --target agent-02 --force", "human"),
    ("echo 'id: CHG-9000' > tickets/CHG-9000.yaml", "protected"),
    ("python -c \"open('tickets/CHG-9000.yaml', 'w').write('x')\"", "protected"),
    ("sed -i 's/customer/internal/' fleet.yaml", "protected"),
    ("rm .fleet-state/ledger.jsonl", "protected"),
    ("cp /tmp/settings.json .claude/settings.json", "protected"),
    ("echo 'unterminated", "cannot parse"),
]


@pytest.mark.parametrize("command, reason", DENY)
def test_denied_commands(project, command, reason):
    message = denied(bash(project, command))
    assert message is not None, f"expected a denial for: {command}"
    assert reason in message


# -- the fleet CLI is pinned to the fleet file the guard protects ----------------------

# A rollout pointed at another state directory skips its approvals, halts and ledger; one
# pointed at another fleet file can name targets, tickets and a state directory of its own.
PINNED_DENY = [
    ("fleet-rollout apply p.yaml --ticket CHG-1042 --include-customer --state /tmp/agent-state",
     "state directory"),
    ("fleet-rollout apply p.yaml --ticket CHG-1042 --state=/tmp/agent-state", "state directory"),
    ("fleet-rollout rollback p.yaml --target agent-01 --ticket CHG-1042 --state /tmp/s",
     "state directory"),
    ("fleet-rollout apply evil.yaml --fleet /tmp/evil-fleet.yaml --targets x1 --ticket CHG-1042",
     "fleet file"),
    ("fleet-rollout apply p.yaml --fleet=/tmp/evil-fleet.yaml --ticket CHG-1042", "fleet file"),
    ("fleet-rollout unlock agent-01 --ticket CHG-1042 --fleet /tmp/evil-fleet.yaml", "fleet file"),
    ("fleet-rollout apply p.yaml --fleet fleet.yaml --fleet /tmp/e.yaml --ticket CHG-1042",
     "fleet file"),                                      # the last one wins, as in argparse
    ("ssh build.example.org fleet-rollout apply p.yaml --ticket CHG-1042", "fleet file"),
    ("cd scripts && fleet-rollout apply ../p.yaml --ticket CHG-1042", "fleet file"),
    ('cd "$WORK" && fleet-rollout apply p.yaml --fleet fleet.yaml --ticket CHG-1042',
     "computed at run time"),
    ("env -C scripts fleet-rollout apply p.yaml --ticket CHG-1042", "fleet file"),
    ("sudo --chdir=scripts fleet-rollout apply p.yaml --ticket CHG-1042", "fleet file"),
    ("fleet-rollout apply p.yaml --fle /tmp/evil-fleet.yaml --ticket CHG-1042", "--fle"),
    ("fleet-rollout apply p.yaml --ticket CHG-1042 -x", "-x"),
    ("fleet-rollout apply p.yaml --targets agent-09 --ticket CHG-1042", "agent-09"),
    ("fleet-rollout rollback p.yaml --target x1 --ticket CHG-1042", "x1"),
    ("fleet-rollout apply p.yaml --ticket $T", "computed at run time"),
    ("python -m fleet_rollout.cli apply p.yaml --ticket CHG-1042 --state /tmp/s",
     "state directory"),
    ("python3 -I -m fleet_rollout apply p.yaml --fleet /tmp/e.yaml --ticket CHG-1042",
     "fleet file"),
    ("uv run fleet-rollout apply p.yaml --ticket CHG-1042 --state /tmp/s", "fleet-rollout"),
    ("python -c 'from fleet_rollout.cli import main; main([])'", "fleet_rollout"),
    ('f() { fleet-rollout "$@"; }; f apply p.yaml --ticket CHG-1042', "computed at run time"),
    ("find /tmp -name '*.yaml' -execdir fleet-rollout apply p.yaml --ticket CHG-1042 \\;",
     "computed at run time"),
    ("echo --state=/tmp/s | xargs fleet-rollout apply p.yaml --ticket CHG-1042",
     "appended at run time"),
    # The script that runs is the one in the directory the shell has changed into.
    ("cd scripts && bash status.sh", "agent-01"),
    ("cd scripts; ./status.sh", "agent-01"),
    ('cd "$DIR" && bash status.sh', "cannot read"),
]


@pytest.mark.parametrize("command, reason", PINNED_DENY)
def test_the_fleet_cli_cannot_be_pointed_at_other_state(project, command, reason):
    message = denied(bash(project, command))
    assert message is not None, f"expected a denial for: {command}"
    assert reason in message


PINNED_ALLOW = [
    "fleet-rollout apply p.yaml --ticket CHG-1042",                 # ./fleet.yaml is the guard's
    "fleet-rollout apply p.yaml --fleet ./fleet.yaml --ticket CHG-1042",
    "fleet-rollout apply p.yaml --fleet fleet.yaml --state .fleet-state --ticket CHG-1042",
    "fleet-rollout apply p.yaml --targets agent-01,agent-02 --ticket CHG-1042",
    "fleet-rollout rollback p.yaml --target agent-02 --ticket CHG-1042",
    "fleet-rollout unlock --run-lock --ticket CHG-1042",
    "python -m fleet_rollout apply p.yaml --ticket CHG-1042",
    "fleet-rollout apply --help",
    "fleet-rollout status p.yaml --state /tmp/elsewhere",            # read-only verbs
    "fleet-rollout ledger verify --fleet /tmp/other-fleet.yaml",
    "cd scripts && bash report.sh",
    "bash status.sh",
]


@pytest.mark.parametrize("command", PINNED_ALLOW)
def test_the_fleet_cli_on_its_own_fleet_is_allowed(project, command):
    assert bash(project, command) is None


def test_an_absolute_fleet_path_is_compared_by_location(project):
    fleet = (project / "fleet.yaml").as_posix()
    assert bash(project, f"cd /tmp; fleet-rollout apply p.yaml --fleet {fleet} "
                         "--ticket CHG-1042") is None


def test_the_default_fleet_file_is_the_one_in_the_commands_directory(project):
    other = project / "elsewhere"
    other.mkdir()
    (other / "fleet.yaml").write_text(FLEET)           # a copy the agent could have written
    result = hook(project, {"tool_name": "Bash", "cwd": str(other),
                            "tool_input": {"command": "fleet-rollout apply p.yaml "
                                                      "--ticket CHG-1042"}})
    assert "fleet file" in denied(result)


def test_write_and_edit_tools_cannot_touch_protected_files(project):
    for tool, key, path in [("Write", "file_path", "tickets/CHG-9000.yaml"),
                            ("Edit", "file_path", str(project / "fleet.yaml")),
                            ("MultiEdit", "file_path", ".fleet-state/approvals.jsonl"),
                            ("Write", "file_path", ".claude/settings.local.json")]:
        result = hook(project, {"tool_name": tool, "cwd": str(project),
                                "tool_input": {key: path, "content": "x"}})
        assert "protected" in denied(result), (tool, path)
    ok = hook(project, {"tool_name": "Write", "cwd": str(project),
                        "tool_input": {"file_path": "src/app.py", "content": "x"}})
    assert ok is None


def test_a_payload_cwd_that_does_not_exist_fails_closed(project):
    # Regression: an unusable cwd (e.g. an MSYS-style /d/... path on Windows) used to make
    # relative paths resolve somewhere harmless, so a protected write slipped through.
    bogus = str(project / "no" / "such" / "dir")
    write = hook(project, {"tool_name": "Write", "cwd": bogus,
                           "tool_input": {"file_path": "tickets/CHG-9000.yaml", "content": "x"}})
    assert "cwd" in denied(write)
    run = hook(project, {"tool_name": "Bash", "cwd": bogus,
                         "tool_input": {"command": "echo x > tickets/CHG-9000.yaml"}})
    assert "cwd" in denied(run)


def test_other_tools_are_not_the_guards_business(project):
    assert hook(project, {"tool_name": "Read", "cwd": str(project),
                          "tool_input": {"file_path": "fleet.yaml"}}) is None


@pytest.mark.parametrize("payload", ["not json", "[]", json.dumps({"tool_name": "Bash"}),
                                     json.dumps({"tool_name": "Bash",
                                                 "tool_input": {"command": ""}}),
                                     json.dumps({"tool_name": "Write", "tool_input": {}})])
def test_malformed_payloads_fail_closed(project, payload):
    assert denied(hook(project, payload)) is not None


def test_an_unreadable_fleet_file_allows_only_plain_reads(project):
    (project / "fleet.yaml").write_text("fleet: [unclosed\n")
    assert bash(project, "ls -la && cat README.md") is None
    assert "fleet file" in denied(bash(project, "docker restart anything"))
    assert "fleet file" in denied(bash(project, "python deploy.py"))


def test_extra_protected_paths(project):
    result = bash(project, "rm secrets/ops.env")
    assert result is None
    result = hook(project, {"tool_name": "Bash", "cwd": str(project),
                            "tool_input": {"command": "rm secrets/ops.env"}},
                  "--protect", str(project / "secrets"))
    assert "protected" in denied(result)


def test_the_installed_entry_point_speaks_the_hook_protocol(project):
    payload = json.dumps({"tool_name": "Bash", "cwd": str(project),
                          "tool_input": {"command": "docker restart agent-01"}})
    proc = subprocess.run([sys.executable, "-m", "fleet_rollout.guard.hook", "--fleet",
                           str(project / "fleet.yaml")], input=payload.encode(),
                          capture_output=True, timeout=60, check=False)
    assert proc.returncode == 0, proc.stderr
    decision = json.loads(proc.stdout)["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    allowed = subprocess.run([sys.executable, "-m", "fleet_rollout.guard.hook", "--fleet",
                              str(project / "fleet.yaml")],
                             input=payload.replace("restart", "inspect").encode(),
                             capture_output=True, timeout=60, check=False)
    assert allowed.returncode == 0 and allowed.stdout.strip() == b""
