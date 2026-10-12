"""The examples are part of the contract: they must load, validate and run."""

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from fleet_rollout.fleet import load_fleet
from fleet_rollout.spec import load_patch
from fleet_rollout.template import render_golden
from fleet_rollout.tickets import load_ticket, ticket_problem
from fleet_rollout.validation import ValidationError

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_the_example_fleet_loads_with_five_fictional_targets():
    fleet = load_fleet(EXAMPLES / "fleet.yaml")
    assert [t.name for t in fleet.targets] == [f"agent-0{i}" for i in range(1, 6)]
    assert all(t.host.endswith(".example.com") for t in fleet.targets)
    assert [t.name for t in fleet.targets if t.customer_owned] == ["agent-03"]


def test_the_golden_template_renders_for_every_target():
    fleet = load_fleet(EXAMPLES / "fleet.yaml")
    for target in fleet.targets:
        identity = render_golden(fleet.golden_dir, target)["config/identity.env"]
        assert f"AGENT_ID={target.name}\n".encode() in identity


@pytest.mark.parametrize("name", ["support-greeting-v2", "agent-config-v3"])
def test_the_example_patches_validate(name):
    assert load_patch(EXAMPLES / "patches" / f"{name}.yaml").id == name


def test_the_hostile_example_is_refused():
    with pytest.raises(ValidationError, match=r"steps\[0\]\.dest"):
        load_patch(EXAMPLES / "patches" / "hostile-example.yaml")


def test_the_example_ticket_covers_the_whole_example_fleet():
    fleet = load_fleet(EXAMPLES / "fleet.yaml")
    ticket = load_ticket(fleet.tickets_dir, "CHG-1042")
    assert ticket_problem(ticket, fleet.targets, datetime(2026, 10, 12, tzinfo=UTC)) is None


def test_the_hook_wiring_points_at_the_guard():
    settings = json.loads((EXAMPLES / "claude-settings.json").read_text())
    [entry] = settings["hooks"]["PreToolUse"]
    assert "Bash" in entry["matcher"] and "Write" in entry["matcher"]
    assert entry["hooks"][0]["command"].startswith("fleet-rollout-guard --fleet")


def test_the_rehearsal_runs_end_to_end():
    proc = subprocess.run([sys.executable, str(EXAMPLES / "rehearse_rollout.py")],
                          capture_output=True, timeout=300, check=False)
    assert proc.returncode == 0, proc.stdout.decode()[-2000:] + proc.stderr.decode()[-2000:]
    assert b"Rehearsal finished" in proc.stdout
