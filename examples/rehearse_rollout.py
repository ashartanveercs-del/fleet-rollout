"""Rehearse a rollout of the example fleet against simulated agents: no Docker, no SSH.

    python examples/rehearse_rollout.py

It copies examples/ to a temporary directory (so no state lands in the repo), simulates
the five agents from the golden template with the pre-change files from
simulation/live-before/ on top, and drives the real `fleet-rollout` CLI through a story:

  1. a hostile patch spec is refused before any plan exists
  2. drift shows the fleet lagging the golden template
  3. the plan: canary, one target per cohort, the rest; the customer target held back
  4. two people approve the customer-owned target
  5. apply: every target patched in waves, each one a verified transaction
  6. drift: every target now matches golden
  7. a patch that passes every syntax check but breaks health: the canary is restored
     and the rollout halts before any other target is touched
  8. status and ledger verification
"""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from pathlib import Path

from fleet_rollout.cli import main
from fleet_rollout.fleet import load_fleet
from fleet_rollout.testing import json_config_health, simulate_fleet

HERE = Path(__file__).resolve().parent


def settings_db() -> bytes:
    """A small settings database like the agents keep, with the v1 invoice template."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "settings.db"
        con = sqlite3.connect(path)
        con.execute("CREATE TABLE settings (name TEXT PRIMARY KEY, value TEXT)")
        con.execute("INSERT INTO settings VALUES ('invoice_template', 'v1')")
        con.commit()
        con.close()
        return path.read_bytes()


def live_before() -> dict[str, bytes]:
    root = HERE / "simulation" / "live-before"
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in sorted(root.rglob("*")) if p.is_file()}


def run(title: str, argv: list[str], factory, expect: int) -> None:
    print(f"\n### {title}\n$ fleet-rollout {' '.join(argv)}", flush=True)
    code = main(argv, executor_factory=factory, sleep=lambda seconds: None)
    print(f"(exit {code})", flush=True)
    if code != expect:
        raise SystemExit(f"unexpected exit code {code}; expected {expect}")


def rehearse() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "examples"
        shutil.copytree(HERE, work, ignore=shutil.ignore_patterns(".fleet-state", "__pycache__"))
        fleet = load_fleet(work / "fleet.yaml")
        agents = simulate_fleet(
            fleet, extra_files={**live_before(), "data/settings.db": settings_db()},
            health_for=lambda t: json_config_health(f"{t.root}/config/agent.json",
                                                    require={"enabled": True}))

        def factory(target):
            return agents[target.name]

        fleet_file = str(work / "fleet.yaml")

        def patch(name: str) -> str:
            return str(work / "patches" / f"{name}.yaml")

        run("1. hostile input is refused before a plan exists",
            ["validate", patch("hostile-example")], factory, 2)
        run("2. the canary lags the golden template in the two files this change touches",
            ["drift", "--fleet", fleet_file, "--targets", "agent-01"], factory, 1)
        run("3. the plan (the customer-owned target is held back)",
            ["plan", patch("support-greeting-v2"), "--fleet", fleet_file], factory, 0)
        for approver in ("ops.oncall", "eng.lead"):
            run(f"4. {approver} approves the customer-owned target",
                ["approve", patch("support-greeting-v2"), "--fleet", fleet_file,
                 "--target", "agent-03", "--approver", approver,
                 "--note", "reviewed the greeting and the refund rule"], factory, 0)
        run("5. apply, including the customer-owned target",
            ["apply", patch("support-greeting-v2"), "--fleet", fleet_file, "--ticket", "CHG-1042",
             "--operator", "ops.oncall", "--include-customer"], factory, 0)
        run("6. every target now matches the golden template",
            ["drift", "--fleet", fleet_file], factory, 0)
        run("7. a change that breaks health is caught on the canary, which is restored",
            ["apply", patch("agent-config-v3"), "--fleet", fleet_file, "--ticket", "CHG-1042",
             "--operator", "ops.oncall"], factory, 1)
        untouched = [n for n in ("agent-02", "agent-04", "agent-05")
                     if b"is_enabled" in agents[n].files["/srv/agent/config/agent.json"]]
        assert not untouched, untouched
        assert b'"enabled": true' in agents["agent-01"].files["/srv/agent/config/agent.json"]
        run("8a. the ledger records why the patch is frozen",
            ["status", patch("agent-config-v3"), "--fleet", fleet_file], factory, 0)
        run("8b. and its hash chain verifies", ["ledger", "verify", "--fleet", fleet_file],
            factory, 0)
        print("\nRehearsal finished: every step behaved as expected.")


if __name__ == "__main__":
    rehearse()
