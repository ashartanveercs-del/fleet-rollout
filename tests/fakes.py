"""Builders shared by the engine tests: targets, patch bundles and seeded fake agents."""

from __future__ import annotations

import sqlite3
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fleet_rollout.fleet import Fleet, HealthCheck, Target
from fleet_rollout.spec import Patch, parse_patch
from fleet_rollout.testing import FakeExecutor, json_config_health

ROOT = "/srv/agent"
T0 = datetime(2026, 10, 12, 10, 0, tzinfo=UTC)
HEALTH = HealthCheck(port=8080, path="/healthz", expect_json={"status": "ok"}, retries=2,
                     interval_seconds=0)

AGENT_JSON = b'{"model": "small", "escalate_to": "support@example.com", "enabled": true}\n'
WORKSPACE = {
    "config/agent.json": AGENT_JSON,
    "config/greeting.txt": b"Hello! You are chatting with the Example Bakery assistant.\n",
    "prompts/support.md": b"# Support rules\n- Be kind.\n",
    "handlers/invoices.py": b"def total(lines):\n    return sum(lines)\n",
}


class Clock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw) -> None:
        self.now += timedelta(**kw)


def make_target(name="agent-01", *, owner="internal", cohort="staff", canary=False,
                host="edge-1.example.com", health=HEALTH) -> Target:
    return Target(name=name, host=host, container=name, executor="ssh", root=ROOT,
                  owner=owner, cohort=cohort, canary=canary, health=health,
                  customer="Example Bakery" if owner == "customer" else None)


def settings_db() -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "settings.db"
        con = sqlite3.connect(path)
        con.execute("CREATE TABLE settings (name TEXT PRIMARY KEY, value TEXT)")
        con.execute("INSERT INTO settings VALUES ('invoice_template', 'v1')")
        con.commit()
        con.close()
        return path.read_bytes()


def db_value(fx: FakeExecutor, key: str = "invoice_template") -> str | None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "copy.db"
        path.write_bytes(fx.files[f"{ROOT}/data/settings.db"])
        con = sqlite3.connect(path)
        try:
            row = con.execute("SELECT value FROM settings WHERE name = ?", (key,)).fetchone()
        finally:
            con.close()
        return row[0] if row else None


def agent(name="agent-01", files=None, *, health=None, with_db=False) -> FakeExecutor:
    """A fake agent whose health depends on the JSON config it has *loaded*."""
    seeded = {f"{ROOT}/{rel}": data for rel, data in (files or WORKSPACE).items()}
    if with_db:
        seeded[f"{ROOT}/data/settings.db"] = settings_db()
    fx = FakeExecutor(name, seeded,
                      health=health or json_config_health(f"{ROOT}/config/agent.json",
                                                          require={"enabled": True}))
    fx.mkdir(ROOT)
    return fx


def make_fleet(tmp_path: Path, targets, *, golden: Path | None = None) -> Fleet:
    tickets = tmp_path / "tickets"
    tickets.mkdir(parents=True, exist_ok=True)
    return Fleet(name="support-agents", targets=tuple(targets), base_dir=tmp_path,
                 state_dir=tmp_path / "state", golden_dir=golden, tickets_dir=tickets)


def five_targets() -> list[Target]:
    """agent-01 is the canary; cohorts: staff (01, 02), bakeries (03 customer, 04), cafes (05)."""
    return [make_target("agent-01", cohort="staff", canary=True),
            make_target("agent-02", cohort="staff"),
            make_target("agent-03", cohort="bakeries", owner="customer"),
            make_target("agent-04", cohort="bakeries", host="edge-2.example.com"),
            make_target("agent-05", cohort="cafes", host="edge-2.example.com")]


def write_ticket(fleet: Fleet, tid: str = "CHG-1042", *, targets=("*",),
                 approvers=("ops.oncall", "eng.lead"),
                 expires: str = "2099-12-31T00:00:00Z") -> str:
    items = ", ".join(f"'{t}'" for t in targets)
    (fleet.tickets_dir / f"{tid}.yaml").write_text(
        f"id: {tid}\nsummary: Roll a patch to the support agents\ntargets: [{items}]\n"
        f"expires: {expires}\napproved_by: [{', '.join(approvers)}]\n", encoding="utf-8")
    return tid


def bundle(tmp_path: Path, files: dict[str, bytes]) -> Path:
    root = tmp_path / "bundle"
    for rel, data in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    root.mkdir(exist_ok=True)
    return root


def make_patch(tmp_path: Path, steps: list[dict], *, files: dict[str, bytes] | None = None,
               verify: list[dict] | None = None, pid: str = "demo-patch") -> Patch:
    doc = {"id": pid, "description": "demo change", "steps": steps}
    if verify is not None:
        doc["verify"] = verify
    return parse_patch(doc, bundle_dir=bundle(tmp_path, files or {}), source=f"{pid}.yaml")
