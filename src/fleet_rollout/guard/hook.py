"""`fleet-rollout-guard`: a Claude Code PreToolUse hook that keeps an AI coding agent from
changing live fleet containers without an explicit change ticket.

Protocol: the hook payload arrives as JSON on stdin (`tool_name`, `tool_input`, `cwd`).
To block, print `{"hookSpecificOutput": {"hookEventName": "PreToolUse",
"permissionDecision": "deny", "permissionDecisionReason": ...}}` and exit 0. To allow,
print nothing: the guard never grants permission, it only takes it away, so the normal
permission prompts still apply to everything it lets through.

It fails closed. A payload it cannot read, a command it cannot parse, a container name it
cannot resolve, or any internal error is a denial with the reason spelled out.

    Bash                     every command it would run is classified (see classify.py)
    Write/Edit/MultiEdit/    refused for protected paths: change tickets, the state
    NotebookEdit             directory (ledger, approvals), the fleet file, hook settings

A Bash command that changes live targets is allowed only when it carries
`CHANGE_TICKET=<id>` (or `fleet-rollout apply --ticket <id>`) naming a ticket file that
is unexpired and covers every target it touches, with two approvers for customer-owned
targets.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

from ..fleet import Fleet, load_fleet
from ..tickets import load_ticket, ticket_problem
from ..validation import ValidationError
from .classify import Inventory, classify, only_reads
from .shell import ShellSyntaxError

EDIT_TOOLS = {"Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path",
              "NotebookEdit": "notebook_path"}


def deny_payload(reason: str) -> dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": "deny",
                                   "permissionDecisionReason": f"fleet-rollout guard: {reason}"}}


class Guard:
    def __init__(self, fleet_file: Path, *, project_dir: Path | None = None,
                 extra_protected: Sequence[Path] = (), now: datetime | None = None) -> None:
        self.fleet_file = Path(fleet_file).resolve()
        self.now = now or datetime.now(UTC)
        self.project_dir = project_dir
        self.extra_protected = list(extra_protected)
        self.fleet: Fleet | None = None
        self.fleet_error: str | None = None
        try:
            self.fleet = load_fleet(self.fleet_file)
        except (ValidationError, OSError) as exc:
            self.fleet_error = str(exc)

    def inventory(self, cwd: Path) -> Inventory:
        project = self.project_dir or cwd
        protected = [self.fleet_file, project / ".claude" / "settings.json",
                     project / ".claude" / "settings.local.json", *self.extra_protected]
        if self.fleet is not None:
            protected.append(self.fleet.state_dir)
            if self.fleet.tickets_dir is not None:
                protected.append(self.fleet.tickets_dir)
        return Inventory(self.fleet, protected, fleet_file=self.fleet_file)

    def decide(self, payload: Any) -> str | None:
        """The reason to deny, or None to stay out of the way."""
        if not isinstance(payload, dict):
            return "malformed hook payload (expected a JSON object); failing closed"
        tool = payload.get("tool_name")
        tool_input = payload.get("tool_input")
        if tool != "Bash" and tool not in EDIT_TOOLS:
            return None
        raw_cwd = payload.get("cwd") or os.getcwd()
        cwd = Path(raw_cwd) if isinstance(raw_cwd, str) else None
        if cwd is None or not cwd.is_dir():
            # Relative paths would resolve somewhere arbitrary and miss the protected ones.
            return f"the payload's cwd {raw_cwd!r} is not an existing directory; failing closed"
        if tool == "Bash":
            command = tool_input.get("command") if isinstance(tool_input, dict) else None
            if not isinstance(command, str) or not command.strip():
                return "a Bash call without a command string; failing closed"
            return self._bash(command, cwd)
        if tool in EDIT_TOOLS:
            path = tool_input.get(EDIT_TOOLS[tool]) if isinstance(tool_input, dict) else None
            if not isinstance(path, str) or not path:
                return f"a {tool} call without a file path; failing closed"
            if self.inventory(cwd).protected_hit(path, cwd):
                return (f"{path} is protected: change tickets, approvals, the ledger, the fleet "
                        "file and the hook settings are changed by people, not by an agent")
        return None

    def _bash(self, command: str, cwd: Path) -> str | None:
        if self.fleet is None:
            try:
                if only_reads(command):
                    return None
            except ShellSyntaxError:
                pass
            return (f"the fleet file could not be loaded ({self.fleet_error}), so the guard "
                    "cannot tell which containers are live; only plain reads are allowed until "
                    "it is fixed")
        inv = self.inventory(cwd)
        try:
            findings = classify(command, inv, cwd=cwd)
        except ShellSyntaxError as exc:
            return f"the guard cannot parse this command ({exc}); simplify it"
        for finding in findings:
            if finding.kind != "mutation":
                return finding.reason
        for finding in findings:
            names = ", ".join(sorted(finding.targets)) or "fleet state"
            if finding.ticket is None:
                why = (" (CHANGE_TICKET must be a literal ticket id)"
                       if finding.ticket_dynamic else "")
                return (f"{finding.reason}: this changes live target(s) {names}. Prefix the "
                        f"command with CHANGE_TICKET=<id> naming an approved, unexpired change "
                        f"ticket that covers them{why}")
            try:
                ticket = load_ticket(self.fleet.tickets_dir, finding.ticket)
            except ValidationError as exc:
                return f"{finding.reason}: change ticket rejected: {exc}"
            problem = ticket_problem(ticket, [inv.targets[n] for n in sorted(finding.targets)],
                                     self.now)
            if problem:
                return f"{finding.reason}: {problem}"
        return None


def main(argv: Sequence[str] | None = None, *, stdin: TextIO | None = None,
         stdout: TextIO | None = None, now: datetime | None = None) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    parser = argparse.ArgumentParser(prog="fleet-rollout-guard", description=__doc__.split("\n")[0])
    parser.add_argument("--fleet", required=True, type=Path, help="the fleet file to protect")
    parser.add_argument("--protect", action="append", default=[], type=Path,
                        help="an extra file or directory the agent may not modify")
    parser.add_argument("--project-dir", type=Path,
                        default=Path(os.environ["CLAUDE_PROJECT_DIR"])
                        if os.environ.get("CLAUDE_PROJECT_DIR") else None)
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        stdout.write(json.dumps(deny_payload("the guard is misconfigured (bad arguments); "
                                             "failing closed")) + "\n")
        return 0
    try:
        payload = json.loads(stdin.read())
    except ValueError:
        reason: str | None = "the hook payload is not valid JSON; failing closed"
    else:
        try:
            guard = Guard(args.fleet, project_dir=args.project_dir,
                          extra_protected=args.protect, now=now)
            reason = guard.decide(payload)
        except Exception as exc:  # fail closed on anything unexpected
            reason = f"internal error ({type(exc).__name__}: {exc}); failing closed"
    if reason:
        stdout.write(json.dumps(deny_payload(reason)) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
