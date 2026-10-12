"""The operator-side state directory: where the ledger, approvals, backups and the run
lock live. One state directory serializes rollouts; keep it on durable storage."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .backup import BackupStore
from .consent import ApprovalStore
from .ledger import Ledger
from .locks import LocalRunLock


@dataclass(frozen=True)
class StateDir:
    root: Path

    def ledger(self) -> Ledger:
        return Ledger(self.root / "ledger.jsonl")

    def approvals(self) -> ApprovalStore:
        return ApprovalStore(self.root / "approvals.jsonl")

    def backups(self) -> BackupStore:
        return BackupStore(self.root / "backups")

    def run_lock(self) -> LocalRunLock:
        return LocalRunLock(self.root / "run.lock")
