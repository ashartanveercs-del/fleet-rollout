"""The rollout ledger: an append-only, hash-chained JSONL audit log.

Every record carries `prev`, the sha256 of the previous line's bytes, and a `seq`.
Editing, deleting or reordering any record breaks the chain at the next record, and
`verify()` names where. Removing records from the *end* cannot be detected by a chain
alone, which is why `verify()` reports the head hash: pin it somewhere the ledger's
writer cannot edit (a ticket, a CI log) and compare.

The ledger also drives behaviour, not just audit: a `halt` record freezes further runs
of that patch until someone appends an explicit `halt_cleared`; targets whose latest
record is `verified` are skipped on resume; and a `started` record without a terminal
record marks an interrupted transaction that must be undone before any patch touches
that target again.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field, fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64
EVENTS = frozenset({
    "run_started", "run_finished", "run_aborted",
    "started", "verified", "skipped", "rolled_back", "rollback_failed", "recovered",
    "manual_rollback", "halt_cleared", "lock_broken",
})
TERMINAL = frozenset({"verified", "skipped", "rolled_back", "rollback_failed", "recovered",
                      "manual_rollback"})
# Events that describe a target's *transaction* state. Others that name a target
# (lock_broken, a bake-time run_aborted) are audit facts, not a change of that state.
TRANSACTION_EVENTS = TERMINAL | {"started"}


class LedgerCorrupt(RuntimeError):
    """The chain does not verify; nothing may be appended until a human looks."""


@dataclass(frozen=True)
class LedgerRecord:
    seq: int
    ts: str
    run: str
    event: str
    operator: str
    patch: str | None = None
    digest: str | None = None
    target: str | None = None
    detail: str = ""
    halt: bool = False
    ticket: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    prev: str = GENESIS


_FIELDS = {f.name for f in fields(LedgerRecord)}


@dataclass(frozen=True)
class VerifyReport:
    ok: bool
    count: int
    head: str
    problem: str = ""


def _serialize(record: LedgerRecord) -> bytes:
    return json.dumps(asdict(record), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _hash(line: bytes) -> str:
    return hashlib.sha256(line).hexdigest()


def _timestamp(ts: datetime) -> str:
    return ts.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


class Ledger:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def _lines(self) -> tuple[list[bytes], bool]:
        if not self.path.is_file():
            return [], False
        raw = self.path.read_bytes()
        torn = bool(raw) and not raw.endswith(b"\n")
        return [line for line in raw.split(b"\n") if line], torn

    def _parse(self) -> tuple[list[LedgerRecord], VerifyReport]:
        lines, torn = self._lines()
        records: list[LedgerRecord] = []
        prev = GENESIS
        for number, line in enumerate(lines, start=1):
            try:
                doc = json.loads(line)
                if not isinstance(doc, dict) or set(doc) != _FIELDS:
                    raise ValueError("unexpected fields")
                record = LedgerRecord(**doc)
            except (ValueError, TypeError):
                return records, VerifyReport(False, number - 1, prev,
                                             f"record {number} is not a valid ledger record")
            if record.seq != number:
                return records, VerifyReport(False, number - 1, prev,
                                             f"record {number}: expected seq {number}, found "
                                             f"{record.seq} (records removed or reordered)")
            if record.prev != prev:
                return records, VerifyReport(False, number - 1, prev,
                                             f"record {number}: prev hash does not match "
                                             f"record {number - 1} (the ledger was edited, "
                                             "truncated or reordered)")
            records.append(record)
            prev = _hash(line)
        if torn:
            return records, VerifyReport(False, len(records), prev,
                                         "the final record is torn (incomplete write)")
        return records, VerifyReport(True, len(records), prev)

    def verify(self) -> VerifyReport:
        return self._parse()[1]

    def records(self) -> list[LedgerRecord]:
        records, report = self._parse()
        if not report.ok:
            raise LedgerCorrupt(f"{self.path}: {report.problem}")
        return records

    def append(self, *, run: str, event: str, operator: str, ts: datetime,
               patch: str | None = None, digest: str | None = None,
               target: str | None = None, detail: str = "", halt: bool = False,
               ticket: str | None = None, extra: dict[str, Any] | None = None) -> LedgerRecord:
        if event not in EVENTS:
            raise ValueError(f"unknown ledger event {event!r}")
        records, report = self._parse()
        if not report.ok:
            raise LedgerCorrupt(f"{self.path}: {report.problem}; refusing to append")
        record = LedgerRecord(seq=len(records) + 1, ts=_timestamp(ts), run=run, event=event,
                              operator=operator, patch=patch, digest=digest, target=target,
                              detail=detail, halt=halt, ticket=ticket, extra=extra or {},
                              prev=report.head)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("ab") as handle:
            handle.write(_serialize(record) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        return record

    # -- queries ---------------------------------------------------------------------

    def halt_record(self, patch_id: str) -> LedgerRecord | None:
        current = None
        for record in self.records():
            if record.patch != patch_id:
                continue
            if record.event == "halt_cleared":
                current = None
            elif record.halt:
                current = record
        return current

    def target_states(self, patch_id: str) -> dict[str, LedgerRecord]:
        latest: dict[str, LedgerRecord] = {}
        for record in self.records():
            if (record.patch == patch_id and record.target
                    and record.event in TRANSACTION_EVENTS):
                latest[record.target] = record
        return latest

    def interrupted(self) -> list[LedgerRecord]:
        """The `started` record of every transaction, of any patch, that never reached a
        terminal record: work a dead run left half done on that target."""
        latest: dict[tuple[str, str], LedgerRecord] = {}
        for record in self.records():
            if record.patch and record.target and record.event in TRANSACTION_EVENTS:
                latest[(record.patch, record.target)] = record
        return [r for r in latest.values() if r.event == "started"]

    def digests_for(self, patch_id: str) -> set[str]:
        return {r.digest for r in self.records() if r.patch == patch_id and r.digest}
