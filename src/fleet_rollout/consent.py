"""Consent for customer-owned targets: two distinct people, bound to the exact patch.

A customer-owned target is mutated only when (1) the operator explicitly opted in with
`--include-customer`, and (2) at least two *different* approvers recorded an approval
for this target and this patch digest, and those approvals have not expired. The digest
covers the spec and every bundled byte, so editing the patch after approval silently
voids the approvals instead of silently inheriting them.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .fleet import Target
from .validation import (
    ValidationError,
    patch_id,
    person_name,
    sha256_hex,
    single_line,
    target_name,
)

REQUIRED_APPROVALS = 2
MAX_TTL = timedelta(days=7)


@dataclass(frozen=True)
class Approval:
    patch: str
    digest: str
    target: str
    approver: str
    note: str
    created: str
    expires: str


class ApprovalStore:
    """Append-only JSONL file of approvals."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def add(self, *, patch_id: str, digest: str, target: str, approver: str, note: str,
            now: datetime, ttl: timedelta = timedelta(hours=24)) -> Approval:
        if not timedelta(0) < ttl <= MAX_TTL:
            raise ValidationError(f"approval ttl must be between 0 and {MAX_TTL}")
        approval = Approval(
            patch=_validate_patch(patch_id), digest=sha256_hex(digest, where="digest"),
            target=target_name(target, where="target"),
            approver=person_name(approver, where="approver"),
            note=single_line(note, where="note"),
            created=now.astimezone(UTC).isoformat(),
            expires=(now + ttl).astimezone(UTC).isoformat())
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("ab") as handle:
            handle.write(json.dumps(asdict(approval), sort_keys=True).encode() + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        return approval

    def all(self) -> list[Approval]:
        if not self.path.is_file():
            return []
        out = []
        for number, line in enumerate(self.path.read_text("utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                out.append(Approval(**json.loads(line)))
            except (ValueError, TypeError) as exc:
                raise ValidationError(f"{self.path.name} line {number} is unreadable") from exc
        return out

    def valid(self, *, digest: str, target: str, now: datetime) -> list[Approval]:
        """Unexpired approvals for this digest and target, one per approver."""
        by_person: dict[str, Approval] = {}
        for approval in self.all():
            if approval.digest != digest or approval.target != target:
                continue
            if datetime.fromisoformat(approval.expires) <= now:
                continue
            by_person[approval.approver] = approval
        return list(by_person.values())


def _validate_patch(value: str) -> str:
    return patch_id(value, where="patch")


def consent_problem(target: Target, *, digest: str, store: ApprovalStore, now: datetime,
                    include_customer: bool, required: int = REQUIRED_APPROVALS) -> str | None:
    """Why `target` may not be mutated by this patch yet, or None if it may."""
    if not target.customer_owned:
        return None
    who = f" ({target.customer})" if target.customer else ""
    if not include_customer:
        return (f"{target.name} is customer-owned{who}; pass --include-customer to include it "
                f"(it then needs {required} distinct approvals)")
    names = sorted(a.approver for a in store.valid(digest=digest, target=target.name, now=now))
    if len(names) < required:
        return (f"{target.name} is customer-owned{who} and needs {required} distinct approvals "
                f"for this patch version (digest {digest[:12]}); have {len(names)}: "
                f"{', '.join(names) or 'none'}. Record them with `fleet-rollout approve`.")
    return None
