"""Change tickets: the explicit, expiring authorization for touching live targets.

A ticket is a small YAML file named after its id (`tickets/CHG-1042.yaml`). It lists the
targets it covers, who approved it, and when it expires. `fleet-rollout apply` and the
AI-agent guard hook both require one, and both apply the same rules:

* the id is validated *before* it is used to build a path;
* an expired ticket covers nothing;
* `*` covers internal targets only; customer-owned targets must be named explicitly
  and the ticket needs two different approvers.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .fleet import Target
from .validation import ValidationError, check_keys, person_name, single_line, target_name
from .yamlsafe import load_strict

_TICKET_ID = re.compile(r"[A-Z][A-Z0-9]{1,9}-[0-9]{1,8}")
CUSTOMER_APPROVERS = 2


@dataclass(frozen=True)
class Ticket:
    id: str
    summary: str
    targets: tuple[str, ...]
    expires: datetime
    approved_by: tuple[str, ...]


def validate_ticket_id(value: Any) -> str:
    if not isinstance(value, str) or not _TICKET_ID.fullmatch(value):
        raise ValidationError(f"{value!r} is not a valid ticket id (like CHG-1042)")
    return value


def load_ticket(tickets_dir: Path | None, ticket_id: Any) -> Ticket:
    tid = validate_ticket_id(ticket_id)
    if tickets_dir is None:
        raise ValidationError("the fleet file sets no tickets_dir, so no change ticket can be "
                              "valid")
    path = Path(tickets_dir) / f"{tid}.yaml"
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ValidationError(f"no such ticket {tid} in {tickets_dir}") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise ValidationError(f"cannot read ticket {tid}: {exc}") from exc
    data = load_strict(text, source=path.name, max_bytes=16 * 1024)
    where = path.name
    check_keys(data, required=("id", "summary", "targets", "expires", "approved_by"),
               optional=(), where=where)
    if data["id"] != tid:
        raise ValidationError(f"{where}: id {data['id']!r} does not match the file name")
    targets = data["targets"]
    if not isinstance(targets, list) or not targets:
        raise ValidationError(f"{where}:targets: expected a non-empty list")
    checked = tuple(t if t == "*" else target_name(t, where=f"{where}:targets") for t in targets)
    approvers = data["approved_by"]
    if not isinstance(approvers, list) or not approvers:
        raise ValidationError(f"{where}:approved_by: expected a non-empty list")
    people = tuple(person_name(p, where=f"{where}:approved_by") for p in approvers)
    if len(set(people)) != len(people):
        raise ValidationError(f"{where}:approved_by: an approver is listed twice")
    return Ticket(id=tid, summary=single_line(data["summary"], where=f"{where}:summary"),
                  targets=checked, expires=_expiry(data["expires"], where), approved_by=people)


def _expiry(value: Any, where: str) -> datetime:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValidationError(f"{where}:expires: not an ISO 8601 timestamp") from exc
    if not isinstance(value, datetime):
        raise ValidationError(f"{where}:expires: expected a timestamp")
    if value.tzinfo is None:
        raise ValidationError(f"{where}:expires: the timestamp needs a timezone (e.g. ...Z)")
    return value


def ticket_problem(ticket: Ticket, targets: Iterable[Target], now: datetime) -> str | None:
    """Why `ticket` does not authorize touching `targets`, or None if it does."""
    targets = list(targets)
    if now >= ticket.expires:
        return f"ticket {ticket.id} expired at {ticket.expires.isoformat()}"
    uncovered = [t.name for t in targets if t.name not in ticket.targets
                 and not ("*" in ticket.targets and not t.customer_owned)]
    if uncovered:
        return f"ticket {ticket.id} does not cover {', '.join(uncovered)}"
    customer = [t.name for t in targets if t.customer_owned]
    if customer and len(set(ticket.approved_by)) < CUSTOMER_APPROVERS:
        return (f"ticket {ticket.id} has {len(set(ticket.approved_by))} approver(s); "
                f"customer-owned {', '.join(customer)} need a ticket approved by "
                f"{CUSTOMER_APPROVERS} different people")
    return None
