from datetime import UTC, datetime

import pytest

from fleet_rollout.fleet import HealthCheck, Target
from fleet_rollout.tickets import load_ticket, ticket_problem
from fleet_rollout.validation import ValidationError

NOW = datetime(2026, 10, 12, 10, 0, tzinfo=UTC)
HC = HealthCheck(port=8080, path="/healthz", expect_body="ok")

TICKET = """\
id: CHG-1042
summary: Roll support-greeting-v2 to the support agents
targets: [agent-01, agent-02]
expires: 2026-10-13T18:00:00Z
approved_by: [ops.oncall, eng.lead]
"""


def target(name, owner="internal"):
    return Target(name=name, host="edge-1.example.com", container=name, executor="ssh",
                  root="/srv/agent", owner=owner, cohort="staff", health=HC)


@pytest.fixture
def tickets(tmp_path):
    d = tmp_path / "tickets"
    d.mkdir()
    (d / "CHG-1042.yaml").write_text(TICKET)
    return d


def write(tickets, name, text):
    (tickets / f"{name}.yaml").write_text(text)


def test_loads_a_valid_ticket(tickets):
    ticket = load_ticket(tickets, "CHG-1042")
    assert ticket.targets == ("agent-01", "agent-02")
    assert ticket.approved_by == ("ops.oncall", "eng.lead")
    assert ticket.expires == datetime(2026, 10, 13, 18, 0, tzinfo=UTC)


@pytest.mark.parametrize("bad_id", ["../CHG-1042", "chg-1042", "CHG-1042/../x", "CHG1042",
                                    "CHG-1042.yaml", ""])
def test_ticket_ids_are_validated_before_touching_the_filesystem(tickets, bad_id):
    with pytest.raises(ValidationError, match="ticket id"):
        load_ticket(tickets, bad_id)


def test_a_missing_ticket_is_refused(tickets):
    with pytest.raises(ValidationError, match="no such ticket"):
        load_ticket(tickets, "CHG-9999")


def test_no_tickets_dir_configured_means_no_ticket_can_be_valid():
    with pytest.raises(ValidationError, match="tickets_dir"):
        load_ticket(None, "CHG-1042")


def test_the_id_inside_must_match_the_file_name(tickets):
    write(tickets, "CHG-2000", TICKET)
    with pytest.raises(ValidationError, match="does not match"):
        load_ticket(tickets, "CHG-2000")


def test_expiry_must_carry_a_timezone(tickets):
    write(tickets, "CHG-2001", TICKET.replace("CHG-1042", "CHG-2001")
          .replace("2026-10-13T18:00:00Z", "2026-10-13T18:00:00"))
    with pytest.raises(ValidationError, match="timezone"):
        load_ticket(tickets, "CHG-2001")


def test_coverage_and_expiry(tickets):
    ticket = load_ticket(tickets, "CHG-1042")
    assert ticket_problem(ticket, [target("agent-01")], NOW) is None
    assert "agent-03" in ticket_problem(ticket, [target("agent-01"), target("agent-03")], NOW)
    late = datetime(2026, 10, 14, tzinfo=UTC)
    assert "expired" in ticket_problem(ticket, [target("agent-01")], late)


def test_customer_owned_targets_need_two_approvers_on_the_ticket(tickets):
    write(tickets, "CHG-2002", TICKET.replace("CHG-1042", "CHG-2002")
          .replace("[ops.oncall, eng.lead]", "[ops.oncall]"))
    ticket = load_ticket(tickets, "CHG-2002")
    assert ticket_problem(ticket, [target("agent-01")], NOW) is None
    message = ticket_problem(ticket, [target("agent-02", "customer")], NOW)
    assert "customer-owned" in message and "2" in message


def test_a_wildcard_never_covers_customer_owned_targets(tickets):
    write(tickets, "CHG-2003", TICKET.replace("CHG-1042", "CHG-2003")
          .replace("[agent-01, agent-02]", "['*']"))
    ticket = load_ticket(tickets, "CHG-2003")
    assert ticket_problem(ticket, [target("agent-01"), target("agent-07")], NOW) is None
    assert "agent-02" in ticket_problem(ticket, [target("agent-02", "customer")], NOW)


def test_duplicate_approvers_are_refused(tickets):
    write(tickets, "CHG-2004", TICKET.replace("CHG-1042", "CHG-2004")
          .replace("[ops.oncall, eng.lead]", "[ops.oncall, ops.oncall]"))
    with pytest.raises(ValidationError, match="listed twice"):
        load_ticket(tickets, "CHG-2004")
