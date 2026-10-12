import copy
from pathlib import Path

import pytest

from fleet_rollout.fleet import load_fleet, parse_fleet
from fleet_rollout.validation import ValidationError

BASE = {
    "fleet": "support-agents",
    "golden": "golden",
    "tickets_dir": "tickets",
    "defaults": {
        "executor": "ssh",
        "root": "/srv/agent",
        "health": {"port": 8080, "path": "/healthz", "expect_json": {"status": "ok"}},
    },
    "targets": [
        {"name": "agent-01", "host": "edge-1.example.com", "owner": "internal",
         "cohort": "staff", "canary": True},
        {"name": "agent-02", "host": "edge-1.example.com", "owner": "customer",
         "customer": "Example Bakery", "cohort": "bakeries"},
        {"name": "agent-03", "host": "edge-2.example.com", "owner": "internal",
         "container": "support-agent-03", "executor": "docker",
         "health": {"port": 9100}, "vars": {"region": "us-east"}},
    ],
}


def fleet_doc(**changes):
    doc = copy.deepcopy(BASE)
    doc.update(changes)
    return doc


def parse(doc, base=Path("/ops")):
    return parse_fleet(doc, base_dir=base, source="fleet.yaml")


def test_defaults_are_merged_into_each_target():
    fleet = parse(fleet_doc())
    one, two, three = fleet.targets
    assert one.container == "agent-01"  # defaults to the target name
    assert one.executor == "ssh" and one.root == "/srv/agent"
    assert one.health.port == 8080 and one.health.expect_json == {"status": "ok"}
    assert three.executor == "docker" and three.container == "support-agent-03"
    assert three.health.port == 9100 and three.health.path == "/healthz"  # deep merge
    assert three.cohort == "default" and three.vars == {"region": "us-east"}
    assert two.customer_owned and not one.customer_owned
    assert two.customer == "Example Bakery"


def test_state_golden_and_tickets_dirs_resolve_next_to_the_fleet_file(tmp_path):
    fleet = parse(fleet_doc(), base=tmp_path)
    assert fleet.golden_dir == tmp_path / "golden"
    assert fleet.tickets_dir == tmp_path / "tickets"
    assert fleet.state_dir == tmp_path / ".fleet-state"


def test_owner_is_mandatory_on_every_target():
    doc = fleet_doc()
    del doc["targets"][1]["owner"]
    with pytest.raises(ValidationError, match=r"targets\[1\].*missing required key\(s\) 'owner'"):
        parse(doc)


def test_owner_cannot_be_defaulted():
    doc = fleet_doc()
    doc["defaults"]["owner"] = "internal"
    with pytest.raises(ValidationError, match=r"defaults.*unknown key\(s\) 'owner'"):
        parse(doc)


def test_owner_must_be_internal_or_customer():
    doc = fleet_doc()
    doc["targets"][0]["owner"] = "ours"
    with pytest.raises(ValidationError, match="internal.*customer"):
        parse(doc)


def test_duplicate_target_names_are_refused():
    doc = fleet_doc()
    doc["targets"][2]["name"] = "agent-01"
    with pytest.raises(ValidationError, match="duplicate target name 'agent-01'"):
        parse(doc)


def test_the_same_container_twice_on_one_host_is_refused():
    doc = fleet_doc()
    doc["targets"][1]["container"] = "agent-01"
    with pytest.raises(ValidationError, match="container 'agent-01' on edge-1.example.com"):
        parse(doc)


@pytest.mark.parametrize("host", ["edge-1.example.com; rm -rf /", "EDGE.example.com",
                                  "-oProxyCommand=sh", "edge..example.com", ""])
def test_hosts_are_validated(host):
    doc = fleet_doc()
    doc["targets"][0]["host"] = host
    with pytest.raises(ValidationError, match="host"):
        parse(doc)


@pytest.mark.parametrize("container", ["-it", "agent 01", "agent;id", "../x"])
def test_container_names_are_validated(container):
    doc = fleet_doc()
    doc["targets"][0]["container"] = container
    with pytest.raises(ValidationError, match="container"):
        parse(doc)


def test_a_health_check_without_a_body_expectation_is_refused():
    doc = fleet_doc()
    doc["defaults"]["health"] = {"port": 8080, "path": "/healthz", "expect_status": 200}
    with pytest.raises(ValidationError, match="bare status code is not health"):
        parse(doc)


@pytest.mark.parametrize("health, reason", [
    ({"port": 0}, "port"),
    ({"port": True}, "port"),
    ({"path": "healthz"}, "path"),
    ({"path": "/health z"}, "path"),
    ({"retries": 0}, "retries"),
    ({"expect_status": 700}, "expect_status"),
    ({"timeout_seconds": 0}, "timeout_seconds"),
    ({"expect_json": "ok"}, "expect_json"),
])
def test_health_fields_are_validated(health, reason):
    doc = fleet_doc()
    doc["targets"][0]["health"] = health
    with pytest.raises(ValidationError, match=reason):
        parse(doc)


def test_at_most_one_canary():
    doc = fleet_doc()
    doc["targets"][2]["canary"] = True
    with pytest.raises(ValidationError, match="at most one target"):
        parse(doc)


def test_a_customer_owned_target_cannot_be_the_canary():
    doc = fleet_doc()
    doc["targets"][0]["canary"] = False
    doc["targets"][1]["canary"] = True
    with pytest.raises(ValidationError, match="canary.*customer-owned"):
        parse(doc)


def test_root_slash_is_refused():
    doc = fleet_doc()
    doc["defaults"]["root"] = "/"
    with pytest.raises(ValidationError, match="root"):
        parse(doc)


def test_unknown_executor_is_refused():
    doc = fleet_doc()
    doc["targets"][0]["executor"] = "kubectl"
    with pytest.raises(ValidationError, match="executor"):
        parse(doc)


def test_vars_are_plain_strings_with_identifier_keys():
    doc = fleet_doc()
    doc["targets"][0]["vars"] = {"Region-1": "x"}
    with pytest.raises(ValidationError, match="vars"):
        parse(doc)
    doc["targets"][0]["vars"] = {"region": ["x"]}
    with pytest.raises(ValidationError, match="vars"):
        parse(doc)


def test_select_returns_targets_in_fleet_order_and_refuses_unknown_names():
    fleet = parse(fleet_doc())
    assert [t.name for t in fleet.select(["agent-03", "agent-01"])] == ["agent-01", "agent-03"]
    assert len(fleet.select(None)) == 3
    with pytest.raises(ValidationError, match="unknown target 'agent-09'"):
        fleet.select(["agent-09"])


def test_targets_on_a_host():
    fleet = parse(fleet_doc())
    assert [t.name for t in fleet.targets_on_host("EDGE-1.example.com")] == ["agent-01", "agent-02"]


def test_load_fleet_reads_strict_yaml(tmp_path):
    path = tmp_path / "fleet.yaml"
    path.write_text("fleet: demo\nfleet: other\ntargets: []\n")
    with pytest.raises(ValidationError, match="duplicate key 'fleet'"):
        load_fleet(path)


def test_an_empty_fleet_is_refused():
    with pytest.raises(ValidationError, match="at least one target"):
        parse(fleet_doc(targets=[]))
