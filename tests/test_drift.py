import os

import pytest

from fleet_rollout.drift import check_drift, golden_lag
from fleet_rollout.fleet import HealthCheck, Target
from fleet_rollout.spec import parse_patch
from fleet_rollout.template import golden_files, render, render_golden
from fleet_rollout.testing import FakeExecutor
from fleet_rollout.validation import ValidationError

HC = HealthCheck(port=8080, path="/healthz", expect_body="ok")


def target(name="agent-01", **kw):
    base = dict(name=name, host="edge-1.example.com", container=name, executor="ssh",
                root="/srv/agent", owner="internal", cohort="staff", health=HC,
                vars={"region": "us-east"})
    base.update(kw)
    return Target(**base)


# -- rendering -----------------------------------------------------------------------


def test_fleet_placeholders_are_rendered_per_target():
    out = render(b"name={{ fleet.target.name }} region={{fleet.vars.region}}\n", target(),
                 where="config/agent.env")
    assert out == b"name=agent-01 region=us-east\n"


def test_the_agents_own_template_syntax_is_left_alone():
    prompt = b"Hello {{ customer_name }}, your invoice {{ invoice.id }} is ready.\n"
    assert render(prompt, target(), where="prompts/support.md") == prompt


def test_an_unknown_fleet_placeholder_is_an_error_never_shipped_raw():
    with pytest.raises(ValidationError, match="fleet.vars.zone"):
        render(b"zone={{ fleet.vars.zone }}", target(), where="config/agent.env")


def test_binary_files_are_copied_verbatim():
    blob = b"\x89PNG\r\n\x1a\n{{ fleet.target.name }}\xff"
    assert render(blob, target(), where="assets/logo.png") == blob


@pytest.fixture
def golden(tmp_path):
    root = tmp_path / "golden"
    (root / "config").mkdir(parents=True)
    (root / "prompts").mkdir()
    (root / "config" / "greeting.txt").write_bytes(b"Hi from {{ fleet.target.name }}!\n")
    (root / "prompts" / "support.md").write_bytes(b"Be kind.\nBe brief.\n")
    return root


def test_golden_files_are_listed_with_validated_relative_paths(golden):
    assert sorted(golden_files(golden)) == ["config/greeting.txt", "prompts/support.md"]


def test_golden_files_refuse_the_reserved_engine_directory(golden):
    (golden / ".fleet-rollout").mkdir()
    (golden / ".fleet-rollout" / "lock").write_text("x")
    with pytest.raises(ValidationError, match="reserved"):
        golden_files(golden)


def test_golden_files_refuse_links(golden, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        os.symlink(outside, golden / "linked", target_is_directory=True)
    except OSError:
        if os.name != "nt":
            raise
        import _winapi
        _winapi.CreateJunction(str(outside), str(golden / "linked"))
    with pytest.raises(ValidationError, match="link"):
        golden_files(golden)


def test_render_golden_for_one_target(golden):
    files = render_golden(golden, target("agent-07"))
    assert files["config/greeting.txt"] == b"Hi from agent-07!\n"


# -- drift -----------------------------------------------------------------------------


def make_fleet_execs(golden, *targets_):
    execs = {}
    for t in targets_:
        execs[t.name] = FakeExecutor(t.name, {
            f"/srv/agent/{rel}": data for rel, data in render_golden(golden, t).items()})
    return execs


def test_a_target_matching_golden_is_in_sync(golden):
    t = target()
    execs = make_fleet_execs(golden, t)
    [report] = check_drift(golden, [t], lambda t: execs[t.name])
    assert not report.drifted
    assert {f.state for f in report.files} == {"in_sync"}


def test_a_hand_edited_file_shows_a_unified_diff(golden):
    t = target()
    execs = make_fleet_execs(golden, t)
    execs["agent-01"].put("/srv/agent/prompts/support.md", b"Be kind.\nBe VERY brief.\n")
    [report] = check_drift(golden, [t], lambda t: execs[t.name])
    assert report.drifted
    [changed] = [f for f in report.files if f.state == "drifted"]
    assert changed.path == "prompts/support.md"
    assert "-Be brief." in changed.diff and "+Be VERY brief." in changed.diff
    assert "golden/prompts/support.md" in changed.diff


def test_a_missing_file_and_an_unreachable_target_are_reported(golden):
    one, two = target("agent-01"), target("agent-02")
    execs = make_fleet_execs(golden, one, two)
    del execs["agent-01"].files["/srv/agent/config/greeting.txt"]
    execs["agent-02"].fail("read", times=99, error="ssh connection failed")
    reports = {r.target: r for r in check_drift(golden, [one, two], lambda t: execs[t.name])}
    states = {f.path: f.state for f in reports["agent-01"].files}
    assert states["config/greeting.txt"] == "missing"
    assert {f.state for f in reports["agent-02"].files} == {"error"}
    assert reports["agent-02"].drifted


def test_binary_drift_is_summarised_not_dumped(golden):
    (golden / "assets").mkdir()
    (golden / "assets" / "logo.png").write_bytes(b"\x89PNG\xff\x00golden")
    t = target()
    execs = make_fleet_execs(golden, t)
    execs["agent-01"].put("/srv/agent/assets/logo.png", b"\x89PNG\xff\x00edited")
    [report] = check_drift(golden, [t], lambda t: execs[t.name])
    [changed] = [f for f in report.files if f.state == "drifted"]
    assert "binary" in changed.diff


def test_golden_lag_warns_when_a_patch_ships_bytes_golden_does_not_have(golden, tmp_path):
    bundle = tmp_path / "bundle"
    (bundle / "files").mkdir(parents=True)
    (bundle / "files" / "greeting.txt").write_bytes(b"Hi from agent-01, v2!\n")
    (bundle / "files" / "support.md").write_bytes(b"Be kind.\nBe brief.\n")
    patch = parse_patch({"id": "demo-patch", "description": "demo", "steps": [
        {"kind": "write_file", "source": "files/greeting.txt", "dest": "config/greeting.txt"},
        {"kind": "write_file", "source": "files/support.md", "dest": "prompts/support.md"},
    ]}, bundle_dir=bundle, source="demo-patch.yaml")
    warnings = golden_lag(golden, patch, target())
    assert len(warnings) == 1 and "config/greeting.txt" in warnings[0]
