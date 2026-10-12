import pytest

from fleet_rollout import validation as v
from fleet_rollout.validation import ValidationError

# -- relative workspace paths -----------------------------------------------------------


@pytest.mark.parametrize("good", [
    "config/greeting.txt",
    "handlers/invoices.py",
    "prompts/support-v2.md",
    ".env.example",
    "a/b/c/d.json",
    "data/settings.db",
    "x+y/z_1.txt",
])
def test_relative_path_accepts_plain_paths(good):
    assert v.relative_path(good, where="dest") == good


@pytest.mark.parametrize("bad, reason", [
    ("/etc/passwd", "relative"),
    ("../etc/passwd", r"\.\."),
    ("config/../../etc/passwd", "normalized"),
    ("config/./greeting.txt", "normalized"),
    ("config//greeting.txt", "normalized"),
    ("config/", "normalized"),
    (".", "workspace root itself"),
    ("", "non-empty"),
    ("config/greeting.txt; rm -rf /", "characters"),
    ("config/$(whoami).txt", "characters"),
    ("config/`id`.txt", "characters"),
    ("config/greet ing.txt", "characters"),
    ("config\\greeting.txt", "characters"),
    ("config/gréeting.txt", "characters"),
    ("config/greeting.txt\n", "characters"),
    ("config/\x00.txt", "characters"),
    ("-rf", "start with '-'"),
    ("config/-n", "start with '-'"),
    (".fleet-rollout/lock", "reserved"),
    (".fleet-rollout", "reserved"),
])
def test_relative_path_rejects_escapes_and_metacharacters(bad, reason):
    with pytest.raises(ValidationError, match=reason):
        v.relative_path(bad, where="steps[0].dest")


def test_relative_path_error_names_the_field():
    with pytest.raises(ValidationError, match=r"steps\[3\]\.dest"):
        v.relative_path("/abs", where="steps[3].dest")


@pytest.mark.parametrize("not_a_string", [None, 7, ["a"], {"a": 1}, True])
def test_relative_path_rejects_non_strings(not_a_string):
    with pytest.raises(ValidationError, match="string"):
        v.relative_path(not_a_string, where="dest")


def test_relative_path_rejects_overlong_components():
    with pytest.raises(ValidationError, match="too long"):
        v.relative_path("a/" + "b" * 256, where="dest")


def test_join_root_stays_inside_the_root():
    assert v.join_root("/srv/agent", "config/greeting.txt") == "/srv/agent/config/greeting.txt"


# -- workspace roots (operator config) -------------------------------------------------


def test_workspace_root_must_be_absolute_and_not_slash():
    assert v.workspace_root("/srv/agent", where="root") == "/srv/agent"
    for bad in ("/", "srv/agent", "/srv/../etc", "/srv/agent/", "//srv/agent", "/srv/a b"):
        with pytest.raises(ValidationError):
            v.workspace_root(bad, where="root")


# -- SQL identifiers ----------------------------------------------------------------------


@pytest.mark.parametrize("good", ["settings", "_private", "Table1", "a" * 63])
def test_sql_identifier_accepts_plain_identifiers(good):
    assert v.sql_identifier(good, where="table") == good


@pytest.mark.parametrize("bad", [
    "settings; DROP TABLE users",
    'settings"--',
    "settings WHERE 1=1",
    "1settings",
    "",
    "a" * 64,
    "sqlite_master",
    "SQLITE_schema",
    "naïve",
    None,
])
def test_sql_identifier_rejects_injection_and_reserved_names(bad):
    with pytest.raises(ValidationError):
        v.sql_identifier(bad, where="table")


# -- single-line text (markers, descriptions, notes) -------------------------------------


def test_single_line_accepts_ordinary_text():
    assert v.single_line("<!-- rule: refunds-v2 -->", where="marker") == "<!-- rule: refunds-v2 -->"


@pytest.mark.parametrize("bad, reason", [
    ("two\nlines", "control"),
    ("carriage\rreturn", "control"),
    ("nul\x00byte", "control"),
    ("escape\x1b[31mred", "control"),
    ("hidden ‮gnp.exe", "bidirectional"),
    ("isolate ⁦x⁩", "bidirectional"),
    ("", "non-empty"),
])
def test_single_line_rejects_control_and_bidi_characters(bad, reason):
    with pytest.raises(ValidationError, match=reason):
        v.single_line(bad, where="marker")


def test_single_line_enforces_max_length():
    with pytest.raises(ValidationError, match="too long"):
        v.single_line("x" * 11, where="marker", max_len=10)


# -- ids and names ---------------------------------------------------------------------


def test_patch_id_rules():
    assert v.patch_id("support-greeting-v2", where="id") == "support-greeting-v2"
    for bad in ("ab", "Upper-case", "../x", "-leading", "a" * 65, "with space", None):
        with pytest.raises(ValidationError):
            v.patch_id(bad, where="id")


def test_target_name_rules():
    assert v.target_name("agent-01", where="name") == "agent-01"
    for bad in ("Agent-01", "-agent", "agent-", "agent_01", "", "a" * 64):
        with pytest.raises(ValidationError):
            v.target_name(bad, where="name")


def test_person_name_rules():
    assert v.person_name("ops.reviewer", where="approver") == "ops.reviewer"
    for bad in ("", "Alice", "a b", "x" * 33, "1abc"):
        with pytest.raises(ValidationError):
            v.person_name(bad, where="approver")


def test_sha256_hex_rules():
    good = "a" * 64
    assert v.sha256_hex(good, where="expect_sha256") == good
    for bad in ("A" * 64, "a" * 63, "g" * 64, 42):
        with pytest.raises(ValidationError):
            v.sha256_hex(bad, where="expect_sha256")


@pytest.mark.parametrize("validator, value", [
    (v.sql_identifier, "settings\n"),
    (v.patch_id, "support-greeting\n"),
    (v.target_name, "agent-01\n"),
    (v.person_name, "alice\n"),
    (v.sha256_hex, "a" * 64 + "\n"),
    (v.workspace_root, "/srv/agent\n"),
])
def test_a_trailing_newline_never_sneaks_past_a_regex(validator, value):
    # Python's `$` also matches just before a final "\n"; every validator must use
    # full-string matching instead.
    with pytest.raises(ValidationError):
        validator(value, where="field")


# -- key sets --------------------------------------------------------------------------


def test_check_keys_rejects_unknown_keys_and_lists_the_allowed_ones():
    with pytest.raises(ValidationError, match=r"unknown key\(s\) 'shell'.*allowed: dest, source"):
        v.check_keys({"dest": 1, "source": 2, "shell": 3}, required=("dest",),
                     optional=("source",), where="steps[0]")


def test_check_keys_reports_missing_required_keys():
    with pytest.raises(ValidationError, match=r"missing required key\(s\) 'dest'"):
        v.check_keys({"source": 2}, required=("dest",), optional=("source",), where="steps[0]")


def test_check_keys_requires_a_mapping():
    with pytest.raises(ValidationError, match="mapping"):
        v.check_keys(["dest"], required=("dest",), optional=(), where="steps[0]")
