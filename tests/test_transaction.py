"""The per-target transaction: backup -> stage -> syntax gate -> swap -> read-back ->
health (body) -> verify -> marker, and a verified restore on any failure."""

import hashlib
import json

import pytest
from fakes import (
    AGENT_JSON,
    ROOT,
    WORKSPACE,
    Clock,
    agent,
    agent_writes_db,
    db_value,
    make_patch,
    make_target,
)

from fleet_rollout import scripts
from fleet_rollout.backup import BackupStore
from fleet_rollout.executors.base import ExecutorError
from fleet_rollout.locks import LockOwner, acquire
from fleet_rollout.testing import healthy
from fleet_rollout.transaction import TargetTransaction, marker_path

GREETING_V2 = b"Thanks for reaching out to Example Bakery support!\n"
CONFIG_V2 = b'{"model": "small", "escalate_to": "support@example.com", "enabled": true, "v": 2}\n'
BROKEN_CONFIG = b'{"model": "small", "enabled": false}\n'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def tx(tmp_path, fx, patch, *, target=None, allow_drift=False):
    store = BackupStore(tmp_path / "state" / "backups")
    return TargetTransaction(target or make_target(fx.name), fx, patch, store, run_id="r-1",
                             operator="ops.oncall", clock=Clock(), sleep=lambda s: None,
                             allow_drift=allow_drift)


def write_step(src, dest, **extra):
    return {"kind": "write_file", "source": src, "dest": dest, **extra}


def greeting_patch(tmp_path, **extra):
    return make_patch(tmp_path, [write_step("files/greeting.txt", "config/greeting.txt", **extra)],
                      files={"files/greeting.txt": GREETING_V2})


def live(fx, rel):
    return fx.files.get(f"{ROOT}/{rel}")


# -- the happy path ----------------------------------------------------------------------


def test_a_clean_apply_backs_up_swaps_verifies_and_marks(tmp_path):
    fx = agent()
    t = tx(tmp_path, fx, greeting_patch(tmp_path))
    outcome = t.apply()
    assert outcome.ok, outcome.error
    assert live(fx, "config/greeting.txt") == GREETING_V2
    assert t.store.get(sha(WORKSPACE["config/greeting.txt"])) == WORKSPACE["config/greeting.txt"]
    [entry] = t.store.manifest("r-1", "agent-01").entries()
    assert entry.path == f"{ROOT}/config/greeting.txt"
    assert entry.sha_before == sha(WORKSPACE["config/greeting.txt"])
    marker = json.loads(fx.files[marker_path(ROOT, "demo-patch")])
    assert marker["digest"] == t.patch.digest and marker["run"] == "r-1"
    assert not [p for p in fx.files if ".rollout-" in p]   # no staging debris


def test_the_order_of_operations_is_the_contract(tmp_path):
    fx = agent()
    tx(tmp_path, fx, greeting_patch(tmp_path)).apply()
    ops = [(op, args[0] if args else None) for op, args in fx.calls]
    dest = f"{ROOT}/config/greeting.txt"
    backup_read = ops.index(("read", dest))
    first_mutation = next(i for i, (op, _) in enumerate(ops)
                          if op in ("write", "rename", "remove", "create_exclusive", "run"))
    assert backup_read < first_mutation                      # back up before touching
    rename = next(i for i, (op, _) in enumerate(ops) if op == "rename")
    readback = max(i for i, c in enumerate(ops) if c == ("read", dest))
    health = ops.index(("http_get", 8080))
    marker = max(i for i, (op, _) in enumerate(ops) if op == "create_exclusive")
    assert rename < readback < health < marker              # marker strictly last


# -- the syntax gate ---------------------------------------------------------------------


def test_python_that_does_not_parse_never_replaces_the_live_file(tmp_path):
    fx = agent()
    patch = make_patch(tmp_path, [write_step("files/invoices.py", "handlers/invoices.py")],
                       files={"files/invoices.py": b"def total(lines:\n    return 0\n"})
    outcome = tx(tmp_path, fx, patch).apply()
    assert not outcome.ok and "syntax" in outcome.error
    assert live(fx, "handlers/invoices.py") == WORKSPACE["handlers/invoices.py"]
    assert not [c for c in fx.calls if c[0] == "rename"]
    assert not [p for p in fx.files if ".rollout-" in p]


def test_invalid_json_config_is_stopped_at_the_gate(tmp_path):
    fx = agent()
    patch = make_patch(tmp_path, [write_step("files/agent.json", "config/agent.json")],
                       files={"files/agent.json": b'{"model": "small",}'})
    outcome = tx(tmp_path, fx, patch).apply()
    assert not outcome.ok and "JSON" in outcome.error
    assert live(fx, "config/agent.json") == AGENT_JSON


def test_a_corrupted_transfer_is_caught_before_the_swap(tmp_path):
    fx = agent()
    fx.corrupt_writes(".rollout-")
    outcome = tx(tmp_path, fx, greeting_patch(tmp_path)).apply()
    assert not outcome.ok and "read back" in outcome.error
    assert live(fx, "config/greeting.txt") == WORKSPACE["config/greeting.txt"]


# -- failure anywhere restores everything already done ---------------------------------


def three_step_patch(tmp_path, third_source=b"def total(x:\n"):
    return make_patch(tmp_path, [
        write_step("files/greeting.txt", "config/greeting.txt"),
        write_step("files/new-faq.md", "prompts/faq.md"),
        write_step("files/invoices.py", "handlers/invoices.py"),
        write_step("files/never.txt", "config/never.txt"),
    ], files={"files/greeting.txt": GREETING_V2, "files/new-faq.md": b"# FAQ\n",
              "files/invoices.py": third_source, "files/never.txt": b"x"})


def test_a_failure_in_step_3_restores_steps_1_and_2_and_never_starts_step_4(tmp_path):
    fx = agent()
    before = fx.snapshot()
    outcome = tx(tmp_path, fx, three_step_patch(tmp_path)).apply()
    assert not outcome.ok and outcome.failed_step == "write_file handlers/invoices.py"
    assert outcome.restore.ok
    assert fx.snapshot() == before                     # byte-identical, new file removed
    assert not [c for c in fx.calls if "config/never.txt" in str(c[1])]


def test_an_executor_error_mid_step_also_restores(tmp_path):
    fx = agent()
    before = fx.snapshot()
    fx.fail("rename", "prompts/faq.md", error="Read-only file system")
    outcome = tx(tmp_path, fx, three_step_patch(tmp_path, b"ok = 1\n")).apply()
    assert not outcome.ok and "Read-only" in outcome.error
    assert outcome.restore.ok and fx.snapshot() == before


def test_an_unhealthy_body_after_apply_rolls_back_and_never_writes_the_marker(tmp_path):
    fx = agent()
    before = fx.snapshot()
    patch = make_patch(tmp_path, [write_step("files/agent.json", "config/agent.json"),
                                  {"kind": "run", "command": "reload_agent"}],
                       files={"files/agent.json": BROKEN_CONFIG})
    outcome = tx(tmp_path, fx, patch).apply()
    assert not outcome.ok and outcome.failed_step == "health gate"
    assert "degraded" in outcome.error              # a 200 with the wrong body
    assert fx.snapshot() == before
    assert marker_path(ROOT, "demo-patch") not in fx.files
    assert fx.reloads == 2                          # reloaded on apply, again on restore
    assert outcome.restore.ok and outcome.restore.health.ok


def test_a_restore_that_cannot_bring_health_back_is_reported_as_failed(tmp_path):
    fx = agent(health=healthy(b'{"status":"degraded"}'))
    outcome = tx(tmp_path, fx, greeting_patch(tmp_path)).apply()
    assert not outcome.ok
    assert outcome.restore is not None and not outcome.restore.ok
    assert "unhealthy after restore" in outcome.restore.detail


def test_a_failed_verify_assertion_rolls_back(tmp_path):
    fx = agent()
    patch = make_patch(tmp_path, [write_step("files/greeting.txt", "config/greeting.txt")],
                       files={"files/greeting.txt": GREETING_V2},
                       verify=[{"file": "config/greeting.txt", "contains": "Goodbye"}])
    outcome = tx(tmp_path, fx, patch).apply()
    assert not outcome.ok and outcome.failed_step == "verify"
    assert live(fx, "config/greeting.txt") == WORKSPACE["config/greeting.txt"]


def test_ctrl_c_mid_transaction_restores_then_propagates(tmp_path):
    fx = agent()
    before = fx.snapshot()
    original_rename = fx.rename

    def interrupted(src, dst):
        if dst.endswith("prompts/faq.md"):
            raise KeyboardInterrupt
        original_rename(src, dst)

    fx.rename = interrupted
    with pytest.raises(KeyboardInterrupt):
        tx(tmp_path, fx, three_step_patch(tmp_path, b"ok = 1\n")).apply()
    fx.rename = original_rename
    assert fx.snapshot() == before


# -- honest partial restores --------------------------------------------------------------


def test_a_tampered_backup_is_not_restored_and_the_restore_is_reported_partial(tmp_path):
    fx = agent()
    t = tx(tmp_path, fx, three_step_patch(tmp_path))
    original = WORKSPACE["config/greeting.txt"]
    real_create = fx.create_exclusive

    def tamper_then_create(path, data):
        if "faq.md" in path:            # the greeting backup was taken one step earlier
            t.store.object_path(sha(original)).write_bytes(b"tampered")
        return real_create(path, data)

    fx.create_exclusive = tamper_then_create
    outcome = t.apply()
    assert not outcome.ok and not outcome.restore.ok
    assert any("config/greeting.txt" in f and "checksum" in f for f in outcome.restore.failed)
    assert f"{ROOT}/prompts/faq.md" in outcome.restore.restored   # the others still restored
    assert live(fx, "prompts/faq.md") is None


def test_a_file_that_cannot_be_written_back_is_reported_partial(tmp_path):
    fx = agent()
    t = tx(tmp_path, fx, three_step_patch(tmp_path))
    real_rename = fx.rename
    renames = {"greeting": 0}

    def flaky(src, dst):
        if dst.endswith("config/greeting.txt"):
            renames["greeting"] += 1
            if renames["greeting"] == 2:            # the second rename is the restore
                raise ExecutorError("disk full")
        real_rename(src, dst)

    fx.rename = flaky
    outcome = t.apply()
    assert not outcome.restore.ok
    assert any("disk full" in f for f in outcome.restore.failed)
    assert f"{ROOT}/prompts/faq.md" in outcome.restore.restored
    assert not [path for path in fx.files if ".rollout-" in path]   # no staging debris


def test_a_lossy_transport_during_restore_never_corrupts_the_live_file(tmp_path):
    # Regression: restore used to rename the staged backup into place before proving
    # the staged bytes, so a damaged transfer landed on the live file.
    fx = agent()
    t = tx(tmp_path, fx, three_step_patch(tmp_path))       # step 3 fails its syntax gate
    real_create = fx.create_exclusive

    def lossy_after_step_two(path, data):
        if "invoices.py" in path:
            fx.corrupt_writes("greeting")                  # restore transfers now arrive damaged
        return real_create(path, data)

    fx.create_exclusive = lossy_after_step_two
    outcome = t.apply()
    assert not outcome.restore.ok
    assert any("config/greeting.txt" in f for f in outcome.restore.failed)
    assert live(fx, "config/greeting.txt") == GREETING_V2   # patched but intact, never damaged


def test_the_manifest_records_what_each_step_leaves_behind(tmp_path):
    fx = agent()
    t = tx(tmp_path, fx, greeting_patch(tmp_path))
    assert t.apply().ok
    [entry] = t.store.manifest("r-1", "agent-01").entries()
    assert entry.sha_before == sha(WORKSPACE["config/greeting.txt"])
    assert entry.sha_after == sha(GREETING_V2)


def test_a_restore_never_overwrites_a_file_changed_after_the_patch(tmp_path):
    # Regression: a rollback days later replayed the pre-state over whatever was there,
    # silently undoing every later patch to the same file.
    fx = agent()
    t = tx(tmp_path, fx, greeting_patch(tmp_path))
    assert t.apply().ok
    fx.put(f"{ROOT}/config/greeting.txt", b"written by a later patch\n")
    entries = t.store.manifest("r-1", "agent-01").entries()
    [conflict] = t.conflicts(entries)
    assert "config/greeting.txt" in conflict and "changed since" in conflict
    report = t.restore(entries)
    assert not report.ok and any("changed since" in f for f in report.failed)
    assert live(fx, "config/greeting.txt") == b"written by a later patch\n"
    forced = t.restore(entries, force=True)
    assert forced.ok, forced.detail
    assert live(fx, "config/greeting.txt") == WORKSPACE["config/greeting.txt"]


def test_a_file_already_back_in_its_pre_state_is_left_alone(tmp_path):
    fx = agent()
    t = tx(tmp_path, fx, greeting_patch(tmp_path))
    assert t.apply().ok
    fx.put(f"{ROOT}/config/greeting.txt", WORKSPACE["config/greeting.txt"])
    entries = t.store.manifest("r-1", "agent-01").entries()
    assert t.conflicts(entries) == []
    renames = len([c for c in fx.calls if c[0] == "rename"])
    assert t.restore(entries).ok
    assert len([c for c in fx.calls if c[0] == "rename"]) == renames


def test_a_file_the_patch_created_is_removed_only_if_it_is_unchanged(tmp_path):
    fx = agent()
    patch = make_patch(tmp_path, [write_step("files/faq.md", "prompts/faq.md")],
                       files={"files/faq.md": b"# FAQ\n"})
    t = tx(tmp_path, fx, patch)
    assert t.apply().ok
    fx.put(f"{ROOT}/prompts/faq.md", b"# FAQ\n- edited later\n")
    entries = t.store.manifest("r-1", "agent-01").entries()
    assert not t.restore(entries).ok and live(fx, "prompts/faq.md") is not None
    fx.put(f"{ROOT}/prompts/faq.md", b"# FAQ\n")
    assert t.restore(entries).ok and live(fx, "prompts/faq.md") is None


def test_restore_clears_the_marker_first(tmp_path):
    fx = agent()
    t = tx(tmp_path, fx, greeting_patch(tmp_path))
    assert t.apply().ok
    calls_before_restore = len(fx.calls)
    report = t.restore(t.store.manifest("r-1", "agent-01").entries())
    assert report.ok
    assert marker_path(ROOT, "demo-patch") not in fx.files
    assert live(fx, "config/greeting.txt") == WORKSPACE["config/greeting.txt"]
    first_mutation = next(c for c in fx.calls[calls_before_restore:]
                          if c[0] in ("remove", "rename", "write", "create_exclusive"))
    assert first_mutation == ("remove", (marker_path(ROOT, "demo-patch"),))


# -- the jail, re-checked on the target --------------------------------------------------


def test_a_symlinked_destination_is_refused_before_any_write(tmp_path):
    fx = agent()
    fx.put("/etc/motd", b"system file")
    del fx.files[f"{ROOT}/config/greeting.txt"]
    fx.symlink("/etc/motd", f"{ROOT}/config/greeting.txt")
    outcome = tx(tmp_path, fx, greeting_patch(tmp_path)).apply()
    assert not outcome.ok and "symlink" in outcome.error
    assert fx.files["/etc/motd"] == b"system file"
    assert not [c for c in fx.mutations if c[0] != "remove"]


def test_a_symlinked_parent_directory_escaping_the_root_is_refused(tmp_path):
    fx = agent()
    fx.mkdir("/etc/cron.d")
    fx.symlink("/etc/cron.d", f"{ROOT}/config")
    outcome = tx(tmp_path, fx, greeting_patch(tmp_path)).apply()
    assert not outcome.ok and "outside the workspace" in outcome.error
    assert not [p for p in fx.files if p.startswith("/etc/cron.d")]


def test_a_missing_parent_directory_needs_an_explicit_make_dirs(tmp_path):
    fx = agent()
    patch = make_patch(tmp_path, [write_step("files/a.txt", "cache/new/a.txt")],
                       files={"files/a.txt": b"x"})
    outcome = tx(tmp_path, fx, patch).apply()
    assert not outcome.ok and "make_dirs" in outcome.error
    patch = make_patch(tmp_path / "2", [
        {"kind": "run", "command": "make_dirs", "args": ["cache/new"]},
        write_step("files/a.txt", "cache/new/a.txt")], files={"files/a.txt": b"x"})
    assert tx(tmp_path / "2", agent(), patch).apply().ok


# -- pre-state drift (also re-checked at apply time) -------------------------------------


def test_a_hand_modified_target_is_refused_not_overwritten(tmp_path):
    fx = agent()
    fx.put(f"{ROOT}/config/greeting.txt", b"hotfix someone made by hand\n")
    patch = greeting_patch(tmp_path, expect_sha256=sha(WORKSPACE["config/greeting.txt"]))
    outcome = tx(tmp_path, fx, patch).apply()
    assert not outcome.ok and "drift" in outcome.error
    assert live(fx, "config/greeting.txt") == b"hotfix someone made by hand\n"


def test_drift_can_be_overridden_only_explicitly(tmp_path):
    fx = agent()
    fx.put(f"{ROOT}/config/greeting.txt", b"hotfix\n")
    patch = greeting_patch(tmp_path, expect_sha256=sha(WORKSPACE["config/greeting.txt"]))
    outcome = tx(tmp_path, fx, patch, allow_drift=True).apply()
    assert outcome.ok and any("DRIFT OVERRIDE" in s.detail for s in outcome.steps)


def test_a_resumed_apply_is_not_mistaken_for_drift(tmp_path):
    fx = agent()
    fx.put(f"{ROOT}/config/greeting.txt", GREETING_V2)   # a crashed run already swapped it
    patch = greeting_patch(tmp_path, expect_sha256=sha(WORKSPACE["config/greeting.txt"]))
    assert tx(tmp_path, fx, patch).apply().ok


def test_drift_introduced_after_preflight_is_caught_at_apply_time(tmp_path):
    fx = agent()
    patch = greeting_patch(tmp_path, expect_sha256=sha(WORKSPACE["config/greeting.txt"]))
    t = tx(tmp_path, fx, patch)
    assert t.preflight().ok
    fx.put(f"{ROOT}/config/greeting.txt", b"edited during the rollout\n")   # TOCTOU
    outcome = t.apply()
    assert not outcome.ok and "drift" in outcome.error
    assert live(fx, "config/greeting.txt") == b"edited during the rollout\n"


# -- append_block --------------------------------------------------------------------


def append_patch(tmp_path):
    return make_patch(tmp_path, [{"kind": "append_block", "source": "files/rule.md",
                                  "dest": "prompts/support.md",
                                  "marker": "<!-- rule: refunds-v2 -->"}],
                      files={"files/rule.md": b"- Refunds over $50 need a manager.\n"})


def test_append_block_adds_marker_and_block_once(tmp_path):
    fx = agent()
    assert tx(tmp_path, fx, append_patch(tmp_path)).apply().ok
    text = live(fx, "prompts/support.md")
    assert text == (b"# Support rules\n- Be kind.\n<!-- rule: refunds-v2 -->\n"
                    b"- Refunds over $50 need a manager.\n")


def test_append_block_is_a_no_op_when_the_marker_is_already_there(tmp_path):
    fx = agent()
    assert tx(tmp_path, fx, append_patch(tmp_path)).apply().ok
    once = live(fx, "prompts/support.md")
    del fx.files[marker_path(ROOT, "demo-patch")]
    outcome = tx(tmp_path, fx, append_patch(tmp_path)).apply()
    assert outcome.ok and live(fx, "prompts/support.md") == once
    assert any("already present" in s.detail for s in outcome.steps)


def test_append_block_refuses_a_file_with_a_duplicated_marker(tmp_path):
    fx = agent()
    doubled = b"<!-- rule: refunds-v2 -->\nold\n<!-- rule: refunds-v2 -->\nold\n"
    fx.put(f"{ROOT}/prompts/support.md", doubled)
    outcome = tx(tmp_path, fx, append_patch(tmp_path)).apply()
    assert not outcome.ok and "2 times" in outcome.error
    assert live(fx, "prompts/support.md") == doubled


# -- sql_upsert and run --------------------------------------------------------------------


def sql_patch(tmp_path, *, then_fail=False):
    steps = [{"kind": "sql_upsert", "db": "data/settings.db", "table": "settings",
              "key_column": "name", "key": "invoice_template", "values": {"value": "v2"}}]
    files = {}
    if then_fail:
        steps.append(write_step("files/bad.py", "handlers/bad.py"))
        files["files/bad.py"] = b"def broken(:\n"
    return make_patch(tmp_path, steps, files=files)


def test_sql_upsert_updates_the_row_and_reads_it_back(tmp_path):
    fx = agent(with_db=True)
    outcome = tx(tmp_path, fx, sql_patch(tmp_path)).apply()
    assert outcome.ok, outcome.error
    assert db_value(fx) == "v2"


def test_a_later_failure_puts_the_row_back(tmp_path):
    fx = agent(with_db=True)
    outcome = tx(tmp_path, fx, sql_patch(tmp_path, then_fail=True)).apply()
    assert not outcome.ok and outcome.restore.ok
    assert db_value(fx) == "v1"


def test_sql_upsert_is_undone_row_by_row(tmp_path):
    # Regression: the database used to be restored by swapping the whole file back, which
    # deleted every row the live agent had written since the patch.
    fx = agent(with_db=True)
    t = tx(tmp_path, fx, sql_patch(tmp_path))
    assert t.apply().ok
    agent_writes_db(fx, "INSERT INTO settings VALUES ('customer_note', 'written by the agent')")
    report = t.restore(t.store.manifest("r-1", "agent-01").entries())
    assert report.ok, report.detail
    assert db_value(fx) == "v1"
    assert db_value(fx, "customer_note") == "written by the agent"


def test_a_row_changed_after_the_patch_is_not_overwritten(tmp_path):
    fx = agent(with_db=True)
    t = tx(tmp_path, fx, sql_patch(tmp_path))
    assert t.apply().ok
    agent_writes_db(fx, "UPDATE settings SET value = 'v3' WHERE name = 'invoice_template'")
    entries = t.store.manifest("r-1", "agent-01").entries()
    [conflict] = t.conflicts(entries)
    assert "invoice_template" in conflict and "changed since" in conflict
    assert not t.restore(entries).ok and db_value(fx) == "v3"
    assert t.restore(entries, force=True).ok and db_value(fx) == "v1"


def test_a_row_the_patch_inserted_is_deleted_on_restore(tmp_path):
    fx = agent(with_db=True)
    patch = make_patch(tmp_path, [{"kind": "sql_upsert", "db": "data/settings.db",
                                   "table": "settings", "key_column": "name",
                                   "key": "receipt_footer", "values": {"value": "Thanks!"}}])
    t = tx(tmp_path, fx, patch)
    assert t.apply().ok and db_value(fx, "receipt_footer") == "Thanks!"
    assert t.restore(t.store.manifest("r-1", "agent-01").entries()).ok
    assert db_value(fx, "receipt_footer") is None and db_value(fx) == "v1"


def test_an_upsert_refuses_a_row_that_changed_after_it_was_backed_up(tmp_path):
    fx = agent(with_db=True)
    real_run = fx.run

    def racing_agent(argv, *, stdin=None, timeout=60.0):
        if argv[:3] == ["python3", "-c", scripts.SQL_ROW] and json.loads(stdin)["op"] == "upsert":
            agent_writes_db(fx, "UPDATE settings SET value = 'agent' "
                                "WHERE name = 'invoice_template'")
        return real_run(argv, stdin=stdin, timeout=timeout)

    fx.run = racing_agent
    outcome = tx(tmp_path, fx, sql_patch(tmp_path)).apply()
    assert not outcome.ok and "changed" in outcome.error
    assert db_value(fx) == "agent"                  # the agent's write survives
    assert outcome.restore.ok                       # and nothing of ours needed undoing


def test_sql_upsert_refuses_a_database_with_a_live_write_ahead_log(tmp_path):
    fx = agent(with_db=True)
    fx.put(f"{ROOT}/data/settings.db-wal", b"\x37\x7f\x06\x82 pending frames")
    outcome = tx(tmp_path, fx, sql_patch(tmp_path)).apply()
    assert not outcome.ok and "write-ahead log" in outcome.error
    assert db_value(fx) == "v1"


def test_sql_upsert_needs_the_database_to_exist(tmp_path):
    fx = agent()
    outcome = tx(tmp_path, fx, sql_patch(tmp_path)).apply()
    assert not outcome.ok and "does not exist" in outcome.error
    assert f"{ROOT}/data/settings.db" not in fx.files


def test_run_steps_read_their_effect_back(tmp_path):
    fx = agent()
    fx.put(f"{ROOT}/bin/rotate-logs", b"#!/bin/sh\n")
    patch = make_patch(tmp_path, [
        {"kind": "run", "command": "make_dirs", "args": ["cache/invoices"]},
        {"kind": "run", "command": "make_executable", "args": ["bin/rotate-logs"]}])
    outcome = tx(tmp_path, fx, patch).apply()
    assert outcome.ok, outcome.error
    assert fx.inspect(f"{ROOT}/cache/invoices").is_dir


def test_a_failing_command_rolls_back(tmp_path):
    fx = agent()
    patch = make_patch(tmp_path, [
        write_step("files/greeting.txt", "config/greeting.txt"),
        {"kind": "run", "command": "make_executable", "args": ["bin/missing-tool"]}],
        files={"files/greeting.txt": GREETING_V2})
    outcome = tx(tmp_path, fx, patch).apply()
    assert not outcome.ok and outcome.restore.ok
    assert live(fx, "config/greeting.txt") == WORKSPACE["config/greeting.txt"]


# -- preflight (read-only) -----------------------------------------------------------


def test_preflight_is_read_only_and_passes_on_a_healthy_target(tmp_path):
    fx = agent()
    report = tx(tmp_path, fx, greeting_patch(tmp_path)).preflight()
    assert report.ok and not report.already_applied
    assert fx.mutations == []


def test_preflight_refuses_a_target_that_is_already_unhealthy(tmp_path):
    fx = agent()
    fx.put(f"{ROOT}/config/agent.json", BROKEN_CONFIG)
    report = tx(tmp_path, fx, greeting_patch(tmp_path)).preflight()
    assert not report.ok and any("before we touched it" in p for p in report.problems)


def test_preflight_sees_a_held_lock(tmp_path):
    fx = agent()
    acquire(fx, ROOT, LockOwner("r-other", "eng.lead", "other-patch", Clock()().isoformat()))
    report = tx(tmp_path, fx, greeting_patch(tmp_path)).preflight()
    assert not report.ok and any("r-other" in p for p in report.problems)


def test_preflight_detects_an_applied_marker(tmp_path):
    fx = agent()
    t = tx(tmp_path, fx, greeting_patch(tmp_path))
    assert t.apply().ok
    report = t.preflight()
    assert report.ok and report.already_applied


def test_a_marker_from_different_patch_content_is_a_problem(tmp_path):
    fx = agent()
    fx.put(marker_path(ROOT, "demo-patch"), json.dumps({"digest": "f" * 64}).encode())
    report = tx(tmp_path, fx, greeting_patch(tmp_path)).preflight()
    assert not report.ok and any("different content" in p for p in report.problems)


def test_preflight_checks_disk_space_where_the_files_land(tmp_path):
    fx = agent()
    fx.free = 1024
    report = tx(tmp_path, fx, greeting_patch(tmp_path)).preflight()
    assert not report.ok and any("free" in p for p in report.problems)


def test_preflight_treats_an_unreachable_target_as_a_failure(tmp_path):
    fx = agent()
    fx.fail("inspect", error="ssh connection failed", times=99)
    report = tx(tmp_path, fx, greeting_patch(tmp_path)).preflight()
    assert not report.ok and any("ssh connection failed" in p for p in report.problems)


def test_preflight_reports_pre_state_drift(tmp_path):
    fx = agent()
    fx.put(f"{ROOT}/config/greeting.txt", b"hand edit\n")
    patch = greeting_patch(tmp_path, expect_sha256=sha(WORKSPACE["config/greeting.txt"]))
    report = tx(tmp_path, fx, patch).preflight()
    assert not report.ok and any("drift" in p for p in report.problems)
    report = tx(tmp_path, fx, patch, allow_drift=True).preflight()
    assert report.ok and any("DRIFT OVERRIDE" in n for n in report.notes)


def test_preflight_refuses_a_symlinked_destination(tmp_path):
    fx = agent()
    del fx.files[f"{ROOT}/config/greeting.txt"]
    fx.symlink("/etc/motd", f"{ROOT}/config/greeting.txt")
    report = tx(tmp_path, fx, greeting_patch(tmp_path)).preflight()
    assert not report.ok and any("symlink" in p for p in report.problems)
