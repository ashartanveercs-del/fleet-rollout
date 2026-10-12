"""The snippets in fleet_rollout.scripts run inside targets; here they run for real against
local files and a loopback HTTP server, using this interpreter in place of the target's."""

import json
import sqlite3
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fleet_rollout import scripts


def run_snippet(source, *args, stdin=b""):
    return subprocess.run([sys.executable, "-c", source, *args], input=stdin,
                          capture_output=True, timeout=30, check=False)


# -- SQL upsert ------------------------------------------------------------------------


@pytest.fixture
def settings_db(tmp_path):
    path = tmp_path / "settings.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE settings (name TEXT PRIMARY KEY, value TEXT, rev INTEGER)")
    con.execute("INSERT INTO settings VALUES ('greeting', 'Hello', 1)")
    con.commit()
    con.close()
    return path


def row_op(db, op, **overrides):
    payload = {"op": op, "db": str(db), "table": "settings", "key_column": "name",
               "key": "invoice_template", "values": {"value": "v2", "rev": 2}}
    payload.update(overrides)
    return run_snippet(scripts.SQL_ROW, stdin=json.dumps(payload).encode())


def upsert(db, **overrides):
    return row_op(db, overrides.pop("op", "upsert"), **overrides)


def rows(db):
    con = sqlite3.connect(db)
    try:
        return sorted(con.execute("SELECT name, value, rev FROM settings").fetchall())
    finally:
        con.close()


def test_upsert_inserts_a_missing_row_and_reads_it_back(settings_db):
    result = upsert(settings_db)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"ok": True, "row": {"value": "v2", "rev": 2}}
    assert ("invoice_template", "v2", 2) in rows(settings_db)


def test_upsert_updates_an_existing_row(settings_db):
    result = upsert(settings_db, key="greeting", values={"value": "Hi there"})
    assert result.returncode == 0, result.stderr
    assert ("greeting", "Hi there", 1) in rows(settings_db)


def test_hostile_values_are_stored_as_data_never_executed(settings_db):
    evil = "x'); DROP TABLE settings; --"
    result = upsert(settings_db, key=evil, values={"value": evil})
    assert result.returncode == 0, result.stderr
    assert (evil, evil, None) in rows(settings_db)  # the table still exists


def test_missing_table_exits_4_and_changes_nothing(settings_db):
    before = settings_db.read_bytes()
    assert upsert(settings_db, table="no_such_table").returncode == 4
    assert settings_db.read_bytes() == before


def test_missing_database_exits_3_and_is_not_created(tmp_path):
    missing = tmp_path / "nope.db"
    assert upsert(missing).returncode == 3
    assert not missing.exists()


@pytest.mark.parametrize("override", [
    {"table": 'settings" ; DROP TABLE settings; --'},
    {"key_column": "name = name OR 1"},
    {"values": {"value; DROP TABLE settings": "x"}},
    {"table": "sqlite_master"},
    {"values": {}},
    {"op": "drop"},
])
def test_the_script_rechecks_identifiers_itself(settings_db, override):
    before = settings_db.read_bytes()
    assert upsert(settings_db, **override).returncode == 5
    assert settings_db.read_bytes() == before


def test_read_returns_the_current_values_and_writes_nothing(settings_db):
    before = settings_db.read_bytes()
    result = row_op(settings_db, "read", key="greeting", values={"value": "x", "rev": 0})
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["row"] == {"value": "Hello", "rev": 1}
    assert json.loads(row_op(settings_db, "read").stdout)["row"] is None    # no such row
    assert settings_db.read_bytes() == before


def test_upsert_refuses_a_row_that_changed_since_it_was_read(settings_db):
    before = settings_db.read_bytes()
    result = upsert(settings_db, key="greeting", values={"value": "Hi"},
                    previous={"value": "Howdy"})
    assert result.returncode == 7
    assert settings_db.read_bytes() == before


def test_restore_puts_back_only_the_columns_the_patch_wrote(settings_db):
    assert upsert(settings_db, key="greeting", values={"value": "Hi"}).returncode == 0
    result = row_op(settings_db, "restore", key="greeting", values={"value": "Hi"},
                    previous={"value": "Hello"})
    assert result.returncode == 0, result.stderr
    assert ("greeting", "Hello", 1) in rows(settings_db)


def test_restore_deletes_a_row_the_patch_inserted(settings_db):
    assert upsert(settings_db).returncode == 0
    assert row_op(settings_db, "restore", previous=None).returncode == 0
    assert [r for r in rows(settings_db) if r[0] == "invoice_template"] == []
    assert ("greeting", "Hello", 1) in rows(settings_db)


def test_restore_refuses_a_row_changed_after_the_patch_unless_forced(settings_db):
    assert upsert(settings_db, key="greeting", values={"value": "Hi"}).returncode == 0
    assert upsert(settings_db, key="greeting", values={"value": "Hey"}).returncode == 0
    payload = {"key": "greeting", "values": {"value": "Hi"}, "previous": {"value": "Hello"}}
    result = row_op(settings_db, "restore", **payload)
    assert result.returncode == 7
    assert json.loads(result.stdout)["row"] == {"value": "Hey"}
    assert ("greeting", "Hey", 1) in rows(settings_db)
    assert row_op(settings_db, "restore", force=True, **payload).returncode == 0
    assert ("greeting", "Hello", 1) in rows(settings_db)


def test_restore_of_a_row_already_in_its_pre_state_changes_nothing(settings_db):
    result = row_op(settings_db, "restore", key="greeting", values={"value": "Hi"},
                    previous={"value": "Hello"})
    assert result.returncode == 0
    assert ("greeting", "Hello", 1) in rows(settings_db)


def test_values_that_are_neither_text_nor_numbers_are_refused(settings_db):
    con = sqlite3.connect(settings_db)
    con.execute("UPDATE settings SET value = x'00ff' WHERE name = 'greeting'")
    con.commit()
    con.close()
    assert row_op(settings_db, "read", key="greeting", values={"value": "x"}).returncode == 8


# -- compile check ---------------------------------------------------------------------


def test_compile_accepts_valid_python_without_writing_bytecode(tmp_path):
    good = tmp_path / "ok.py"
    good.write_text("def total(items):\n    return sum(items)\n")
    result = run_snippet(scripts.COMPILE_PYTHON, str(good))
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "__pycache__").exists()


def test_compile_rejects_a_syntax_error(tmp_path):
    bad = tmp_path / "bad.py"
    bad.write_text("def total(items:\n    return sum(items)\n")
    result = run_snippet(scripts.COMPILE_PYTHON, str(bad))
    assert result.returncode != 0
    assert b"SyntaxError" in result.stderr


# -- HTTP probe ------------------------------------------------------------------------


class _Agent(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        status, body = {"/healthz": (200, b'{"status":"ok"}'),
                        "/teapot": (418, b"short and stout")}.get(self.path, (404, b"nope"))
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def agent_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Agent)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def test_probe_prints_status_then_raw_body(agent_url):
    result = run_snippet(scripts.HTTP_PROBE, agent_url + "/healthz", "5")
    assert result.returncode == 0, result.stderr
    assert result.stdout == b'200\n{"status":"ok"}'


def test_probe_reports_error_statuses_with_their_body(agent_url):
    result = run_snippet(scripts.HTTP_PROBE, agent_url + "/teapot", "5")
    assert result.stdout == b"418\nshort and stout"


def test_probe_fails_loudly_when_nothing_listens():
    result = run_snippet(scripts.HTTP_PROBE, "http://127.0.0.1:9/healthz", "2")
    assert result.returncode != 0
