"""One behavioural contract, two implementations.

Every test here runs against the in-memory FakeExecutor *and* against the real container
adapter executing its actual shell scripts under a local POSIX `sh` (identity transport,
`python3` mapped to this interpreter). If the fake ever drifts from what the real
adapter does, this file fails, which is what makes the rest of the suite trustworthy.
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys

import pytest

from fleet_rollout import scripts
from fleet_rollout.executors.base import ExecutorError
from fleet_rollout.executors.container import ContainerExecutor
from fleet_rollout.testing import FakeExecutor


class LocalTransport:
    error_codes = {127: "command not found"}

    def wrap(self, argv):
        argv = list(argv)
        if argv and argv[0] == "python3":
            argv[0] = sys.executable
        return argv


class Env:
    def __init__(self, kind, executor, root, symlink, posix):
        self.kind, self.ex, self.root, self._symlink, self.posix = (
            kind, executor, root, symlink, posix)

    def symlink(self, target, link):
        """Create `link` pointing at `target` (os.symlink argument order)."""
        if self._symlink is None:
            pytest.skip("symlinks need a POSIX filesystem for this implementation")
        self._symlink(target, link)

    def mkdir(self, path):
        self.ex.run(["mkdir", "-p", "--", path])


@pytest.fixture(params=["fake", "real-sh"])
def env(request, tmp_path):
    if request.param == "fake":
        fx = FakeExecutor("agent-01")
        fx.mkdir("/srv/agent")
        return Env("fake", fx, "/srv/agent", fx.symlink, True)
    if shutil.which("sh") is None:
        pytest.skip("needs a POSIX sh")
    ex = ContainerExecutor(LocalTransport(), runner=subprocess.run, name="local")
    posix = os.name != "nt"
    return Env("real-sh", ex, tmp_path.as_posix(), os.symlink if posix else None, posix)


def test_binary_round_trip(env):
    payload = bytes(range(256)) * 3
    env.ex.write(f"{env.root}/blob.bin", payload)
    assert env.ex.read(f"{env.root}/blob.bin") == payload


def test_missing_reads_as_none(env):
    assert env.ex.read(f"{env.root}/missing.txt") is None


def test_a_directory_is_not_readable_as_a_file(env):
    env.mkdir(f"{env.root}/adir")
    with pytest.raises(ExecutorError, match="not a regular file"):
        env.ex.read(f"{env.root}/adir")


def test_write_needs_an_existing_parent_directory(env):
    with pytest.raises(ExecutorError):
        env.ex.write(f"{env.root}/no/such/dir/file.txt", b"x")


def test_rename_replaces_atomically(env):
    env.ex.write(f"{env.root}/new", b"new")
    env.ex.write(f"{env.root}/live", b"old")
    env.ex.rename(f"{env.root}/new", f"{env.root}/live")
    assert env.ex.read(f"{env.root}/live") == b"new"
    assert env.ex.read(f"{env.root}/new") is None


def test_rename_onto_a_directory_is_refused(env):
    env.ex.write(f"{env.root}/new", b"payload")
    env.mkdir(f"{env.root}/target")
    with pytest.raises(ExecutorError, match="directory"):
        env.ex.rename(f"{env.root}/new", f"{env.root}/target")
    assert env.ex.read(f"{env.root}/new") == b"payload"


def test_inspect_files_dirs_and_missing(env):
    env.ex.write(f"{env.root}/f.txt", b"x")
    env.mkdir(f"{env.root}/d")
    f = env.ex.inspect(f"{env.root}/f.txt")
    assert (f.exists, f.is_file, f.is_dir, f.is_symlink) == (True, True, False, False)
    assert f.realpath.endswith("/f.txt")
    d = env.ex.inspect(f"{env.root}/d")
    assert (d.exists, d.is_file, d.is_dir) == (True, False, True)
    missing = env.ex.inspect(f"{env.root}/missing")
    assert (missing.exists, missing.is_symlink) == (False, False)


def test_inspect_resolves_a_symlinked_file(env):
    env.mkdir(f"{env.root}/elsewhere")
    env.ex.write(f"{env.root}/elsewhere/real.txt", b"x")
    env.symlink(f"{env.root}/elsewhere/real.txt", f"{env.root}/link.txt")
    info = env.ex.inspect(f"{env.root}/link.txt")
    assert info.is_symlink and info.exists and info.is_file
    assert info.realpath.endswith("/elsewhere/real.txt")


def test_inspect_resolves_a_symlinked_parent_directory(env):
    env.mkdir(f"{env.root}/outside")
    env.symlink(f"{env.root}/outside", f"{env.root}/config")
    info = env.ex.inspect(f"{env.root}/config/greeting.txt")
    assert not info.exists and not info.is_symlink
    assert info.realpath.endswith("/outside/greeting.txt")


def test_write_follows_a_symlink_like_cat_does(env):
    # This is why the transaction refuses symlinked destinations before writing.
    env.mkdir(f"{env.root}/outside")
    env.ex.write(f"{env.root}/outside/target.txt", b"original")
    env.symlink(f"{env.root}/outside/target.txt", f"{env.root}/link.txt")
    env.ex.write(f"{env.root}/link.txt", b"overwritten")
    assert env.ex.read(f"{env.root}/outside/target.txt") == b"overwritten"


def test_create_exclusive_first_writer_wins_and_makes_the_parent(env):
    lock = f"{env.root}/.state/lock"
    assert env.ex.create_exclusive(lock, b"run-1") is True
    assert env.ex.create_exclusive(lock, b"run-2") is False
    assert env.ex.read(lock) == b"run-1"


def test_remove_is_idempotent(env):
    env.ex.write(f"{env.root}/gone.txt", b"x")
    env.ex.remove(f"{env.root}/gone.txt")
    env.ex.remove(f"{env.root}/gone.txt")
    assert env.ex.read(f"{env.root}/gone.txt") is None


def test_free_bytes_is_positive(env):
    assert env.ex.free_bytes(env.root) > 0


def test_make_dirs_command(env):
    result = env.ex.run(["mkdir", "-p", "--", f"{env.root}/a/b", f"{env.root}/c"])
    assert result.ok
    assert env.ex.inspect(f"{env.root}/a/b").is_dir and env.ex.inspect(f"{env.root}/c").is_dir


def test_make_executable_then_test_x(env):
    if not env.posix:
        pytest.skip("exec bits need a POSIX filesystem")
    env.ex.write(f"{env.root}/tool.sh", b"#!/bin/sh\necho hi\n")
    assert not env.ex.run(["test", "-x", f"{env.root}/tool.sh"]).ok
    assert env.ex.run(["chmod", "0755", "--", f"{env.root}/tool.sh"]).ok
    assert env.ex.run(["test", "-x", f"{env.root}/tool.sh"]).ok


def test_compile_check(env):
    env.ex.write(f"{env.root}/ok.py", b"def f():\n    return 1\n")
    env.ex.write(f"{env.root}/bad.py", b"def f(:\n    return 1\n")
    assert env.ex.run(["python3", "-c", scripts.COMPILE_PYTHON, f"{env.root}/ok.py"]).ok
    bad = env.ex.run(["python3", "-c", scripts.COMPILE_PYTHON, f"{env.root}/bad.py"])
    assert not bad.ok and b"SyntaxError" in bad.stderr


def test_sql_upsert(env, tmp_path):
    seed = tmp_path / "seed.db"
    con = sqlite3.connect(seed)
    con.execute("CREATE TABLE settings (name TEXT PRIMARY KEY, value TEXT)")
    con.commit()
    con.close()
    db = f"{env.root}/settings.db"
    env.ex.write(db, seed.read_bytes())
    payload = {"db": db, "table": "settings", "key_column": "name", "key": "greeting",
               "values": {"value": "Hi"}}
    result = env.ex.run(["python3", "-c", scripts.SQL_UPSERT],
                        stdin=json.dumps(payload).encode())
    assert result.ok, result.summary()
    assert json.loads(result.stdout) == {"ok": True, "row": {"value": "Hi"}}
    after = tmp_path / "after.db"
    after.write_bytes(env.ex.read(db))
    con = sqlite3.connect(after)
    assert con.execute("SELECT value FROM settings WHERE name='greeting'").fetchone() == ("Hi",)
    con.close()


def test_unknown_commands_fail(env):
    with pytest.raises(ExecutorError, match="not found"):
        env.ex.run(["definitely-not-a-real-command-xyz"])
