"""An in-memory executor for tests and rehearsals: no Docker, no SSH, no network.

`FakeExecutor` models the parts of a container the engine touches: a POSIX-like file
tree with directories and symlinks, a health endpoint, and the handful of commands the
allowlist can run. `tests/test_executor_contract.py` runs the same behavioural contract
against this fake and against the real adapter under a real shell, so the fake stays
honest. It also supports fault injection, which is how the test suite proves that every
failure path restores the target.

Row reads, upserts and restores run the real `scripts.SQL_ROW` program with this Python
interpreter against a temporary copy of the database bytes, so SQLite semantics are real
too.
"""

from __future__ import annotations

import json
import posixpath
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from . import scripts
from .executors.base import CommandResult, ExecutorError, HttpResponse, PathInfo
from .fleet import Fleet, Target

HealthFn = Callable[["FakeExecutor"], HttpResponse]
_MUTATING = frozenset({"write", "rename", "remove", "create_exclusive", "run"})


def healthy(body: bytes = b'{"status":"ok"}', status: int = 200) -> HealthFn:
    """A health endpoint that always answers the same thing."""
    return lambda _fx: HttpResponse(status=status, body=body)


def json_config_health(config_path: str, *, require: Mapping[str, object] | None = None
                       ) -> HealthFn:
    """Health derived from the agent's *loaded* JSON config, the way a real agent might:
    200 + {"status":"ok"} when the config parses (and has the `require`d values),
    otherwise 200 + {"status":"degraded"}. Note the 200: only the body tells them apart."""

    def health(fx: FakeExecutor) -> HttpResponse:
        raw = fx.loaded_file(config_path)
        try:
            config = json.loads(raw or b"")
            ok = isinstance(config, dict) and all(
                config.get(k) == v for k, v in (require or {}).items())
        except ValueError:
            ok = False
        body = {"status": "ok"} if ok else {"status": "degraded", "reason": "config"}
        return HttpResponse(status=200, body=json.dumps(body).encode())

    return health


def simulate_fleet(fleet: Fleet, *, health_for: Callable[[Target], HealthFn] | None = None,
                   extra_files: Mapping[str, bytes] | None = None) -> dict[str, FakeExecutor]:
    """One FakeExecutor per target, its workspace seeded from the rendered golden template
    plus `extra_files` (workspace-relative). Use `agents[target.name]` as the executor."""
    from .template import render_golden
    from .validation import join_root

    agents = {}
    for target in fleet.targets:
        rendered = render_golden(fleet.golden_dir, target) if fleet.golden_dir else {}
        files = {join_root(target.root, rel): data
                 for rel, data in {**rendered, **(extra_files or {})}.items()}
        agent = FakeExecutor(target.name, files,
                             health=health_for(target) if health_for else None)
        agent.mkdir(target.root)
        agents[target.name] = agent
    return agents


@dataclass
class _Fault:
    op: str
    path: str | None
    error: str
    times: int


class FakeExecutor:
    def __init__(self, name: str = "fake", files: Mapping[str, bytes | str] | None = None, *,
                 health: HealthFn | None = None, free: int = 10 * 2**30) -> None:
        self.name = name
        self.files: dict[str, bytes] = {}
        self.dirs: set[str] = {"/"}
        self.links: dict[str, str] = {}
        self.modes: dict[str, int] = {}
        self.calls: list[tuple[str, tuple]] = []
        self.health: HealthFn = health or healthy()
        self.free = free
        self.reloads = 0
        self.loaded: dict[str, bytes] | None = None
        self.commands: dict[str, Callable[[FakeExecutor, list[str], bytes], CommandResult]] = {}
        self._faults: list[_Fault] = []
        self._corrupt: set[str] = set()
        for path, data in (files or {}).items():
            self.put(path, data)

    # -- setup and inspection helpers (not recorded as calls) ---------------------------

    def put(self, path: str, data: bytes | str) -> None:
        self.mkdir(posixpath.dirname(path))
        self.files[path] = data.encode() if isinstance(data, str) else bytes(data)

    def mkdir(self, path: str) -> None:
        parts = [p for p in path.split("/") if p]
        cur = "/"
        for part in parts:
            cur = posixpath.join(cur, part)
            real = self._resolve(cur)
            if real in self.files:
                raise ExecutorError(f"{self.name}: mkdir {cur}: File exists")
            self.dirs.add(real)

    def symlink(self, target: str, link: str) -> None:
        """Create `link` -> `target` (argument order matches os.symlink)."""
        self.links[link] = target

    def snapshot(self) -> dict[str, bytes]:
        return dict(self.files)

    def reload(self) -> None:
        """What SIGHUP does to the simulated agent: re-read files into memory."""
        self.reloads += 1
        self.loaded = dict(self.files)

    def loaded_file(self, path: str) -> bytes | None:
        source = self.loaded if self.loaded is not None else self.files
        return source.get(self._resolve(path))

    @property
    def mutations(self) -> list[tuple[str, tuple]]:
        return [c for c in self.calls if c[0] in _MUTATING]

    def fail(self, op: str, path: str | None = None, *, error: str = "injected failure",
             times: int = 1) -> None:
        """Make the next `times` calls of `op` (on paths containing `path`) raise."""
        self._faults.append(_Fault(op, path, error, times))

    def corrupt_writes(self, path_fragment: str) -> None:
        """Bytes written to matching paths arrive altered (a lossy transport)."""
        self._corrupt.add(path_fragment)

    # -- path resolution ---------------------------------------------------------------

    def _resolve(self, path: str, *, follow_last: bool = True, depth: int = 0) -> str:
        if depth > 40:
            raise ExecutorError(f"{self.name}: too many levels of symbolic links")
        cur = "/"
        parts = [p for p in path.split("/") if p]
        for i, part in enumerate(parts):
            nxt = posixpath.join(cur, part)
            last = i == len(parts) - 1
            if nxt in self.links and (follow_last or not last):
                target = self.links[nxt]
                if not target.startswith("/"):
                    target = posixpath.join(cur, target)
                nxt = self._resolve(posixpath.normpath(target), depth=depth + 1)
            cur = nxt
        return cur

    def _lexists(self, path: str) -> bool:
        parent = self._resolve(posixpath.dirname(path))
        name = posixpath.join(parent, posixpath.basename(path))
        return name in self.files or name in self.dirs or name in self.links

    def _check_faults(self, op: str, *paths: str) -> None:
        for fault in self._faults:
            if fault.op == op and fault.times > 0 and (
                    fault.path is None or any(fault.path in p for p in paths)):
                fault.times -= 1
                raise ExecutorError(f"{self.name}: {op}: {fault.error}")

    def _maybe_corrupt(self, path: str, data: bytes) -> bytes:
        if any(fragment in path for fragment in self._corrupt):
            return data[:-1] + bytes([data[-1] ^ 0xFF]) if data else b"\x00"
        return bytes(data)

    def _record(self, op: str, *args) -> None:
        self.calls.append((op, args))

    # -- the Executor interface ----------------------------------------------------------

    def read(self, path: str) -> bytes | None:
        self._record("read", path)
        self._check_faults("read", path)
        real = self._resolve(path)
        if real in self.files:
            return self.files[real]
        if real in self.dirs or self._lexists(path):
            raise ExecutorError(f"{self.name}: {path} exists but is not a regular file")
        return None

    def write(self, path: str, data: bytes) -> None:
        self._record("write", path, len(data))
        self._check_faults("write", path)
        real = self._resolve(path)
        if self._resolve(posixpath.dirname(real)) not in self.dirs:
            raise ExecutorError(f"{self.name}: write {path}: No such file or directory")
        if real in self.dirs:
            raise ExecutorError(f"{self.name}: write {path}: Is a directory")
        if any(fragment in path for fragment in self._corrupt):
            data = data[:-1] + bytes([data[-1] ^ 0xFF]) if data else b"\x00"
        self.files[real] = bytes(data)

    def rename(self, src: str, dst: str) -> None:
        self._record("rename", src, dst)
        self._check_faults("rename", src, dst)
        src_parent = self._resolve(posixpath.dirname(src))
        src_entry = posixpath.join(src_parent, posixpath.basename(src))
        if self._resolve(dst) in self.dirs:
            raise ExecutorError(f"{self.name}: refusing to rename onto {dst}: it is a directory")
        dst_parent = self._resolve(posixpath.dirname(dst))
        if dst_parent not in self.dirs:
            raise ExecutorError(f"{self.name}: rename {dst}: No such file or directory")
        dst_entry = posixpath.join(dst_parent, posixpath.basename(dst))
        if src_entry in self.links:
            self.links[dst_entry] = self.links.pop(src_entry)
            self.files.pop(dst_entry, None)
        elif src_entry in self.files:
            self.links.pop(dst_entry, None)
            self.files[dst_entry] = self.files.pop(src_entry)
            if src_entry in self.modes:
                self.modes[dst_entry] = self.modes.pop(src_entry)
        else:
            raise ExecutorError(f"{self.name}: rename {src}: No such file or directory")

    def remove(self, path: str) -> None:
        self._record("remove", path)
        self._check_faults("remove", path)
        parent = self._resolve(posixpath.dirname(path))
        entry = posixpath.join(parent, posixpath.basename(path))
        if entry in self.dirs and entry not in self.links:
            raise ExecutorError(f"{self.name}: remove {path}: Is a directory")
        self.links.pop(entry, None)
        self.files.pop(entry, None)

    def inspect(self, path: str) -> PathInfo:
        self._record("inspect", path)
        self._check_faults("inspect", path)
        parent = self._resolve(posixpath.dirname(path))
        entry = posixpath.join(parent, posixpath.basename(path))
        real = self._resolve(path)
        is_file, is_dir = real in self.files, real in self.dirs
        return PathInfo(exists=is_file or is_dir, is_file=is_file, is_dir=is_dir,
                        is_symlink=entry in self.links, realpath=real)

    def create_exclusive(self, path: str, data: bytes) -> bool:
        self._record("create_exclusive", path)
        self._check_faults("create_exclusive", path)
        self.mkdir(posixpath.dirname(path))
        if self._lexists(path):
            return False
        self.files[self._resolve(path)] = self._maybe_corrupt(path, data)
        return True

    def run(self, argv: Sequence[str], *, stdin: bytes | None = None,
            timeout: float = 60.0) -> CommandResult:
        argv = list(argv)
        self._record("run", tuple(argv))
        self._check_faults("run", " ".join(argv))
        if argv[:3] == ["python3", "-c", scripts.COMPILE_PYTHON]:
            return self._compile(argv[3:])
        if argv[:3] == ["python3", "-c", scripts.SQL_ROW]:
            return self._sql_row(stdin or b"")
        if argv[:3] == ["mkdir", "-p", "--"]:
            for path in argv[3:]:
                self.mkdir(path)
            return CommandResult(0)
        if argv[:3] == ["chmod", "0755", "--"]:
            for path in argv[3:]:
                if self._resolve(path) not in self.files:
                    return CommandResult(1, stderr=f"chmod: {path}: No such file".encode())
                self.modes[self._resolve(path)] = 0o755
            return CommandResult(0)
        if argv[:2] == ["test", "-x"] and len(argv) == 3:
            return CommandResult(0 if self.modes.get(self._resolve(argv[2]), 0) & 0o111 else 1)
        if argv == ["kill", "-HUP", "1"]:
            self.reload()
            return CommandResult(0)
        handler = self.commands.get(argv[0]) if argv else None
        if handler is not None:
            return handler(self, argv, stdin or b"")
        raise ExecutorError(f"{self.name}: command not found in the container: {argv[:1]}")

    def http_get(self, port: int, path: str, *, timeout: float = 5.0) -> HttpResponse:
        self._record("http_get", port, path)
        self._check_faults("http_get", path)
        return self.health(self)

    def free_bytes(self, path: str) -> int:
        self._record("free_bytes", path)
        self._check_faults("free_bytes", path)
        return self.free

    # -- command emulation -------------------------------------------------------------

    def _compile(self, paths: list[str]) -> CommandResult:
        for path in paths:
            data = self.files.get(self._resolve(path))
            if data is None:
                return CommandResult(1, stderr=f"FileNotFoundError: {path}".encode())
            try:
                compile(data, path, "exec", dont_inherit=True)
            except SyntaxError as exc:
                return CommandResult(1, stderr=f"SyntaxError: {exc}".encode())
        return CommandResult(0)

    def _sql_row(self, stdin: bytes) -> CommandResult:
        payload = json.loads(stdin)
        real = self._resolve(payload["db"])
        if real not in self.files:
            return CommandResult(3)
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "db.sqlite"
            db.write_bytes(self.files[real])
            payload["db"] = str(db)
            proc = subprocess.run([sys.executable, "-c", scripts.SQL_ROW],
                                  input=json.dumps(payload).encode(), capture_output=True,
                                  timeout=60, check=False)
            if proc.returncode == 0 and payload.get("op") != "read":
                self.files[real] = db.read_bytes()
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)
