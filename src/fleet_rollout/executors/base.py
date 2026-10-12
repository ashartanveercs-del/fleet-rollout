"""The executor interface: everything the engine ever asks of a target.

It is deliberately small and file-oriented. The transaction logic is written once
against these primitives; adapters (local Docker, Docker over SSH, the in-memory
fake) only have to implement them faithfully. Paths are absolute container paths that
the engine has already validated and jailed.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


class ExecutorError(RuntimeError):
    """The target could not be reached or the primitive could not complete.

    Raised for transport failures too, so "unreachable" can never be mistaken for a
    legitimate answer such as "file absent"."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def summary(self, limit: int = 300) -> str:
        text = (self.stderr or self.stdout).decode("utf-8", "replace").strip()
        return text[-limit:] if text else f"exit status {self.returncode}"


@dataclass(frozen=True)
class HttpResponse:
    status: int          # 0 when no HTTP response arrived at all
    body: bytes = b""
    error: str = ""


@dataclass(frozen=True)
class PathInfo:
    exists: bool         # follows symlinks (a dangling link does not exist)
    is_file: bool
    is_dir: bool
    is_symlink: bool     # the path itself is a symlink (lstat)
    realpath: str        # fully resolved path, "" if it cannot be resolved


@runtime_checkable
class Executor(Protocol):
    name: str

    def read(self, path: str) -> bytes | None:
        """File bytes, or None if nothing exists at `path`."""

    def write(self, path: str, data: bytes) -> None:
        """Create or truncate `path` with `data`. The parent directory must exist."""

    def rename(self, src: str, dst: str) -> None:
        """Atomically replace `dst` with `src` (same filesystem)."""

    def remove(self, path: str) -> None:
        """Remove a file; succeed if it is already gone."""

    def inspect(self, path: str) -> PathInfo: ...

    def create_exclusive(self, path: str, data: bytes) -> bool:
        """Atomically create `path` (and its parent dir); False if it already exists."""

    def run(self, argv: Sequence[str], *, stdin: bytes | None = None,
            timeout: float = 60.0) -> CommandResult: ...

    def http_get(self, port: int, path: str, *, timeout: float = 5.0) -> HttpResponse:
        """GET http://127.0.0.1:<port><path> from inside the target."""

    def free_bytes(self, path: str) -> int: ...
