"""Executor adapters for containers: local `docker exec`, or `docker exec` over SSH.

Every primitive is one argv. Paths never appear inside a shell script: the scripts are
constants that refer to `"$1"`/`"$2"`, and paths are appended as positional arguments.
Locally there is no shell at all (`subprocess.run` with a list). Over SSH the remote
side does run a shell, so the whole `docker exec ...` argv is joined with `shlex.join`,
which quotes every element for POSIX `sh`.
"""

from __future__ import annotations

import shlex
import subprocess
from collections.abc import Callable, Sequence
from typing import Any

from .. import scripts
from .base import CommandResult, ExecutorError, HttpResponse, PathInfo

Runner = Callable[..., Any]

_READ = ('if [ -f "$1" ]; then exec cat -- "$1"; '
         'elif [ -e "$1" ] || [ -L "$1" ]; then exit 4; else exit 3; fi')
_WRITE = 'exec cat > "$1"'
# `mv` onto a directory would move the file *into* it; refuse that explicitly.
_RENAME = 'if [ -d "$2" ]; then exit 5; fi; exec mv -f -- "$1" "$2"'
_INSPECT = ('p="$1"; e=0; f=0; d=0; l=0; '
            '[ -e "$p" ] && e=1; [ -f "$p" ] && f=1; [ -d "$p" ] && d=1; [ -L "$p" ] && l=1; '
            'r=$(readlink -f -- "$p" 2>/dev/null) || r=""; '
            'printf "%s %s %s %s\\n%s" "$e" "$f" "$d" "$l" "$r"')
# noclobber (`set -C`) makes `>` an O_EXCL create: atomic even with concurrent callers.
_CREATE_EXCLUSIVE = ('mkdir -p -- "$(dirname -- "$1")" || exit 1; set -C; '
                     'if cat > "$1"; then exit 0; elif [ -e "$1" ]; then exit 3; '
                     'else exit 1; fi')


class DockerTransport:
    """Run argv inside a container on this machine via the docker CLI."""

    error_codes = {125: "docker could not exec in the container",
                   126: "docker could not invoke the command",
                   127: "command not found in the container"}

    def __init__(self, container: str) -> None:
        self.container = container

    def wrap(self, argv: Sequence[str]) -> list[str]:
        return ["docker", "exec", "-i", self.container, *argv]


class SSHTransport:
    """Run argv inside a container on a remote host: ssh, then docker exec."""

    error_codes = {255: "ssh connection failed",
                   **DockerTransport.error_codes}

    def __init__(self, host: str, container: str, *, connect_timeout: int = 10) -> None:
        self.host = host
        self.container = container
        self.connect_timeout = connect_timeout

    def wrap(self, argv: Sequence[str]) -> list[str]:
        remote = shlex.join(["docker", "exec", "-i", self.container, *argv])
        return ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={self.connect_timeout}",
                "--", self.host, remote]


class ContainerExecutor:
    def __init__(self, transport: DockerTransport | SSHTransport, *,
                 runner: Runner = subprocess.run, name: str = "",
                 default_timeout: float = 60.0) -> None:
        self.transport = transport
        self.runner = runner
        self.name = name or getattr(transport, "container", "target")
        self.default_timeout = default_timeout

    # -- plumbing -------------------------------------------------------------------

    def _call(self, argv: Sequence[str], *, stdin: bytes | None = None,
              timeout: float | None = None) -> CommandResult:
        full = self.transport.wrap(argv)
        try:
            proc = self.runner(full, input=stdin if stdin is not None else b"",
                               capture_output=True, timeout=timeout or self.default_timeout,
                               check=False)
        except FileNotFoundError as exc:
            raise ExecutorError(f"{self.name}: {full[0]} CLI not found on this machine") from exc
        except subprocess.TimeoutExpired as exc:
            raise ExecutorError(f"{self.name}: {full[0]} timed out after {exc.timeout}s") from exc
        result = CommandResult(proc.returncode, proc.stdout or b"", proc.stderr or b"")
        transport_error = self.transport.error_codes.get(result.returncode)
        if transport_error:
            raise ExecutorError(f"{self.name}: {transport_error}: {result.summary()}")
        return result

    def _sh(self, script: str, *args: str, stdin: bytes | None = None) -> CommandResult:
        return self._call(["sh", "-c", script, "sh", *args], stdin=stdin)

    def _fail(self, what: str, result: CommandResult) -> ExecutorError:
        return ExecutorError(f"{self.name}: {what}: {result.summary()}")

    # -- primitives -------------------------------------------------------------------

    def read(self, path: str) -> bytes | None:
        result = self._sh(_READ, path)
        if result.returncode == 0:
            return result.stdout
        if result.returncode == 3:
            return None
        if result.returncode == 4:
            raise ExecutorError(f"{self.name}: {path} exists but is not a regular file")
        raise self._fail(f"read {path}", result)

    def write(self, path: str, data: bytes) -> None:
        result = self._sh(_WRITE, path, stdin=data)
        if not result.ok:
            raise self._fail(f"write {path}", result)

    def rename(self, src: str, dst: str) -> None:
        result = self._sh(_RENAME, src, dst)
        if result.returncode == 5:
            raise ExecutorError(f"{self.name}: refusing to rename onto {dst}: it is a directory")
        if not result.ok:
            raise self._fail(f"rename {src} -> {dst}", result)

    def remove(self, path: str) -> None:
        result = self._call(["rm", "-f", "--", path])
        if not result.ok:
            raise self._fail(f"remove {path}", result)

    def inspect(self, path: str) -> PathInfo:
        result = self._sh(_INSPECT, path)
        if not result.ok:
            raise self._fail(f"inspect {path}", result)
        head, _, real = result.stdout.decode("utf-8", "replace").partition("\n")
        try:
            e, f, d, link = (flag == "1" for flag in head.split())
        except ValueError as exc:
            raise ExecutorError(f"{self.name}: unexpected inspect output {head!r}") from exc
        return PathInfo(exists=e, is_file=f, is_dir=d, is_symlink=link, realpath=real.strip())

    def create_exclusive(self, path: str, data: bytes) -> bool:
        result = self._sh(_CREATE_EXCLUSIVE, path, stdin=data)
        if result.returncode == 0:
            return True
        if result.returncode == 3:
            return False
        raise self._fail(f"create {path}", result)

    def run(self, argv: Sequence[str], *, stdin: bytes | None = None,
            timeout: float = 60.0) -> CommandResult:
        return self._call(list(argv), stdin=stdin, timeout=timeout)

    def http_get(self, port: int, path: str, *, timeout: float = 5.0) -> HttpResponse:
        url = f"http://127.0.0.1:{int(port)}{path}"
        result = self._call(["python3", "-c", scripts.HTTP_PROBE, url, f"{timeout:g}"],
                            timeout=timeout + 10)
        if not result.ok:
            return HttpResponse(status=0, error=result.summary())
        status, _, body = result.stdout.partition(b"\n")
        try:
            return HttpResponse(status=int(status), body=body)
        except ValueError:
            return HttpResponse(status=0, error=f"unexpected probe output {status[:40]!r}")

    def free_bytes(self, path: str) -> int:
        result = self._call(["df", "-Pk", "--", path])
        if not result.ok:
            raise self._fail(f"df {path}", result)
        try:
            line = result.stdout.decode().strip().splitlines()[1]
            return int(line.split()[3]) * 1024
        except (IndexError, ValueError) as exc:
            raise ExecutorError(f"{self.name}: cannot parse df output") from exc


def make_executor(target: Any, *, runner: Runner = subprocess.run) -> ContainerExecutor:
    """The real adapter for a fleet target (`executor: docker` or `executor: ssh`)."""
    if target.executor == "docker":
        transport: DockerTransport | SSHTransport = DockerTransport(target.container)
    elif target.executor == "ssh":
        transport = SSHTransport(target.host, target.container)
    else:
        raise ExecutorError(f"{target.name}: unknown executor {target.executor!r}")
    return ContainerExecutor(transport, runner=runner, name=target.name)
