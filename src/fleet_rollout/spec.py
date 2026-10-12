"""Patch specs: a YAML file that declares a change once, validated as hostile input.

A spec is a short list of steps over files inside an agent's workspace:

* `write_file`   - replace a file with a file from the patch bundle
* `append_block` - append a block once, identified by a marker line
* `sql_upsert`   - upsert one row in a SQLite table, with bound parameters
* `run`          - run a command from the allowlist in `commands.py`

Every field passes an allowlist validator at load time, so a bad spec fails before a
plan exists, long before anything touches a target. The spec's `digest` covers the
validated steps *and* the bytes of every bundled file; approvals are bound to it.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .commands import ResolvedCommand, resolve_command
from .validation import (
    ValidationError,
    check_keys,
    patch_id,
    relative_path,
    sha256_hex,
    single_line,
    sql_identifier,
)
from .yamlsafe import load_strict

MAX_SPEC_BYTES = 64 * 1024
MAX_SOURCE_BYTES = 1024 * 1024
MAX_STEPS = 50
MAX_SQL_COLUMNS = 32
MAX_SQL_TEXT = 64 * 1024
MIN_MARKER = 8
_COMPILE_SUFFIXES = (".py",)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class WriteFile:
    index: int
    source: str
    dest: str
    content: bytes
    expect_sha256: str | None = None
    kind: str = "write_file"

    @property
    def content_sha256(self) -> str:
        return sha256(self.content)

    @property
    def needs_compile(self) -> bool:
        # Key on either end: shipping Python to a suffix-less destination that the agent
        # still executes must not skip the only syntax check there is.
        return self.dest.endswith(_COMPILE_SUFFIXES) or self.source.endswith(_COMPILE_SUFFIXES)

    @property
    def label(self) -> str:
        return f"write_file {self.dest}"


@dataclass(frozen=True)
class AppendBlock:
    index: int
    source: str
    dest: str
    marker: str
    block: bytes
    expect_sha256: str | None = None
    kind: str = "append_block"

    @property
    def needs_compile(self) -> bool:
        return self.dest.endswith(_COMPILE_SUFFIXES)

    @property
    def label(self) -> str:
        return f"append_block {self.dest}"

    def appended_to(self, current: bytes) -> bytes:
        """The full new file: current content, a newline if needed, marker, block."""
        sep = b"" if not current or current.endswith(b"\n") else b"\n"
        block = self.block if self.block.endswith(b"\n") else self.block + b"\n"
        return current + sep + self.marker.encode("utf-8") + b"\n" + block


@dataclass(frozen=True)
class SqlUpsert:
    index: int
    db: str
    table: str
    key_column: str
    key: str | int
    values: tuple[tuple[str, str | int | float], ...]
    kind: str = "sql_upsert"

    @property
    def dest(self) -> str:
        return self.db

    @property
    def label(self) -> str:
        return f"sql_upsert {self.db} {self.table}[{self.key_column}={self.key!r}]"

    def payload(self, db_path: str) -> dict[str, Any]:
        return {"db": db_path, "table": self.table, "key_column": self.key_column,
                "key": self.key, "values": dict(self.values)}


@dataclass(frozen=True)
class RunCommand:
    index: int
    command: ResolvedCommand
    kind: str = "run"

    @property
    def label(self) -> str:
        args = " ".join(self.command.args)
        return f"run {self.command.name}" + (f" {args}" if args else "")


Step = WriteFile | AppendBlock | SqlUpsert | RunCommand


@dataclass(frozen=True)
class VerifyContains:
    file: str
    text: str


@dataclass(frozen=True)
class Patch:
    id: str
    description: str
    steps: tuple[Step, ...]
    verify: tuple[VerifyContains, ...]
    digest: str
    source: str

    def written_paths(self) -> list[str]:
        """Workspace-relative files the patch mutates, in step order."""
        return [s.dest for s in self.steps if not isinstance(s, RunCommand)]

    @property
    def short_digest(self) -> str:
        return self.digest[:12]


# -- loading ----------------------------------------------------------------------------


def load_patch(path: str | Path) -> Patch:
    """Load and validate `<id>.yaml`. Bundle files are resolved next to the spec."""
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValidationError(f"{path.name}: cannot read patch spec: {exc}") from exc
    if len(raw) > MAX_SPEC_BYTES:
        raise ValidationError(f"{path.name}: spec is larger than {MAX_SPEC_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"{path.name}: spec is not UTF-8") from exc
    data = load_strict(text, source=path.name, max_bytes=MAX_SPEC_BYTES)
    patch = parse_patch(data, bundle_dir=path.parent, source=path.name)
    if patch.id != path.stem:
        raise ValidationError(
            f"{path.name}: patch id {patch.id!r} does not match its file name "
            f"{path.stem!r}; ledger entries and markers are keyed by the id")
    return patch


def parse_patch(data: Any, *, bundle_dir: str | Path, source: str) -> Patch:
    bundle = Path(bundle_dir)
    check_keys(data, required=("id", "description", "steps"), optional=("verify",),
               where=source)
    pid = patch_id(data["id"], where=f"{source}:id")
    description = single_line(data["description"], where=f"{source}:description", max_len=300)

    raw_steps = data["steps"]
    if not isinstance(raw_steps, list) or not raw_steps:
        raise ValidationError(f"{source}:steps: expected a non-empty list of steps")
    if len(raw_steps) > MAX_STEPS:
        raise ValidationError(f"{source}:steps: at most {MAX_STEPS} steps per patch")

    steps: list[Step] = []
    written: dict[str, int] = {}
    for i, raw in enumerate(raw_steps):
        where = f"{source}:steps[{i}]"
        step = _parse_step(raw, i, where, bundle)
        dest = getattr(step, "dest", None)
        if dest is not None:
            if dest in written:
                raise ValidationError(
                    f"{where}: {dest} is already written by steps[{written[dest]}]; one file "
                    "per step keeps every backup an exact pre-state")
            written[dest] = i
        steps.append(step)

    verify = _parse_verify(data.get("verify"), source)
    digest = _digest(pid, description, steps, verify)
    return Patch(id=pid, description=description, steps=tuple(steps), verify=verify,
                 digest=digest, source=source)


def _parse_step(raw: Any, i: int, where: str, bundle: Path) -> Step:
    if not isinstance(raw, dict):
        raise ValidationError(f"{where}: expected a mapping, got {type(raw).__name__}")
    kind = raw.get("kind")
    parser = _STEP_PARSERS.get(kind) if isinstance(kind, str) else None
    if parser is None:
        raise ValidationError(f"{where}.kind: unknown step kind {kind!r} "
                              f"(allowed: {', '.join(_STEP_PARSERS)})")
    fields = {k: v for k, v in raw.items() if k != "kind"}
    return parser(fields, i, where, bundle)


def _read_source(rel: Any, where: str, bundle: Path) -> tuple[str, bytes]:
    rel = relative_path(rel, where=where)
    base = bundle.resolve()
    candidate = bundle / rel
    resolved = candidate.resolve()
    if not resolved.is_relative_to(base):
        raise ValidationError(f"{where}: {rel!r} resolves outside the patch bundle "
                              "(a symlinked file or directory)")
    if not resolved.is_file():
        raise ValidationError(f"{where}: {rel!r} does not exist in the patch bundle")
    size = resolved.stat().st_size
    if size > MAX_SOURCE_BYTES:
        raise ValidationError(f"{where}: {rel!r} is larger than {MAX_SOURCE_BYTES} bytes")
    return rel, resolved.read_bytes()


def _optional_sha(fields: dict, where: str) -> str | None:
    value = fields.get("expect_sha256")
    return None if value is None else sha256_hex(value, where=f"{where}.expect_sha256")


def _parse_write_file(fields: dict, i: int, where: str, bundle: Path) -> WriteFile:
    check_keys(fields, required=("source", "dest"), optional=("expect_sha256",), where=where)
    src, content = _read_source(fields["source"], f"{where}.source", bundle)
    dest = relative_path(fields["dest"], where=f"{where}.dest")
    return WriteFile(index=i, source=src, dest=dest, content=content,
                     expect_sha256=_optional_sha(fields, where))


def _parse_append_block(fields: dict, i: int, where: str, bundle: Path) -> AppendBlock:
    check_keys(fields, required=("source", "dest", "marker"), optional=("expect_sha256",),
               where=where)
    src, block = _read_source(fields["source"], f"{where}.source", bundle)
    dest = relative_path(fields["dest"], where=f"{where}.dest")
    marker = single_line(fields["marker"], where=f"{where}.marker", max_len=200)
    if len(marker.strip()) < MIN_MARKER:
        raise ValidationError(f"{where}.marker: must be at least {MIN_MARKER} characters so "
                              "it cannot match ordinary text")
    try:
        block.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"{where}.source: an appended block must be UTF-8 text") from exc
    if marker.encode("utf-8") in block:
        raise ValidationError(f"{where}.source: the block already contains its marker, so "
                              "the 'exactly one marker' read-back could never pass")
    return AppendBlock(index=i, source=src, dest=dest, marker=marker, block=block,
                       expect_sha256=_optional_sha(fields, where))


def _sql_scalar(value: Any, where: str) -> str | int | float:
    if isinstance(value, bool):
        raise ValidationError(f"{where}: YAML read this as a boolean ({value!r}); "
                              "quote it if you meant the text")
    if isinstance(value, str):
        if "\x00" in value:
            raise ValidationError(f"{where}: NUL characters are not allowed")
        if len(value) > MAX_SQL_TEXT:
            raise ValidationError(f"{where}: text is longer than {MAX_SQL_TEXT} characters")
        return value
    if isinstance(value, int | float):
        return value
    raise ValidationError(f"{where}: expected a string or a number, got {type(value).__name__}")


def _parse_sql_upsert(fields: dict, i: int, where: str, bundle: Path) -> SqlUpsert:
    check_keys(fields, required=("db", "table", "key_column", "key", "values"), optional=(),
               where=where)
    db = relative_path(fields["db"], where=f"{where}.db")
    table = sql_identifier(fields["table"], where=f"{where}.table")
    key_column = sql_identifier(fields["key_column"], where=f"{where}.key_column")
    key = _sql_scalar(fields["key"], f"{where}.key")
    if isinstance(key, float):
        raise ValidationError(f"{where}.key: a float is not a reliable row key")
    raw_values = fields["values"]
    if not isinstance(raw_values, dict) or not raw_values:
        raise ValidationError(f"{where}.values: expected a non-empty column -> value mapping")
    if len(raw_values) > MAX_SQL_COLUMNS:
        raise ValidationError(f"{where}.values: at most {MAX_SQL_COLUMNS} columns")
    values: list[tuple[str, str | int | float]] = []
    for column, value in raw_values.items():
        col = sql_identifier(column, where=f"{where}.values")
        if col == key_column:
            raise ValidationError(f"{where}.values: must not restate the key column "
                                  f"{key_column!r}; it comes from `key`")
        values.append((col, _sql_scalar(value, f"{where}.values.{col}")))
    return SqlUpsert(index=i, db=db, table=table, key_column=key_column, key=key,
                     values=tuple(values))


def _parse_run(fields: dict, i: int, where: str, bundle: Path) -> RunCommand:
    check_keys(fields, required=("command",), optional=("args",), where=where)
    return RunCommand(index=i, command=resolve_command(fields["command"], fields.get("args"),
                                                       where=f"{where}.command"))


_STEP_PARSERS = {
    "write_file": _parse_write_file,
    "append_block": _parse_append_block,
    "sql_upsert": _parse_sql_upsert,
    "run": _parse_run,
}


def _parse_verify(raw: Any, source: str) -> tuple[VerifyContains, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ValidationError(f"{source}:verify: expected a list")
    out = []
    for i, entry in enumerate(raw):
        where = f"{source}:verify[{i}]"
        check_keys(entry, required=("file", "contains"), optional=(), where=where)
        out.append(VerifyContains(
            file=relative_path(entry["file"], where=f"{where}.file"),
            text=single_line(entry["contains"], where=f"{where}.contains")))
    return tuple(out)


def _digest(pid: str, description: str, steps: list[Step],
            verify: tuple[VerifyContains, ...]) -> str:
    def describe(step: Step) -> dict[str, Any]:
        if isinstance(step, WriteFile):
            return {"kind": step.kind, "source": step.source, "dest": step.dest,
                    "sha256": step.content_sha256, "expect_sha256": step.expect_sha256}
        if isinstance(step, AppendBlock):
            return {"kind": step.kind, "source": step.source, "dest": step.dest,
                    "marker": step.marker, "sha256": sha256(step.block),
                    "expect_sha256": step.expect_sha256}
        if isinstance(step, SqlUpsert):
            return {"kind": step.kind, "db": step.db, "table": step.table,
                    "key_column": step.key_column, "key": step.key,
                    "values": [list(v) for v in step.values]}
        return {"kind": step.kind, "command": step.command.name,
                "args": list(step.command.args)}

    doc = {"id": pid, "description": description, "steps": [describe(s) for s in steps],
           "verify": [[v.file, v.text] for v in verify]}
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(canonical.encode("ascii"))
