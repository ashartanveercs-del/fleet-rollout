"""Operator-side backups: a content-addressed object store plus a write-ahead manifest.

Before a step mutates a file on a target, the engine reads the file, stores its bytes
under `objects/<sha256>`, and appends `{step, path, sha_before}` to the manifest for
(run, target), with an fsync, *before* the mutation happens. That ordering turns the
manifest into an undo log: whatever state a crash leaves a target in, every file the
run touched has a recorded, checksummed pre-state to go back to.

Objects are verified on the way in and on the way out. A backup that no longer hashes
to its own name is refused rather than "restored".
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from .validation import ValidationError, target_name

_RUN_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")


class BackupCorrupt(RuntimeError):
    """A backup object or manifest cannot be trusted."""


def validate_run_id(value: str) -> str:
    if not isinstance(value, str) or not _RUN_ID.fullmatch(value):
        raise ValidationError(f"run id {value!r} is not [a-z0-9-], 1-64 characters")
    return value


def _fsync_write(path: Path, data: bytes, *, append: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab" if append else "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


@dataclass(frozen=True)
class BackupEntry:
    step: int
    path: str                 # absolute path on the target
    sha_before: str | None    # None: the file did not exist before the step


class Manifest:
    """Append-only JSONL undo log for one target in one run."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def record(self, entry: BackupEntry) -> None:
        line = json.dumps(asdict(entry), sort_keys=True, separators=(",", ":")) + "\n"
        _fsync_write(self.path, line.encode("utf-8"), append=True)

    def exists(self) -> bool:
        return self.path.is_file()

    def entries(self) -> list[BackupEntry]:
        if not self.path.is_file():
            return []
        raw = self.path.read_bytes()
        lines = raw.split(b"\n")
        torn_tail = not raw.endswith(b"\n")
        out = []
        for number, line in enumerate(lines, start=1):
            if not line:
                continue
            try:
                doc = json.loads(line)
                out.append(BackupEntry(step=int(doc["step"]), path=str(doc["path"]),
                                       sha_before=doc["sha_before"]))
            except (ValueError, KeyError, TypeError) as exc:
                if torn_tail and number == len(lines):
                    break  # a crash mid-append; the mutation it guarded never started
                raise BackupCorrupt(f"{self.path.name} line {number} is unreadable") from exc
        return out


class BackupStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def object_path(self, sha: str) -> Path:
        return self.root / "objects" / sha[:2] / sha

    def put(self, data: bytes) -> str:
        sha = hashlib.sha256(data).hexdigest()
        path = self.object_path(sha)
        if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == sha:
            return sha
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{sha}.{os.getpid()}.tmp")
        _fsync_write(tmp, data, append=False)
        os.replace(tmp, path)
        if hashlib.sha256(path.read_bytes()).hexdigest() != sha:
            raise BackupCorrupt(f"backup object {sha[:12]} did not read back intact")
        return sha

    def get(self, sha: str) -> bytes:
        path = self.object_path(sha)
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise BackupCorrupt(f"backup object {sha[:12]} is missing") from exc
        if hashlib.sha256(data).hexdigest() != sha:
            raise BackupCorrupt(f"backup object {sha[:12]} fails its checksum; refusing to "
                                "restore bytes that are not the recorded pre-state")
        return data

    def manifest(self, run_id: str, target: str) -> Manifest:
        validate_run_id(run_id)
        target_name(target, where="backup target")
        return Manifest(self.root / "manifests" / run_id / f"{target}.jsonl")
