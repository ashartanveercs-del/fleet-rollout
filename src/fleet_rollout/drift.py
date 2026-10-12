"""Drift detection: compare each target's live files with the rendered golden template.

Read-only by construction: it only calls `Executor.read`. A target that cannot be read
is reported as `error` for every file, never as in sync. Text differences come back as a
unified diff; binary differences as a pair of checksums.
"""

from __future__ import annotations

import difflib
import hashlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from .executors.base import Executor, ExecutorError
from .fleet import Target
from .spec import AppendBlock, Patch, WriteFile
from .template import render_golden
from .validation import join_root

MAX_DIFF_LINES = 200


@dataclass(frozen=True)
class FileDrift:
    path: str
    state: str          # "in_sync" | "drifted" | "missing" | "error"
    diff: str = ""
    detail: str = ""


@dataclass(frozen=True)
class TargetDrift:
    target: str
    files: tuple[FileDrift, ...]

    @property
    def drifted(self) -> bool:
        return any(f.state != "in_sync" for f in self.files)


def unified(golden: bytes, live: bytes, rel: str, where: str) -> str:
    try:
        g, lv = golden.decode("utf-8"), live.decode("utf-8")
    except UnicodeDecodeError:
        return (f"binary content differs: golden sha256 "
                f"{hashlib.sha256(golden).hexdigest()[:12]}, live sha256 "
                f"{hashlib.sha256(live).hexdigest()[:12]}")
    lines = list(difflib.unified_diff(g.splitlines(keepends=True), lv.splitlines(keepends=True),
                                      fromfile=f"golden/{rel}", tofile=where))
    if len(lines) > MAX_DIFF_LINES:
        lines = lines[:MAX_DIFF_LINES] + [f"... ({len(lines) - MAX_DIFF_LINES} more lines)\n"]
    return "".join(line if line.endswith("\n") else line + "\n" for line in lines)


def check_drift(golden_dir: Path, targets: Iterable[Target],
                executor_for: Callable[[Target], Executor]) -> list[TargetDrift]:
    reports = []
    for target in targets:
        executor = executor_for(target)
        results = []
        for rel, expected in render_golden(golden_dir, target).items():
            path = join_root(target.root, rel)
            try:
                live = executor.read(path)
            except ExecutorError as exc:
                results.append(FileDrift(rel, "error", detail=str(exc)))
                continue
            if live is None:
                results.append(FileDrift(rel, "missing", detail=f"{path} does not exist"))
            elif live == expected:
                results.append(FileDrift(rel, "in_sync"))
            else:
                results.append(FileDrift(rel, "drifted",
                                         diff=unified(expected, live, rel,
                                                      f"{target.name}:{path}")))
        reports.append(TargetDrift(target.name, tuple(results)))
    return reports


def golden_lag(golden_dir: Path | None, patch: Patch, target: Target) -> list[str]:
    """Warn when a patch ships bytes the golden template does not contain: after the
    rollout, every patched target would show up as drifted."""
    if golden_dir is None:
        return []
    rendered = render_golden(golden_dir, target)
    warnings = []
    for step in patch.steps:
        if isinstance(step, WriteFile) and rendered.get(step.dest) != step.content:
            warnings.append(f"{step.dest}: golden/{step.dest} does not match the bytes this "
                            "patch ships; update the golden template in the same change")
        elif isinstance(step, AppendBlock) and (
                step.marker.encode() not in rendered.get(step.dest, b"")):
            warnings.append(f"{step.dest}: golden/{step.dest} lacks the marker "
                            f"{step.marker!r}; update the golden template in the same change")
    return warnings
