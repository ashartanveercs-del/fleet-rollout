"""The golden template: the fleet's intended workspace, one directory tree for all agents.

`golden/config/greeting.txt` describes `<root>/config/greeting.txt` on every target.
Per-target differences use `{{ fleet.* }}` placeholders (`fleet.target.name`,
`fleet.vars.region`, ...). Only the `fleet.` namespace is ours: AI agents often keep their
own `{{ ... }}` prompt templates, and those pass through untouched. An unknown `fleet.`
placeholder is an error, so a half-rendered file is never compared, let alone shipped.
"""

from __future__ import annotations

import re
from pathlib import Path

from .fleet import Target
from .validation import ValidationError, relative_path

MAX_GOLDEN_BYTES = 1024 * 1024
_PLACEHOLDER = re.compile(r"\{\{\s*fleet\.([A-Za-z_][A-Za-z0-9_.]*)\s*\}\}")


def _context(target: Target) -> dict[str, str]:
    ctx = {
        "target.name": target.name, "target.host": target.host,
        "target.container": target.container, "target.cohort": target.cohort,
        "target.owner": target.owner, "target.root": target.root,
    }
    ctx.update({f"vars.{k}": v for k, v in target.vars.items()})
    return ctx


def render(data: bytes, target: Target, *, where: str) -> bytes:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data  # binary files are compared byte for byte
    ctx = _context(target)

    def substitute(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in ctx:
            raise ValidationError(f"{where}: unknown placeholder {{{{ fleet.{key} }}}} for "
                                  f"target {target.name}")
        return ctx[key]

    return _PLACEHOLDER.sub(substitute, text).encode("utf-8")


def _is_link(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or bool(is_junction and is_junction())


def golden_files(golden_dir: Path) -> dict[str, bytes]:
    """Every file in the golden tree, keyed by validated workspace-relative path."""
    root = Path(golden_dir)
    if not root.is_dir():
        raise ValidationError(f"golden template directory {root} does not exist")
    out: dict[str, bytes] = {}
    pending = [root]
    while pending:
        directory = pending.pop()
        for entry in sorted(directory.iterdir()):
            rel = entry.relative_to(root).as_posix()
            if _is_link(entry):
                raise ValidationError(f"golden/{rel} is a link; the golden template must "
                                      "contain real files only")
            if entry.is_dir():
                pending.append(entry)
                continue
            relative_path(rel, where=f"golden/{rel}")
            if entry.stat().st_size > MAX_GOLDEN_BYTES:
                raise ValidationError(f"golden/{rel} is larger than {MAX_GOLDEN_BYTES} bytes")
            out[rel] = entry.read_bytes()
    return dict(sorted(out.items()))


def render_golden(golden_dir: Path, target: Target) -> dict[str, bytes]:
    return {rel: render(data, target, where=f"golden/{rel}")
            for rel, data in golden_files(golden_dir).items()}
