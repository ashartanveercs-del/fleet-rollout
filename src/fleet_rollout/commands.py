"""The command allowlist for `run` steps.

There is no free-text command field anywhere in the patch schema. A step names an entry
in this table; the argv prefix is ours, and the patch may only append arguments of the
declared kind (always validated workspace-relative paths, joined to the target's root
at execution time). Extending the table is a code change that goes through review, not
something a YAML file can do.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from . import scripts
from .validation import ValidationError, join_root, relative_path


@dataclass(frozen=True)
class AllowedCommand:
    name: str
    prefix: tuple[str, ...]
    takes_paths: bool
    min_args: int
    max_args: int
    purpose: str
    # How the engine reads the effect back: "is_dir", "is_executable", or None when
    # the exit status is the evidence (compile) or the health gate is (reload).
    verify: str | None = None
    # Re-run after a restore, so the agent picks up the restored files again.
    rerun_on_restore: bool = False


_COMMANDS = {
    "compile_python": AllowedCommand(
        "compile_python", ("python3", "-c", scripts.COMPILE_PYTHON), True, 1, 8,
        "prove Python files parse, without writing bytecode"),
    "make_dirs": AllowedCommand(
        "make_dirs", ("mkdir", "-p", "--"), True, 1, 8,
        "create directories a later step writes into", verify="is_dir"),
    "make_executable": AllowedCommand(
        "make_executable", ("chmod", "0755", "--"), True, 1, 8,
        "mark a shipped helper script executable", verify="is_executable"),
    "reload_agent": AllowedCommand(
        "reload_agent", ("kill", "-HUP", "1"), False, 0, 0,
        "send SIGHUP to the agent supervisor (PID 1) so it re-reads its config",
        rerun_on_restore=True),
}

ALLOWED_COMMANDS: Mapping[str, AllowedCommand] = MappingProxyType(_COMMANDS)


@dataclass(frozen=True)
class ResolvedCommand:
    spec: AllowedCommand
    args: tuple[str, ...]

    @property
    def name(self) -> str:
        return self.spec.name

    def argv(self, root: str) -> list[str]:
        return [*self.spec.prefix, *(join_root(root, a) for a in self.args)]


def resolve_command(name: Any, args: Any, *, where: str) -> ResolvedCommand:
    spec = ALLOWED_COMMANDS.get(name) if isinstance(name, str) else None
    if spec is None:
        raise ValidationError(
            f"{where}: {name!r} is not on the command allowlist "
            f"({', '.join(sorted(ALLOWED_COMMANDS))}); arbitrary commands cannot be expressed")
    if args is None:
        args = []
    if not isinstance(args, list):
        raise ValidationError(f"{where}.args: expected a list, got {type(args).__name__}")
    if not spec.min_args <= len(args) <= spec.max_args:
        raise ValidationError(
            f"{where}.args: {spec.name!r} takes {spec.min_args}..{spec.max_args} "
            f"argument(s), got {len(args)}")
    checked = tuple(relative_path(a, where=f"{where}.args[{i}]") for i, a in enumerate(args))
    return ResolvedCommand(spec=spec, args=checked)
