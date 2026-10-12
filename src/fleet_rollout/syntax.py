"""The syntax gate: a staged file must parse before it may replace the live one.

Structured formats are parsed here from the bytes *read back* from the staged copy,
which also proves the transport delivered them intact. Python is compiled on the
target itself, with the target's interpreter, because that is the interpreter that
will import it. Nothing is written by the check (no bytecode caches).
"""

from __future__ import annotations

import json
import tomllib

import yaml

from . import scripts
from .executors.base import Executor


def _decode(data: bytes, fmt: str) -> tuple[str | None, str | None]:
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, f"{fmt} file is not valid UTF-8"


def check_staged(executor: Executor, staged_path: str, dest: str, data: bytes, *,
                 needs_compile: bool) -> str | None:
    """Return a description of the syntax problem, or None if the file is acceptable."""
    if needs_compile:
        result = executor.run(["python3", "-c", scripts.COMPILE_PYTHON, staged_path])
        if not result.ok:
            return f"Python syntax check failed: {result.summary()}"
    suffix = dest.rsplit(".", 1)[-1].lower() if "." in dest.rsplit("/", 1)[-1] else ""
    if suffix == "json":
        text, problem = _decode(data, "JSON")
        if problem:
            return problem
        try:
            json.loads(text)
        except ValueError as exc:
            return f"JSON syntax error: {exc}"
    elif suffix in ("yaml", "yml"):
        text, problem = _decode(data, "YAML")
        if problem:
            return problem
        try:
            yaml.safe_load(text)
        except yaml.YAMLError as exc:
            return f"YAML syntax error: {str(exc).splitlines()[0]}"
    elif suffix == "toml":
        text, problem = _decode(data, "TOML")
        if problem:
            return problem
        try:
            tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            return f"TOML syntax error: {exc}"
    return None
