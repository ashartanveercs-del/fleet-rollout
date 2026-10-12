"""Validators for every field that comes from a patch spec, a fleet file or a ticket.

Each validator is an allowlist, not a filter: it accepts a narrow, boring shape and
rejects everything else with a message that names the offending field. Nothing here
tries to "clean up" a bad value, because a value that needed cleaning was written by
someone who did not mean what it says.
"""

from __future__ import annotations

import posixpath
import re
import unicodedata
from collections.abc import Iterable, Mapping
from typing import Any

# The directory under each agent's workspace where the engine keeps its own lock and
# applied markers. Patch steps may never write there.
RESERVED_DIR = ".fleet-rollout"

_PATH_CHARS = re.compile(r"[A-Za-z0-9._+/-]+")
_MAX_PATH = 1024
_MAX_COMPONENT = 255
_SQL_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")
_PATCH_ID = re.compile(r"[a-z0-9][a-z0-9._-]{2,63}")
_TARGET_NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_PERSON = re.compile(r"[a-z][a-z0-9._-]{0,31}")
_SHA256 = re.compile(r"[0-9a-f]{64}")

# Characters that change how text is *displayed* without being visible: bidirectional
# overrides/isolates ("Trojan Source") and zero-width joiners. A reviewer must see
# exactly the text that will be written.
_INVISIBLE = frozenset(
    "؜​‌‍‎‏‪‫‬‭‮"
    "⁦⁧⁨⁩﻿")


class ValidationError(ValueError):
    """Input was rejected. The message always starts with the field location."""


def _fail(where: str, message: str) -> ValidationError:
    return ValidationError(f"{where}: {message}")


def relative_path(value: Any, *, where: str) -> str:
    """A path relative to an agent's workspace root (or to a patch bundle).

    Accepts only `[A-Za-z0-9._+-/]`, already-normalized, no `..`, no component that
    starts with `-` (so a path can never be read as a command-line option), and nothing
    under the engine's reserved directory. An absolute path cannot be expressed at all,
    so "inside the workspace" holds by construction once it is joined to the root.
    """
    if not isinstance(value, str):
        raise _fail(where, f"expected a non-empty path string, got {type(value).__name__}")
    if not value:
        raise _fail(where, "expected a non-empty path string")
    if value == ".":
        raise _fail(where, "'.' is the workspace root itself; name a file under it")
    if value.startswith("/"):
        raise _fail(where, f"{value!r} must be relative to the workspace root")
    if not _PATH_CHARS.fullmatch(value):
        raise _fail(where, f"{value!r} contains characters outside [A-Za-z0-9._+-/] "
                           "(whitespace, quotes, shell metacharacters, non-ASCII)")
    if len(value) > _MAX_PATH:
        raise _fail(where, f"path is too long ({len(value)} > {_MAX_PATH})")
    parts = value.split("/")
    if any(len(part) > _MAX_COMPONENT for part in parts):
        raise _fail(where, f"a path component is too long (> {_MAX_COMPONENT})")
    if posixpath.normpath(value) != value:
        raise _fail(where, f"{value!r} is not normalized (it contains '.', '..', '//' "
                           "or a trailing '/')")
    if ".." in parts:
        raise _fail(where, f"{value!r} climbs out with '..'")
    if any(part.startswith("-") for part in parts):
        raise _fail(where, f"{value!r} has a component that would start with '-'")
    if parts[0] == RESERVED_DIR:
        raise _fail(where, f"{value!r} is under {RESERVED_DIR}/, which is reserved for "
                           "the rollout engine's own lock and markers")
    return value


def join_root(root: str, rel: str) -> str:
    """Join a validated workspace root and a validated relative path."""
    return f"{root}/{rel}"


def workspace_root(value: Any, *, where: str) -> str:
    """An agent's workspace root: absolute, normalized, never `/` itself."""
    if not isinstance(value, str) or not value:
        raise _fail(where, "expected an absolute directory path")
    if not value.startswith("/") or value.startswith("//"):
        raise _fail(where, f"{value!r} must be an absolute path starting with a single '/'")
    if value == "/":
        raise _fail(where, "'/' cannot be a workspace root: the jail would be the whole disk")
    if not _PATH_CHARS.fullmatch(value):
        raise _fail(where, f"{value!r} contains characters outside [A-Za-z0-9._+-/]")
    if posixpath.normpath(value) != value:
        raise _fail(where, f"{value!r} is not normalized")
    return value


def sql_identifier(value: Any, *, where: str) -> str:
    """A table or column name. Identifiers cannot be bound as SQL parameters, so they
    are allowlisted here and double-quoted again when the statement is built."""
    if not isinstance(value, str) or not _SQL_IDENT.fullmatch(value):
        raise _fail(where, f"{value!r} is not a plain SQL identifier "
                           "([A-Za-z_][A-Za-z0-9_]*, at most 63 characters)")
    if value.lower().startswith("sqlite_"):
        raise _fail(where, f"{value!r} is a reserved SQLite internal name")
    return value


def single_line(value: Any, *, where: str, max_len: int = 200) -> str:
    """Free text that is shown to reviewers or matched literally (markers, notes)."""
    if not isinstance(value, str) or not value:
        raise _fail(where, "expected a non-empty string")
    if len(value) > max_len:
        raise _fail(where, f"text is too long ({len(value)} > {max_len})")
    for ch in value:
        if ch in _INVISIBLE:
            raise _fail(where, f"contains a bidirectional or invisible formatting "
                               f"character U+{ord(ch):04X}")
        if unicodedata.category(ch) == "Cc":
            raise _fail(where, f"contains a control character U+{ord(ch):04X} "
                               "(newlines, tabs and escapes are not allowed)")
    return value


def patch_id(value: Any, *, where: str) -> str:
    """Patch ids become file names (markers, manifests), so they are tightly shaped."""
    if not isinstance(value, str) or not _PATCH_ID.fullmatch(value) or ".." in value:
        raise _fail(where, f"{value!r} is not a valid patch id "
                           "(lowercase [a-z0-9._-], 3-64 characters, no '..')")
    return value


def target_name(value: Any, *, where: str) -> str:
    """A fleet target name: a lowercase DNS label."""
    if not isinstance(value, str) or not _TARGET_NAME.fullmatch(value):
        raise _fail(where, f"{value!r} is not a valid target name "
                           "(lowercase letters, digits and '-', 1-63 characters)")
    return value


def person_name(value: Any, *, where: str) -> str:
    """An operator or approver id. Lowercase only, so 'Alice' and 'alice' can never
    count as two different approvers."""
    if not isinstance(value, str) or not _PERSON.fullmatch(value):
        raise _fail(where, f"{value!r} is not a valid person id "
                           "(lowercase, starts with a letter, [a-z0-9._-], at most 32)")
    return value


def sha256_hex(value: Any, *, where: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise _fail(where, f"{value!r} is not a lowercase sha256 hex digest")
    return value


def check_keys(mapping: Any, *, required: Iterable[str], optional: Iterable[str],
               where: str) -> Mapping[str, Any]:
    """Reject unknown keys (typos and smuggled fields alike) and missing required ones."""
    if not isinstance(mapping, Mapping):
        raise _fail(where, f"expected a mapping, got {type(mapping).__name__}")
    required = tuple(required)
    allowed = set(required) | set(optional)
    unknown = sorted(k for k in mapping if k not in allowed)
    if unknown:
        raise _fail(where, f"unknown key(s) {', '.join(repr(k) for k in unknown)} "
                           f"(allowed: {', '.join(sorted(allowed))})")
    missing = [k for k in required if k not in mapping]
    if missing:
        raise _fail(where, f"missing required key(s) {', '.join(repr(k) for k in missing)}")
    return mapping
