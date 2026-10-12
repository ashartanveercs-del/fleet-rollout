"""A strict YAML loader for files we treat as hostile input.

`yaml.safe_load` already refuses to construct Python objects, but it still has three
behaviours that matter when the file decides what gets written to production:

* **Duplicate keys win silently.** `{dest: a, dest: b}` loads as `{dest: b}`. A human
  reviewing the diff reads the first value; the loader acts on the last one.
* **Anchors and aliases** let a small file describe an enormous (or deeply shared)
  structure, which turns every recursive walk over it into a denial-of-service.
* **Merge keys (`<<`)** splice one mapping into another, so the keys a step really
  has are not the keys written under it.

This loader rejects all three, requires string keys, accepts exactly one document,
and caps the input size before the parser sees a byte.
"""

from __future__ import annotations

from typing import Any

import yaml

from .validation import ValidationError

DEFAULT_MAX_BYTES = 256 * 1024
_MERGE_TAG = "tag:yaml.org,2002:merge"


class StrictYAMLError(ValidationError):
    """The document is not acceptable input (syntax, size or a forbidden construct)."""


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses aliases, anchors, merge keys and duplicate keys."""

    def compose_node(self, parent, index):  # type: ignore[override]
        event = self.peek_event()
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None) is not None:
            raise StrictYAMLError(
                f"line {event.start_mark.line + 1}: YAML anchors and aliases are not allowed")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):  # type: ignore[override]
        if not isinstance(node, yaml.MappingNode):
            return super().construct_mapping(node, deep=deep)
        seen: set[str] = set()
        for key_node, _value_node in node.value:
            if key_node.tag == _MERGE_TAG:
                raise StrictYAMLError(
                    f"line {key_node.start_mark.line + 1}: YAML merge keys (<<) are not allowed")
            key = self.construct_object(key_node, deep=True)
            if not isinstance(key, str):
                raise StrictYAMLError(
                    f"line {key_node.start_mark.line + 1}: mapping keys must be strings, "
                    f"got {type(key).__name__} {key!r}")
            if key in seen:
                raise StrictYAMLError(
                    f"line {key_node.start_mark.line + 1}: duplicate key {key!r}")
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def load_strict(text: str, *, source: str, max_bytes: int = DEFAULT_MAX_BYTES) -> Any:
    """Parse one YAML document from `text` with the restrictions described above."""
    size = len(text.encode("utf-8"))
    if size > max_bytes:
        raise StrictYAMLError(f"{source}: document is {size} bytes, larger than {max_bytes}")
    loader = _StrictLoader(text)
    try:
        try:
            data = loader.get_single_data()
        except yaml.composer.ComposerError as exc:
            if "expected a single document" in str(exc):
                raise StrictYAMLError(
                    f"{source}: expected a single YAML document") from exc
            raise
    except StrictYAMLError as exc:
        if str(exc).startswith(source):
            raise
        raise StrictYAMLError(f"{source}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise StrictYAMLError(f"{source}: invalid YAML: {exc}") from exc
    finally:
        loader.dispose()
    return data
