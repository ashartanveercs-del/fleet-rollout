"""The fleet file: which agents exist, where they run, who owns them, how to tell they
are healthy.

Two choices here are deliberate safety decisions rather than conveniences:

* `owner` is mandatory on every target and cannot come from `defaults`. A target that
  silently inherited "internal" would skip the customer consent gate.
* A health check must assert something about the response *body*. A status code alone
  is not health: proxies, load balancers and half-started apps all answer 200.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .validation import (
    ValidationError,
    check_keys,
    single_line,
    target_name,
    workspace_root,
)
from .yamlsafe import load_strict

EXECUTORS = ("docker", "ssh")
OWNERS = ("internal", "customer")

_HOST = re.compile(r"(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                   r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")
_CONTAINER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}")
_HEALTH_PATH = re.compile(r"/[A-Za-z0-9._~/?=&%-]{0,199}")
_VAR_NAME = re.compile(r"[a-z_][a-z0-9_]{0,31}")

_TARGET_REQUIRED = ("name", "host", "owner")
_TARGET_OPTIONAL = ("container", "executor", "root", "cohort", "canary", "health", "vars",
                    "customer")
_DEFAULT_KEYS = ("executor", "root", "cohort", "health")
_HEALTH_KEYS = ("port", "path", "expect_status", "expect_json", "expect_body",
                "expect_contains", "retries", "interval_seconds", "timeout_seconds")


@dataclass(frozen=True)
class HealthCheck:
    port: int
    path: str
    expect_status: int = 200
    expect_json: Mapping[str, Any] | None = None
    expect_body: str | None = None
    expect_contains: str | None = None
    retries: int = 3
    interval_seconds: float = 2.0
    timeout_seconds: float = 5.0


@dataclass(frozen=True)
class Target:
    name: str
    host: str
    container: str
    executor: str
    root: str
    owner: str
    cohort: str
    health: HealthCheck
    canary: bool = False
    customer: str | None = None
    vars: Mapping[str, str] = field(default_factory=dict)

    @property
    def customer_owned(self) -> bool:
        return self.owner == "customer"

    def describe(self) -> str:
        who = f"customer: {self.customer}" if self.customer else self.owner
        return f"{self.name} ({self.container}@{self.host}, cohort {self.cohort}, {who})"


@dataclass(frozen=True)
class Fleet:
    name: str
    targets: tuple[Target, ...]
    base_dir: Path
    state_dir: Path
    golden_dir: Path | None = None
    tickets_dir: Path | None = None
    source: str = "fleet.yaml"

    def target(self, name: str) -> Target:
        for t in self.targets:
            if t.name == name:
                return t
        raise ValidationError(f"{self.source}: unknown target {name!r}")

    def select(self, names: Iterable[str] | None) -> tuple[Target, ...]:
        """The named targets in fleet-file order (all of them when `names` is None)."""
        if names is None:
            return self.targets
        wanted = set(names)
        for name in wanted:
            self.target(name)
        return tuple(t for t in self.targets if t.name in wanted)

    def targets_on_host(self, host: str) -> tuple[Target, ...]:
        host = host.lower()
        return tuple(t for t in self.targets if t.host == host)

    @property
    def canary(self) -> Target | None:
        return next((t for t in self.targets if t.canary), None)


def load_fleet(path: str | Path) -> Fleet:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValidationError(f"{path.name}: cannot read fleet file: {exc}") from exc
    data = load_strict(text, source=path.name)
    return parse_fleet(data, base_dir=path.resolve().parent, source=path.name)


def parse_fleet(data: Any, *, base_dir: Path, source: str) -> Fleet:
    check_keys(data, required=("fleet", "targets"),
               optional=("defaults", "golden", "state_dir", "tickets_dir"), where=source)
    name = target_name(data["fleet"], where=f"{source}:fleet")
    defaults = data.get("defaults") or {}
    check_keys(defaults, required=(), optional=_DEFAULT_KEYS, where=f"{source}:defaults")

    raw_targets = data["targets"]
    if not isinstance(raw_targets, list) or not raw_targets:
        raise ValidationError(f"{source}:targets: a fleet needs at least one target")
    targets = [_parse_target(raw, defaults, f"{source}:targets[{i}]")
               for i, raw in enumerate(raw_targets)]

    seen_names: set[str] = set()
    seen_containers: set[tuple[str, str]] = set()
    for i, t in enumerate(targets):
        where = f"{source}:targets[{i}]"
        if t.name in seen_names:
            raise ValidationError(f"{where}: duplicate target name {t.name!r}")
        seen_names.add(t.name)
        if (t.host, t.container) in seen_containers:
            raise ValidationError(f"{where}: container {t.container!r} on {t.host} is "
                                  "already claimed by another target")
        seen_containers.add((t.host, t.container))
    canaries = [t for t in targets if t.canary]
    if len(canaries) > 1:
        raise ValidationError(f"{source}: at most one target may be flagged canary "
                              f"(got {', '.join(t.name for t in canaries)})")
    if canaries and canaries[0].customer_owned:
        raise ValidationError(f"{source}: the canary {canaries[0].name!r} is customer-owned; "
                              "the canary is the target you are willing to break")

    def resolve(key: str, default: str | None) -> Path | None:
        value = data.get(key, default)
        if value is None:
            return None
        if not isinstance(value, str) or not value:
            raise ValidationError(f"{source}:{key}: expected a directory path")
        return base_dir / value

    return Fleet(name=name, targets=tuple(targets), base_dir=base_dir,
                 state_dir=resolve("state_dir", ".fleet-state") or base_dir / ".fleet-state",
                 golden_dir=resolve("golden", None), tickets_dir=resolve("tickets_dir", None),
                 source=source)


def _parse_target(raw: Any, defaults: Mapping[str, Any], where: str) -> Target:
    check_keys(raw, required=_TARGET_REQUIRED, optional=_TARGET_OPTIONAL, where=where)
    name = target_name(raw["name"], where=f"{where}.name")
    host = raw["host"]
    if not isinstance(host, str) or not _HOST.fullmatch(host):
        raise ValidationError(f"{where}.host: {host!r} is not a lowercase host name")
    container = raw.get("container", name)
    if not isinstance(container, str) or not _CONTAINER.fullmatch(container):
        raise ValidationError(f"{where}.container: {container!r} is not a valid container name")
    executor = raw.get("executor", defaults.get("executor"))
    if executor not in EXECUTORS:
        raise ValidationError(f"{where}.executor: expected one of {', '.join(EXECUTORS)}, "
                              f"got {executor!r}")
    root = workspace_root(raw.get("root", defaults.get("root")), where=f"{where}.root")
    owner = raw["owner"]
    if owner not in OWNERS:
        raise ValidationError(f"{where}.owner: expected 'internal' or 'customer', got {owner!r}")
    cohort = target_name(raw.get("cohort", defaults.get("cohort", "default")),
                         where=f"{where}.cohort")
    canary = raw.get("canary", False)
    if not isinstance(canary, bool):
        raise ValidationError(f"{where}.canary: expected true or false")
    customer = raw.get("customer")
    if customer is not None:
        if owner != "customer":
            raise ValidationError(f"{where}.customer: only customer-owned targets name a customer")
        customer = single_line(customer, where=f"{where}.customer", max_len=80)
    health_doc = copy.deepcopy(dict(defaults.get("health") or {}))
    health_doc.update(raw.get("health") or {})
    return Target(name=name, host=host, container=container, executor=executor, root=root,
                  owner=owner, cohort=cohort, canary=canary, customer=customer,
                  health=_parse_health(health_doc, f"{where}.health"),
                  vars=_parse_vars(raw.get("vars"), f"{where}.vars"))


def _number(value: Any, where: str, lo: float, hi: float, *, integer: bool = False) -> Any:
    ok_type = isinstance(value, int) if integer else isinstance(value, int | float)
    if isinstance(value, bool) or not ok_type or not lo <= value <= hi:
        kind = "an integer" if integer else "a number"
        raise ValidationError(f"{where}: expected {kind} in [{lo}, {hi}], got {value!r}")
    return value


def _parse_health(doc: dict, where: str) -> HealthCheck:
    check_keys(doc, required=("port", "path"), optional=_HEALTH_KEYS, where=where)
    port = _number(doc["port"], f"{where}.port", 1, 65535, integer=True)
    path = doc["path"]
    if not isinstance(path, str) or not _HEALTH_PATH.fullmatch(path):
        raise ValidationError(f"{where}.path: {path!r} must start with '/' and use URL-safe "
                              "characters only")
    expect_json = doc.get("expect_json")
    if expect_json is not None and (not isinstance(expect_json, dict) or not expect_json):
        raise ValidationError(f"{where}.expect_json: expected a non-empty mapping of the JSON "
                              "fields the body must contain")
    expect_body = doc.get("expect_body")
    if expect_body is not None:
        expect_body = single_line(expect_body, where=f"{where}.expect_body")
    expect_contains = doc.get("expect_contains")
    if expect_contains is not None:
        expect_contains = single_line(expect_contains, where=f"{where}.expect_contains")
    if expect_json is None and expect_body is None and expect_contains is None:
        raise ValidationError(f"{where}: set expect_json, expect_body or expect_contains; a "
                              "bare status code is not health (a proxy's catch-all route "
                              "answers 200 too)")
    return HealthCheck(
        port=port, path=path,
        expect_status=_number(doc.get("expect_status", 200), f"{where}.expect_status",
                              100, 599, integer=True),
        expect_json=expect_json, expect_body=expect_body, expect_contains=expect_contains,
        retries=_number(doc.get("retries", 3), f"{where}.retries", 1, 20, integer=True),
        interval_seconds=float(_number(doc.get("interval_seconds", 2.0),
                                       f"{where}.interval_seconds", 0, 300)),
        timeout_seconds=float(_number(doc.get("timeout_seconds", 5.0),
                                      f"{where}.timeout_seconds", 0.1, 60)),
    )


def _parse_vars(raw: Any, where: str) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValidationError(f"{where}: expected a mapping of name -> text")
    out = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not _VAR_NAME.fullmatch(key):
            raise ValidationError(f"{where}: {key!r} is not a valid variable name "
                                  "([a-z_][a-z0-9_]*)")
        if not isinstance(value, str):
            raise ValidationError(f"{where}.{key}: expected text, got {type(value).__name__}")
        out[key] = single_line(value, where=f"{where}.{key}")
    return out
