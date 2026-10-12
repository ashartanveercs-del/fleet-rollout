"""The health gate: the target must answer with the right status AND the right body.

A status code on its own proves very little. A reverse proxy's catch-all route, a
maintenance page, or an agent that started but failed to load its config can all
answer 200. So every health check in the fleet file asserts something about the body
(`fleet.py` refuses one that does not), and this module reports exactly which
expectation failed, with a short, escaped excerpt of what actually came back.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass

from .executors.base import Executor, ExecutorError, HttpResponse
from .fleet import HealthCheck


@dataclass(frozen=True)
class HealthResult:
    ok: bool
    detail: str
    attempts: int


def _excerpt(body: bytes | str, limit: int = 80) -> str:
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    shown = repr(text[:limit])
    return shown + ("..." if len(text) > limit else "")


def evaluate(response: HttpResponse, hc: HealthCheck) -> str | None:
    """Return what is wrong with `response`, or None if it proves health."""
    if response.status == 0:
        return f"no HTTP response ({response.error or 'unknown error'})"
    if response.status != hc.expect_status:
        return f"HTTP {response.status}, expected {hc.expect_status}"
    try:
        text = response.body.decode("utf-8")
    except UnicodeDecodeError:
        return f"HTTP {response.status} but the body is not UTF-8: {_excerpt(response.body)}"
    if hc.expect_body is not None and text.strip() != hc.expect_body:
        return f"HTTP {response.status} but the body {_excerpt(text)} is not {hc.expect_body!r}"
    if hc.expect_contains is not None and hc.expect_contains not in text:
        return (f"HTTP {response.status} but the body {_excerpt(text)} does not contain "
                f"{hc.expect_contains!r}")
    if hc.expect_json is not None:
        try:
            doc = json.loads(text)
        except ValueError:
            return f"HTTP {response.status} but the body is not JSON: {_excerpt(text)}"
        if not isinstance(doc, dict):
            return f"HTTP {response.status} but the JSON body is not an object: {_excerpt(text)}"
        for key, want in hc.expect_json.items():
            if doc.get(key) != want:
                got = json.dumps(doc.get(key), ensure_ascii=True)
                got = got if len(got) <= 40 else got[:40] + "..."
                return (f"HTTP {response.status} but body field {key!r} is {got}, expected "
                        f"{json.dumps(want, ensure_ascii=True)}")
    return None


def check_health(executor: Executor, hc: HealthCheck, *,
                 sleep: Callable[[float], None] = time.sleep) -> HealthResult:
    """Probe up to `hc.retries` times, sleeping `hc.interval_seconds` between attempts."""
    problem = "not probed"
    for attempt in range(1, hc.retries + 1):
        try:
            problem = evaluate(executor.http_get(hc.port, hc.path, timeout=hc.timeout_seconds),
                               hc)
        except ExecutorError as exc:
            problem = str(exc)
        if problem is None:
            return HealthResult(True, f"healthy (attempt {attempt})", attempt)
        if attempt < hc.retries:
            sleep(hc.interval_seconds)
    return HealthResult(False, problem, hc.retries)
