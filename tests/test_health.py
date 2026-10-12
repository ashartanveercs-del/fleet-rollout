from fleet_rollout.executors.base import HttpResponse
from fleet_rollout.fleet import HealthCheck
from fleet_rollout.health import check_health, evaluate
from fleet_rollout.testing import FakeExecutor

JSON_OK = HealthCheck(port=8080, path="/healthz", expect_json={"status": "ok"}, retries=1)


def test_the_right_status_and_body_is_healthy():
    assert evaluate(HttpResponse(200, b'{"status":"ok","uptime":12}'), JSON_OK) is None


def test_a_200_with_the_wrong_body_is_not_healthy():
    problem = evaluate(HttpResponse(200, b'{"status":"degraded"}'), JSON_OK)
    assert problem is not None
    assert "status" in problem and "degraded" in problem


def test_a_proxy_catch_all_page_is_not_healthy():
    page = b"<html><body>Welcome to nginx!</body></html>"
    problem = evaluate(HttpResponse(200, page), JSON_OK)
    assert problem is not None and "not JSON" in problem


def test_json_that_is_not_an_object_is_not_healthy():
    assert "object" in evaluate(HttpResponse(200, b'["ok"]'), JSON_OK)


def test_the_right_body_with_the_wrong_status_is_not_healthy():
    problem = evaluate(HttpResponse(503, b'{"status":"ok"}'), JSON_OK)
    assert problem is not None and "503" in problem


def test_no_response_at_all_is_not_healthy():
    problem = evaluate(HttpResponse(0, error="Connection refused"), JSON_OK)
    assert "Connection refused" in problem


def test_exact_body_and_contains_expectations():
    exact = HealthCheck(port=1, path="/h", expect_body="ok")
    assert evaluate(HttpResponse(200, b"ok\n"), exact) is None
    assert evaluate(HttpResponse(200, b"okay"), exact) is not None
    contains = HealthCheck(port=1, path="/h", expect_contains="ready")
    assert evaluate(HttpResponse(200, b"agent ready, 3 workers"), contains) is None
    assert evaluate(HttpResponse(200, b"starting"), contains) is not None


def test_non_utf8_bodies_are_not_healthy():
    contains = HealthCheck(port=1, path="/h", expect_contains="ok")
    assert "UTF-8" in evaluate(HttpResponse(200, b"\xff\xfeok"), contains)


def test_body_excerpts_in_messages_are_escaped_and_truncated():
    exact = HealthCheck(port=1, path="/h", expect_body="ok")
    problem = evaluate(HttpResponse(200, b"\x1b[31mred " + b"x" * 500), exact)
    assert "\x1b" not in problem and len(problem) < 300


def flaky(*responses):
    queue = list(responses)
    return lambda fx: queue.pop(0) if len(queue) > 1 else queue[0]


def test_retries_until_healthy_and_sleeps_between_attempts():
    fx = FakeExecutor(health=flaky(HttpResponse(0, error="refused"),
                                   HttpResponse(200, b'{"status":"starting"}'),
                                   HttpResponse(200, b'{"status":"ok"}')))
    slept = []
    hc = HealthCheck(port=8080, path="/healthz", expect_json={"status": "ok"}, retries=5,
                     interval_seconds=1.5)
    result = check_health(fx, hc, sleep=slept.append)
    assert result.ok and result.attempts == 3
    assert slept == [1.5, 1.5]


def test_gives_up_after_the_configured_retries_and_reports_the_last_problem():
    fx = FakeExecutor(health=lambda _: HttpResponse(200, b'{"status":"degraded"}'))
    hc = HealthCheck(port=8080, path="/healthz", expect_json={"status": "ok"}, retries=3,
                     interval_seconds=0)
    result = check_health(fx, hc, sleep=lambda s: None)
    assert not result.ok and result.attempts == 3
    assert "degraded" in result.detail


def test_an_unreachable_target_is_unhealthy_not_an_exception():
    fx = FakeExecutor()
    fx.fail("http_get", error="ssh connection failed", times=5)
    result = check_health(fx, JSON_OK, sleep=lambda s: None)
    assert not result.ok and "ssh connection failed" in result.detail
