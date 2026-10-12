from fleet_rollout.syntax import check_staged
from fleet_rollout.testing import FakeExecutor

STAGED = "/srv/agent/config/.x.rollout-demo.tmp"


def check(dest, data, *, needs_compile=False, fx=None):
    fx = fx or FakeExecutor()
    fx.put(STAGED, data)
    return check_staged(fx, STAGED, dest, data, needs_compile=needs_compile)


def test_valid_json_passes_and_invalid_json_is_reported():
    assert check("config/agent.json", b'{"model": "small", "temperature": 0.2}') is None
    problem = check("config/agent.json", b'{"model": "small",}')
    assert problem is not None and "JSON" in problem


def test_yaml_and_toml_are_checked():
    assert check("config/routes.yaml", b"routes:\n  - billing\n") is None
    assert "YAML" in check("config/routes.yml", b"routes: [billing\n")
    assert check("config/limits.toml", b"[limits]\nper_minute = 30\n") is None
    assert "TOML" in check("config/limits.toml", b"[limits\nper_minute = 30\n")


def test_python_is_compiled_on_the_target_using_the_staged_copy():
    fx = FakeExecutor()
    assert check("handlers/invoices.py", b"def total(x):\n    return sum(x)\n",
                 needs_compile=True, fx=fx) is None
    compiled = [c for c in fx.calls if c[0] == "run"]
    assert compiled and compiled[-1][1][0][-1] == STAGED
    problem = check("handlers/invoices.py", b"def total(x:\n", needs_compile=True)
    assert problem is not None and "SyntaxError" in problem


def test_files_without_a_known_format_are_not_checked():
    assert check("prompts/support.md", b"anything { goes") is None


def test_non_utf8_structured_files_are_reported():
    assert "UTF-8" in check("config/agent.json", b"\xff\xfe{}")
