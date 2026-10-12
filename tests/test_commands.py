import pytest

from fleet_rollout.commands import ALLOWED_COMMANDS, resolve_command
from fleet_rollout.validation import ValidationError


def test_known_command_resolves_to_our_argv_prefix_plus_jailed_paths():
    cmd = resolve_command("make_dirs", ["cache/invoices", "logs"], where="steps[1]")
    assert cmd.argv("/srv/agent") == [
        "mkdir", "-p", "--", "/srv/agent/cache/invoices", "/srv/agent/logs"]


def test_reload_agent_takes_no_arguments_and_is_rerun_after_a_restore():
    cmd = resolve_command("reload_agent", [], where="steps[0]")
    assert cmd.argv("/srv/agent") == ["kill", "-HUP", "1"]
    assert cmd.spec.rerun_on_restore is True
    with pytest.raises(ValidationError, match=r"takes 0\.\.0 argument"):
        resolve_command("reload_agent", ["x"], where="steps[0]")


def test_args_may_be_omitted_for_zero_argument_commands():
    assert resolve_command("reload_agent", None, where="steps[0]").args == ()


@pytest.mark.parametrize("name", ["rm -rf /", "bash", "sh -c id", "", "Make_Dirs", None, 3])
def test_anything_not_on_the_allowlist_has_no_way_in(name):
    with pytest.raises(ValidationError, match="not on the command allowlist"):
        resolve_command(name, [], where="steps[0].command")


def test_the_error_lists_what_is_allowed():
    with pytest.raises(ValidationError, match="compile_python, make_dirs, make_executable"):
        resolve_command("curl", [], where="steps[0].command")


@pytest.mark.parametrize("arg", ["../outside", "/etc/cron.d/x", "a;b", "$(id)", "-rf",
                                 ".fleet-rollout/lock"])
def test_command_arguments_are_validated_as_jailed_paths(arg):
    with pytest.raises(ValidationError):
        resolve_command("make_executable", [arg], where="steps[0]")


def test_argument_count_is_bounded():
    with pytest.raises(ValidationError, match=r"takes 1\.\.8 argument"):
        resolve_command("make_dirs", [], where="steps[0]")
    with pytest.raises(ValidationError, match=r"takes 1\.\.8 argument"):
        resolve_command("make_dirs", [f"d{i}" for i in range(9)], where="steps[0]")


def test_arguments_must_be_a_list():
    with pytest.raises(ValidationError, match="list"):
        resolve_command("make_dirs", "logs", where="steps[0]")


def test_compile_python_never_writes_bytecode():
    argv = resolve_command("compile_python", ["handlers/invoices.py"],
                           where="steps[0]").argv("/srv/agent")
    assert argv[:2] == ["python3", "-c"]
    assert "py_compile" not in argv[2]  # py_compile would drop a __pycache__ next to it
    assert argv[-1] == "/srv/agent/handlers/invoices.py"


def test_the_allowlist_cannot_be_extended_at_runtime():
    with pytest.raises(TypeError):
        ALLOWED_COMMANDS["shell"] = ALLOWED_COMMANDS["make_dirs"]  # type: ignore[index]
