import shlex
import subprocess

import pytest

from fleet_rollout.executors.base import ExecutorError
from fleet_rollout.executors.container import (
    ContainerExecutor,
    DockerTransport,
    SSHTransport,
    make_executor,
)
from fleet_rollout.fleet import HealthCheck, Target


class FakeRunner:
    """Stands in for subprocess.run: records argv/stdin, replays scripted results."""

    def __init__(self, *results):
        self.results = list(results)
        self.calls = []

    def __call__(self, argv, *, input=None, capture_output=None, timeout=None, check=None):
        self.calls.append({"argv": argv, "input": input, "timeout": timeout})
        result = self.results.pop(0) if self.results else (0, b"", b"")
        if isinstance(result, BaseException):
            raise result
        rc, out, err = result
        return subprocess.CompletedProcess(argv, rc, out, err)

    @property
    def argv(self):
        return self.calls[-1]["argv"]


def docker(*results):
    runner = FakeRunner(*results)
    return ContainerExecutor(DockerTransport("agent-01"), runner=runner, name="agent-01"), runner


def ssh(*results):
    runner = FakeRunner(*results)
    transport = SSHTransport("edge-1.example.com", "agent-01", connect_timeout=7)
    return ContainerExecutor(transport, runner=runner, name="agent-01"), runner


PATH = "/srv/agent/config/greeting.txt"


def test_docker_read_passes_the_path_as_an_argument_not_inside_the_script():
    ex, runner = docker((0, b"hello\n", b""))
    assert ex.read(PATH) == b"hello\n"
    argv = runner.argv
    assert argv[:4] == ["docker", "exec", "-i", "agent-01"]
    assert argv[4:6] == ["sh", "-c"]
    assert PATH not in argv[6]          # the script only ever says "$1"
    assert argv[7:] == ["sh", PATH]


def test_read_of_a_missing_file_is_none():
    ex, _ = docker((3, b"", b""))
    assert ex.read(PATH) is None


def test_read_of_something_that_is_not_a_regular_file_is_an_error():
    ex, _ = docker((4, b"", b""))
    with pytest.raises(ExecutorError, match="not a regular file"):
        ex.read(PATH)


def test_an_unreachable_container_is_an_error_never_a_missing_file():
    ex, _ = docker((125, b"", b"Error response from daemon: container is not running"))
    with pytest.raises(ExecutorError, match="not running"):
        ex.read(PATH)


def test_ssh_wraps_docker_exec_in_one_correctly_quoted_remote_command():
    ex, runner = ssh((0, b"hello\n", b""))
    assert ex.read(PATH) == b"hello\n"
    argv = runner.argv
    assert argv[:6] == ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=7", "--"]
    assert argv[6] == "edge-1.example.com"
    remote = shlex.split(argv[7])
    assert remote[:4] == ["docker", "exec", "-i", "agent-01"]
    assert remote[4:6] == ["sh", "-c"]
    assert remote[7:] == ["sh", PATH]
    assert len(argv) == 8


def test_ssh_connection_failure_is_an_error_never_a_missing_file():
    ex, _ = ssh((255, b"", b"ssh: connect to host edge-1.example.com port 22: timed out"))
    with pytest.raises(ExecutorError, match="ssh"):
        ex.read(PATH)


def test_write_streams_bytes_over_stdin():
    ex, runner = docker((0, b"", b""))
    ex.write(PATH + ".tmp", b"\x00binary\xff")
    assert runner.calls[-1]["input"] == b"\x00binary\xff"
    assert runner.argv[-2:] == ["sh", PATH + ".tmp"]


def test_write_failure_raises():
    ex, _ = docker((1, b"", b"sh: can't create: Read-only file system"))
    with pytest.raises(ExecutorError, match="Read-only"):
        ex.write(PATH, b"x")


def test_rename_refuses_a_directory_destination_inside_the_script():
    ex, runner = docker((5, b"", b""))
    with pytest.raises(ExecutorError, match="directory"):
        ex.rename(PATH + ".tmp", PATH)
    assert runner.argv[-3:] == ["sh", PATH + ".tmp", PATH]


def test_remove_uses_double_dash():
    ex, runner = docker((0, b"", b""))
    ex.remove(PATH)
    assert runner.argv[4:] == ["rm", "-f", "--", PATH]


def test_inspect_parses_flags_and_realpath():
    ex, _ = docker((0, b"1 1 0 1\n/srv/other/greeting.txt", b""))
    info = ex.inspect(PATH)
    assert (info.exists, info.is_file, info.is_dir, info.is_symlink) == (True, True, False, True)
    assert info.realpath == "/srv/other/greeting.txt"


def test_create_exclusive_reports_an_existing_file_as_false():
    ex, _ = docker((3, b"", b""))
    assert ex.create_exclusive("/srv/agent/.fleet-rollout/lock", b"{}") is False
    ex, runner = docker((0, b"", b""))
    assert ex.create_exclusive("/srv/agent/.fleet-rollout/lock", b"{}") is True
    assert runner.calls[-1]["input"] == b"{}"


def test_create_exclusive_other_failures_raise():
    ex, _ = docker((1, b"", b"mkdir: Permission denied"))
    with pytest.raises(ExecutorError, match="Permission denied"):
        ex.create_exclusive("/srv/agent/.fleet-rollout/lock", b"{}")


def test_http_get_probes_from_inside_the_container():
    ex, runner = docker((0, b'200\n{"status":"ok"}', b""))
    resp = ex.http_get(8080, "/healthz", timeout=3)
    assert (resp.status, resp.body) == (200, b'{"status":"ok"}')
    assert runner.argv[4:6] == ["python3", "-c"]
    assert runner.argv[-2:] == ["http://127.0.0.1:8080/healthz", "3"]


def test_http_get_connection_refused_is_status_zero_with_the_error():
    ex, _ = docker((1, b"", b"ConnectionRefusedError: [Errno 111] Connection refused"))
    resp = ex.http_get(8080, "/healthz")
    assert resp.status == 0 and "Connection refused" in resp.error


def test_free_bytes_parses_df_output():
    out = b"Filesystem 1024-blocks Used Available Capacity Mounted on\noverlay 100 40 60 40% /\n"
    ex, runner = docker((0, out, b""))
    assert ex.free_bytes("/srv/agent") == 60 * 1024
    assert runner.argv[4:] == ["df", "-Pk", "--", "/srv/agent"]


def test_run_returns_the_result_and_passes_the_timeout():
    ex, runner = docker((2, b"out", b"err"))
    result = ex.run(["kill", "-HUP", "1"], timeout=9)
    assert (result.returncode, result.stdout, result.stderr) == (2, b"out", b"err")
    assert runner.calls[-1]["timeout"] == 9


def test_a_missing_cli_is_an_executor_error():
    ex, _ = docker(FileNotFoundError("docker"))
    with pytest.raises(ExecutorError, match="not found"):
        ex.read(PATH)


def test_timeouts_are_executor_errors():
    ex, _ = docker(subprocess.TimeoutExpired(["docker"], 5))
    with pytest.raises(ExecutorError, match="timed out"):
        ex.read(PATH)


def target(executor):
    return Target(name="agent-01", host="edge-1.example.com", container="agent-01",
                  executor=executor, root="/srv/agent", owner="internal", cohort="staff",
                  health=HealthCheck(port=8080, path="/healthz", expect_body="ok"))


def test_make_executor_picks_the_transport_from_the_target():
    runner = FakeRunner((0, b"x", b""), (0, b"x", b""))
    make_executor(target("docker"), runner=runner).read(PATH)
    assert runner.argv[0] == "docker"
    make_executor(target("ssh"), runner=runner).read(PATH)
    assert runner.argv[0] == "ssh"
