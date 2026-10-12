"""Decide what a shell command would do to the fleet.

The classifier walks every simple command (see `shell.py`) in one of four contexts:

* `local`     - the machine the agent runs on. Local files are the agent's business,
                except the protected ones; a program the guard does not understand is
                assumed harmless *unless it names a fleet target*.
* `remote`    - a host reached over ssh that is not in the fleet: same as local, minus
                the protected-path rules.
* `host`      - a fleet host. Anything that is not a plain read is a change to every
                target on that host, unless a docker command names the containers.
* `container` - inside a fleet container. Anything that is not a plain read changes it.

The result is a list of findings. `mutation` findings carry the targets they touch and
the change ticket the command presented; the hook decides whether that ticket is good
enough. `unknown`, `forbidden` and `protected` findings are denied outright: no ticket
can authorize what cannot be named, nor let an agent edit its own authorization.
"""

from __future__ import annotations

import contextlib
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path

from ..fleet import Fleet
from .shell import Command, Word, parse

MAX_SCRIPT_BYTES = 256 * 1024

DOCKER_CLIS = frozenset({"docker", "podman", "nerdctl"})
SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "ash"})
PYTHONS = frozenset({"python", "python3", "py"})
RESERVED = frozenset({"if", "then", "else", "elif", "do", "while", "until", "!", "time", "fi",
                      "done", "esac"})
HEADERS = frozenset({"for", "case", "select", "function"})

READ_ONLY = frozenset({
    "cat", "tac", "head", "tail", "less", "more", "ls", "tree", "grep", "egrep", "fgrep", "rg",
    "wc", "stat", "file", "du", "df", "ps", "pgrep", "free", "uptime", "id", "whoami",
    "uname", "printenv", "pwd", "echo", "printf", "true", "false", "test", "[",
    "sha256sum", "sha1sum", "md5sum", "cksum", "sort", "uniq", "cut", "tr", "rev", "jq",
    "diff", "cmp", "column", "nl", "od", "xxd", "hexdump", "strings", "basename", "dirname",
    "realpath", "readlink", "which", "type", "sleep", "nproc", "lsof", "netstat", "ss",
    "getent", "env", "vmstat", "iostat", "dmesg",
})
LOCAL_ONLY = READ_ONLY | frozenset({
    "git", "cd", "pushd", "popd", "export", "unset", "set", "alias", "read", "shift", "exit",
    "return", "local", "declare", "typeset", "wait", "rm", "cp", "mv", "mkdir", "rmdir",
    "touch", "ln", "chmod", "chown", "tee", "tar", "gzip", "gunzip", "zip", "unzip", "ruff",
})

DOCKER_GLOBAL_VALUE = frozenset({"--context", "-c", "--config", "-l", "--log-level",
                                 "--tlscacert", "--tlscert", "--tlskey"})
DOCKER_READ_ONLY = frozenset({"ps", "inspect", "logs", "stats", "top", "port", "diff", "images",
                              "history", "version", "info", "events", "search", "wait",
                              "export", "help"})
DOCKER_MGMT = frozenset({"image", "network", "volume", "system", "plugin", "builder", "buildx",
                         "context", "swarm", "service", "stack", "node", "secret", "config",
                         "manifest", "trust"})
DOCKER_MGMT_READ = frozenset({"ls", "list", "inspect", "history", "df", "info", "events", "ps",
                              "show"})
DOCKER_CREATE = frozenset({"run", "create", "build", "pull", "push", "login", "logout", "load",
                           "save", "tag", "import"})
EXEC_VALUE = frozenset({"-e", "--env", "--env-file", "-u", "--user", "-w", "--workdir",
                        "--detach-keys"})
COMPOSE_VALUE = frozenset({"-f", "--file", "-p", "--project-name", "--project-directory",
                           "--profile", "--env-file", "--ansi", "--parallel", "--progress"})
COMPOSE_READ_ONLY = frozenset({"ps", "logs", "config", "images", "top", "ls", "version", "port",
                               "events", "convert"})
SSH_VALUE = frozenset("BbcDEeFIiJLlmOoPpQRSWw")
SCP_VALUE = frozenset({"-c", "-F", "-i", "-l", "-o", "-P", "-S", "-J", "-D", "-X"})
RSYNC_VALUE = frozenset({"-e", "--rsh", "--rsync-path", "--exclude", "--include", "--filter",
                         "-f", "--port", "--password-file", "--log-file", "--partial-dir",
                         "--temp-dir", "-T", "--files-from", "--exclude-from", "--include-from",
                         "-B", "--block-size", "--timeout", "--contimeout", "--bwlimit",
                         "--chmod", "--backup-dir", "--suffix", "--compare-dest", "--copy-dest",
                         "--link-dest"})
FIND_WRITES = frozenset({"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0",
                         "-fprintf", "-fls"})
FIND_EXEC = frozenset({"-exec", "-execdir", "-ok", "-okdir"})
SYSTEMCTL_READ = frozenset({"status", "is-active", "is-enabled", "is-failed", "list-units",
                            "list-unit-files", "show", "cat", "list-timers",
                            "list-dependencies"})
FLEET_CLI_VALUE_OPTIONS = frozenset({"--fleet", "--state", "--canary", "--operator", "--bake",
                                     "--reason", "--approver", "--note", "--ttl-hours",
                                     "--run"})
FLEET_FORBIDDEN = {
    "approve": "approvals must be recorded by people, not by an agent session",
    "clear-halt": "clearing a halt is a human decision, made after investigating why the "
                  "rollout stopped",
}
_WRITE_REDIRECTS = frozenset({">", ">>", ">|", "&>", "&>>", "<>"})
_HARMLESS_SINKS = frozenset({"/dev/null", "/dev/stdout", "/dev/stderr"})
_SQL_WRITE = re.compile(r"\b(insert|update|delete|drop|create|alter|replace|attach|detach|"
                        r"vacuum|reindex|analyze|begin|commit|savepoint|release|upsert)\b")
_SQL_DOT_WRITE = re.compile(r"(^|\s)\.(import|restore|read|output|once|save|backup|shell|"
                            r"system|load|open|cd|excel|log)\b")
_ASSIGN = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=")


# -- inventory ----------------------------------------------------------------------------


class Inventory:
    """What the guard knows about the fleet: names, containers, hosts, protected paths."""

    def __init__(self, fleet: Fleet | None, protected: Iterable[Path] = ()) -> None:
        self.fleet = fleet
        self.targets = {t.name: t for t in fleet.targets} if fleet else {}
        self._containers: dict[str, set[str]] = {}
        self._hosts: dict[str, set[str]] = {}
        for t in self.targets.values():
            self._containers.setdefault(t.container.lower(), set()).add(t.name)
            self._containers.setdefault(t.name.lower(), set()).add(t.name)
            self._hosts.setdefault(t.host.lower(), set()).add(t.name)
        tokens = sorted(set(self._containers) | set(self._hosts), key=len, reverse=True)
        self._mention = re.compile(
            r"(?<![A-Za-z0-9_-])(" + "|".join(re.escape(t) for t in tokens) + r")(?![A-Za-z0-9_-])",
            re.IGNORECASE) if tokens else None
        self.protected = tuple(Path(os.path.normpath(os.path.abspath(p))) for p in protected)

    def by_container(self, token: str) -> frozenset[str]:
        return frozenset(self._containers.get(token.lower(), ()))

    def by_host(self, host: str) -> frozenset[str]:
        return frozenset(self._hosts.get(host.lower(), ()))

    def mentioned(self, texts: Iterable[str]) -> frozenset[str]:
        if self._mention is None:
            return frozenset()
        found: set[str] = set()
        for text in texts:
            for match in self._mention.finditer(text):
                key = match.group(1).lower()
                found |= self._containers.get(key, set()) | self._hosts.get(key, set())
        return frozenset(found)

    def protected_hit(self, text: str, cwd: Path) -> bool:
        if not self.protected or not text:
            return False
        if not re.search(r"[\s'\"();|&<>`$]", text):          # a plain path argument
            path = Path(os.path.expanduser(text))
            path = Path(os.path.normpath(path if path.is_absolute() else cwd / path))
            return any(path == root or root in path.parents for root in self.protected)
        normalized = text.replace("\\", "/")                     # code: look for the names
        for root in self.protected:
            forms = {root.as_posix()}
            with contextlib.suppress(ValueError):       # not under cwd: absolute form only
                forms.add(root.relative_to(cwd).as_posix())
            for form in forms:
                if re.search(r"(?<![A-Za-z0-9_.-])" + re.escape(form) + r"(?![A-Za-z0-9_-])",
                             normalized):
                    return True
        return False


# -- findings and scope ---------------------------------------------------------------------


@dataclass(frozen=True)
class Context:
    kind: str                             # "local" | "remote" | "host" | "container"
    targets: frozenset[str] = frozenset()
    where: str = "this machine"


LOCAL = Context("local")


@dataclass(frozen=True)
class Finding:
    kind: str                             # "mutation" | "unknown" | "forbidden" | "protected"
    reason: str
    targets: frozenset[str] = frozenset()
    ticket: str | None = None
    ticket_dynamic: bool = False


@dataclass(frozen=True)
class Scope:
    inv: Inventory
    cwd: Path
    ctx: Context = LOCAL
    ticket: str | None = None
    ticket_dynamic: bool = False
    depth: int = 0

    def mutation(self, targets: Iterable[str], reason: str) -> Finding:
        return Finding("mutation", reason, frozenset(targets), self.ticket, self.ticket_dynamic)

    def unknown(self, reason: str) -> Finding:
        return Finding("unknown", reason)

    def within(self, ctx: Context) -> Scope:
        return replace(self, ctx=ctx, depth=self.depth + 1)

    def classify(self, script: str) -> list[Finding]:
        return classify(script, self.inv, cwd=self.cwd, ctx=self.ctx, ticket=self.ticket,
                        ticket_dynamic=self.ticket_dynamic, depth=self.depth + 1)


def classify(script: str, inv: Inventory, *, cwd: Path, ctx: Context = LOCAL,
             ticket: str | None = None, ticket_dynamic: bool = False,
             depth: int = 0) -> list[Finding]:
    """Findings for every command in `script`. Raises ShellSyntaxError if unparseable."""
    scope = Scope(inv, Path(cwd), ctx, ticket, ticket_dynamic, depth)
    findings: list[Finding] = []
    for command in parse(script, depth=depth):
        findings.extend(_command(command, scope))
    return findings


def only_reads(script: str) -> bool:
    """True if every command in `script` is a plain read (used when the fleet is unknown)."""
    for command in parse(script):
        words = _unwrap(list(command.words), None, False)[0]
        if not words:
            if _writes(command):
                return False
            continue
        if words[0].dynamic or not _is_read_only(_base(words[0].text), words[1:], command):
            return False
    return True


# -- helpers ---------------------------------------------------------------------------


def _base(text: str) -> str:
    name = text.replace("\\", "/").rsplit("/", 1)[-1]
    return name[:-4] if name.lower().endswith(".exe") else name


def _texts(words: Iterable[Word]) -> list[str]:
    return [w.text for w in words]


def _skip_options(words: list[Word], value_opts: frozenset[str] | set[str]) -> list[Word]:
    i = 0
    while i < len(words):
        text = words[i].text
        if text == "--":
            return words[i + 1:]
        if not text.startswith("-") or text == "-":
            break
        i += 2 if text in value_opts else 1
    return words[i:]


def _unwrap(words: list[Word], ticket: str | None, ticket_dynamic: bool
            ) -> tuple[list[Word], bool, str | None, bool, dict[str, Word]]:
    """Strip shell keywords and wrapper programs (sudo, env, timeout, xargs, ...).
    Returns the remaining words, whether arguments get appended at run time (xargs), the
    change ticket, and the environment variables `env` assigned on the way."""
    tail_dynamic = False
    env: dict[str, Word] = {}
    while words:
        head = words[0]
        name = _base(head.text)
        if head.text in RESERVED and not head.quoted:
            words = words[1:]
        elif name in HEADERS:
            return [], tail_dynamic, ticket, ticket_dynamic, env
        elif name in ("sudo", "doas"):
            words = _skip_options(words[1:], {"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t",
                                              "-U", "-T"})
        elif name == "env":
            words = _skip_options(words[1:], {"-u", "-C", "-S", "--unset", "--chdir"})
            while words and (match := _ASSIGN.match(words[0].text)):
                value = Word(words[0].text[match.end():], words[0].dynamic, words[0].quoted)
                env[match.group(1)] = value
                if match.group(1) == "CHANGE_TICKET":
                    ticket, ticket_dynamic = value.text, value.dynamic
                words = words[1:]
        elif name in ("nohup", "command", "builtin", "exec", "setsid", "chronic", "unbuffer"):
            words = _skip_options(words[1:], set())
        elif name == "stdbuf":
            words = _skip_options(words[1:], {"-i", "-o", "-e"})
        elif name == "nice":
            words = _skip_options(words[1:], {"-n", "--adjustment"})
        elif name == "ionice":
            words = _skip_options(words[1:], {"-c", "-n", "-p", "-P", "-u"})
        elif name == "timeout":
            words = _skip_options(words[1:], {"-s", "-k", "--signal", "--kill-after"})[1:]
        elif name == "watch":
            words = _skip_options(words[1:], {"-n", "--interval"})
        elif name == "xargs":
            words = _skip_options(words[1:], {"-I", "-n", "-P", "-L", "-d", "-a", "-E", "-s",
                                              "--max-args", "--max-procs", "--delimiter",
                                              "--arg-file", "--replace"})
            tail_dynamic = True
        else:
            break
    return words, tail_dynamic, ticket, ticket_dynamic, env


def _writes(command: Command) -> bool:
    for r in command.redirects:
        if r.op in _WRITE_REDIRECTS and r.target.text not in _HARMLESS_SINKS:
            return True
        if r.op == ">&" and not (r.target.text.isdigit() or r.target.text == "-"):
            return True
    return False


def _sqlite_read_only(texts: list[str]) -> bool:
    if any(t in ("-cmd", "-init") for t in texts):
        return False
    positional = [t for t in texts if not t.startswith("-")]
    if len(positional) < 2:
        return False                      # interactive, or SQL arriving on stdin
    sql = " ".join(positional[1:]).lower()
    return not (_SQL_WRITE.search(sql) or _SQL_DOT_WRITE.search(sql)
                or re.search(r"\bpragma\s+\w+\s*[=(]", sql))


def _curl_writes(text: str) -> bool:
    long_writes = ("--request", "--data", "--json", "--form", "--upload-file", "--output",
                   "--remote-name", "--config")
    if text.startswith("--"):
        return text.startswith(long_writes)
    return text.startswith(("-X", "-d", "-F", "-T", "-o", "-O", "-K"))


def _is_read_only(prog: str, args: list[Word], command: Command) -> bool:
    if _writes(command):
        return False
    texts = _texts(args)
    if prog in READ_ONLY:
        return True
    if prog == "hostname":
        return all(t.startswith("-") for t in texts)
    if prog == "date":
        return not any(t in ("-s", "--set") or t.startswith("--set=") for t in texts)
    if prog == "find":
        return not any(t in FIND_WRITES for t in texts)
    if prog == "curl":
        return not any(_curl_writes(t) for t in texts)
    if prog == "sqlite3":
        return _sqlite_read_only(texts)
    if prog == "systemctl":
        verbs = [t for t in texts if not t.startswith("-")]
        return bool(verbs) and verbs[0] in SYSTEMCTL_READ
    if prog == "journalctl":
        return not any(t.startswith(("--vacuum", "--rotate", "--flush", "--sync",
                                     "--relinquish")) for t in texts)
    return False


def _host_of(text: str) -> str:
    host = text.split("://", 1)[-1]
    host = host.rsplit("@", 1)[-1]
    if host.startswith("["):
        return host[1:].split("]", 1)[0].lower()
    return host.split(":", 1)[0].split("/", 1)[0].lower()


def _remote_host(text: str) -> str | None:
    """Host of an scp/rsync remote spec (`user@host:path`, `host::module`, rsync://...)."""
    if text.startswith("rsync://"):
        return _host_of(text)
    head, sep, _ = text.partition(":")
    if not sep or "/" in head or len(head) <= 1:
        return None                       # a local path (or a Windows drive letter)
    return head.rsplit("@", 1)[-1].lower()


def _read_script(word: Word, cwd: Path) -> str | None:
    if word.dynamic:
        return None
    path = Path(word.text)
    path = path if path.is_absolute() else cwd / path
    try:
        if path.stat().st_size > MAX_SCRIPT_BYTES:
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


# -- one simple command --------------------------------------------------------------------


def _command(command: Command, scope: Scope) -> list[Finding]:
    ticket, ticket_dynamic = scope.ticket, scope.ticket_dynamic
    for name, value in command.assignments:
        if name == "CHANGE_TICKET":
            ticket, ticket_dynamic = value.text, value.dynamic
    words, tail, ticket, ticket_dynamic, env = _unwrap(list(command.words), ticket,
                                                       ticket_dynamic)
    env = {**dict(command.assignments), **env}
    scope = replace(scope, ticket=None if ticket_dynamic else ticket,
                    ticket_dynamic=ticket_dynamic)
    if not words:
        if scope.ctx.kind in ("host", "container") and _writes(command):
            return [scope.mutation(scope.ctx.targets, f"a redirection writes on {scope.ctx.where}")]
        return []
    head, args = words[0], words[1:]
    if head.dynamic:
        return [scope.unknown(f"the command name `{head.text}` is computed at run time, so "
                              "the guard cannot tell what it runs")]
    prog = _base(head.text)
    if prog == "busybox" and args:
        prog, args = _base(args[0].text), args[1:]
    fleet_cli = prog == "fleet-rollout" or (
        prog in PYTHONS and _texts(args[:2]) == ["-m", "fleet_rollout"])

    findings: list[Finding] = []
    if scope.ctx.kind == "local" and not fleet_cli:
        findings += _protected(prog, args, command, scope)

    if prog in DOCKER_CLIS:
        if "DOCKER_HOST" in env:              # same as `docker -H <host>`
            scope = replace(scope, ctx=_docker_host(env["DOCKER_HOST"], scope) or scope.ctx)
        return findings + _docker(args, command, scope, tail)
    if prog == "docker-compose":
        return findings + _compose(args, scope, tail)
    if prog == "ssh":
        return findings + _ssh(args, command, scope)
    if prog in ("scp", "rsync", "sftp"):
        return findings + _transfer(prog, args, scope)
    if fleet_cli:
        return findings + _fleet_cli(args[2:] if prog in PYTHONS else args, scope)
    if prog in SHELLS or prog in (".", "source"):
        return findings + _shell(prog, args, command, scope)
    if prog == "eval":
        if any(a.dynamic for a in args):
            return findings + [scope.unknown("eval of text computed at run time")]
        return findings + scope.classify(" ".join(_texts(args)))
    if prog == "find" and any(a.text in FIND_EXEC for a in args):
        findings += _find_exec(args, scope)
        return findings if scope.ctx.kind in ("local", "remote") or not _writes(command) else (
            findings + [scope.mutation(scope.ctx.targets, f"find writes on {scope.ctx.where}")])
    if "/" in head.text and scope.ctx.kind == "local":
        content = _read_script(head, scope.cwd)
        if content is not None and content.startswith("#!") and any(
                shell in content.splitlines()[0] for shell in SHELLS):
            return findings + scope.classify(content)
    if _is_read_only(prog, args, command):
        return findings
    if scope.ctx.kind in ("local", "remote"):
        if scope.ctx.kind == "local" and prog in LOCAL_ONLY:
            return findings
        named = scope.inv.mentioned(_texts(words))
        if named:
            findings.append(scope.mutation(named, f"`{prog}` is not a program the guard "
                                                  "understands, and it names fleet target(s)"))
        return findings
    return findings + [scope.mutation(scope.ctx.targets,
                                      f"`{prog}` would change {scope.ctx.where}")]


def _protected(prog: str, args: list[Word], command: Command, scope: Scope) -> list[Finding]:
    candidates = _texts(args) + [r.target.text for r in command.redirects
                                 if r.op not in ("<<", "<<-")]
    hit = next((text for text in candidates if scope.inv.protected_hit(text, scope.cwd)), None)
    if hit is None:
        return []
    git_read = prog == "git" and bool(args) and args[0].text in {"status", "diff", "log", "show",
                                                                 "blame"}
    if (_is_read_only(prog, args, command) or git_read) and not _writes(command):
        return []
    return [Finding("protected", f"`{hit}` is protected: change tickets, approvals, the ledger, "
                                 "the fleet file and the hook settings are changed by people, "
                                 "not by an agent session")]


def _find_exec(args: list[Word], scope: Scope) -> list[Finding]:
    findings: list[Finding] = []
    i = 0
    while i < len(args):
        if args[i].text in FIND_EXEC:
            inner: list[Word] = []
            i += 1
            while i < len(args) and args[i].text not in (";", "+"):
                word = args[i]
                inner.append(Word(word.text, True, word.quoted) if "{}" in word.text else word)
                i += 1
            if inner:
                findings += _command(Command(words=inner), scope)
        i += 1
    return findings


# -- docker ----------------------------------------------------------------------------


def _docker_host(word: Word, scope: Scope) -> Context | None:
    if word.dynamic:
        return None
    host = _host_of(word.text)
    targets = scope.inv.by_host(host)
    return Context("host", targets, f"fleet host {host}") if targets else None


def _docker(args: list[Word], command: Command, scope: Scope, tail: bool) -> list[Finding]:
    i = 0
    while i < len(args):
        text = args[i].text
        if not text.startswith("-") or text == "-":
            break
        if text in ("-H", "--host") and i + 1 < len(args):
            scope = replace(scope, ctx=_docker_host(args[i + 1], scope) or scope.ctx)
            i += 2
        elif text.startswith("--host="):
            host_word = Word(text.split("=", 1)[1], args[i].dynamic)
            scope = replace(scope, ctx=_docker_host(host_word, scope) or scope.ctx)
            i += 1
        else:
            i += 2 if text in DOCKER_GLOBAL_VALUE else 1
    rest = args[i:]
    if not rest:
        return []
    verb, rest = rest[0].text, rest[1:]
    if verb == "container" and rest:
        verb, rest = rest[0].text, rest[1:]
    ctx = scope.ctx
    on_fleet_host = ctx.kind in ("host", "container")
    if verb == "compose":
        return _compose(rest, scope, tail)
    if verb in DOCKER_MGMT:
        sub = rest[0].text if rest else ""
        if sub in DOCKER_MGMT_READ:
            return []
        named = scope.inv.mentioned(_texts(rest))
        if named:
            return [scope.mutation(named, f"docker {verb} {sub} names fleet target(s)")]
        return [scope.mutation(ctx.targets, f"docker {verb} {sub} on {ctx.where}")] \
            if on_fleet_host else []
    if verb in DOCKER_READ_ONLY:
        return []
    if verb == "exec":
        return _docker_exec(rest, command, scope)
    if verb == "cp":
        return _docker_cp(rest, scope)
    if verb in DOCKER_CREATE:
        named = scope.inv.mentioned(_texts(rest))
        if named:
            return [scope.mutation(named, f"docker {verb} names fleet target(s)")]
        return [scope.mutation(ctx.targets, f"docker {verb} on {ctx.where}")] \
            if on_fleet_host else []
    positional = [w for w in rest if not w.text.startswith("-")]
    if tail or any(w.dynamic for w in positional):
        return [scope.unknown(f"`docker {verb}` with a container name computed at run time; "
                              "name the containers explicitly")]
    named = frozenset().union(*(scope.inv.by_container(w.text) for w in positional))
    if named:
        return [scope.mutation(named, f"docker {verb} {' '.join(_texts(positional))}")]
    if on_fleet_host:
        return [scope.mutation(ctx.targets, f"docker {verb} on {ctx.where}")]
    return []


def _docker_exec(rest: list[Word], command: Command, scope: Scope) -> list[Finding]:
    i = 0
    while i < len(rest) and rest[i].text.startswith("-") and rest[i].text != "-":
        if rest[i].text == "--":
            i += 1
            break
        i += 2 if rest[i].text in EXEC_VALUE else 1
    if i >= len(rest):
        return []
    container, inner = rest[i], rest[i + 1:]
    if container.dynamic:
        return [scope.unknown("`docker exec` into a container computed at run time")]
    named = scope.inv.by_container(container.text)
    if named:
        ctx = Context("container", named,
                      f"container {container.text} ({', '.join(sorted(named))})")
    elif scope.ctx.kind == "host":
        ctx = Context("container", scope.ctx.targets,
                      f"container {container.text} on {scope.ctx.where}")
    else:
        return []
    if not inner:
        return []
    stdin = [r for r in command.redirects if r.op in ("<", "<<", "<<-", "<<<")]
    return _command(Command(words=list(inner), redirects=stdin), scope.within(ctx))


def _docker_cp(rest: list[Word], scope: Scope) -> list[Finding]:
    positional = [w for w in rest if not w.text.startswith("-")]
    if len(positional) < 2:
        return []
    if any(w.dynamic for w in positional):
        return [scope.unknown("`docker cp` with a path computed at run time")]
    dest = positional[-1].text
    head, sep, _ = dest.partition(":")
    if not sep or "/" in head or len(head) <= 1:
        return []                          # copying *out* of a container is a read
    named = scope.inv.by_container(head)
    if named:
        return [scope.mutation(named, f"docker cp into {head}")]
    if scope.ctx.kind in ("host", "container"):
        return [scope.mutation(scope.ctx.targets, f"docker cp into {head} on {scope.ctx.where}")]
    return []


def _compose(args: list[Word], scope: Scope, tail: bool) -> list[Finding]:
    rest = _skip_options(args, COMPOSE_VALUE)
    if not rest:
        return []
    verb, rest = rest[0].text, rest[1:]
    if verb in COMPOSE_READ_ONLY:
        return []
    services = [w for w in rest if not w.text.startswith("-")]
    if verb in ("exec", "run", "cp"):
        services = services[:1]
    if tail or any(w.dynamic for w in services):
        return [scope.unknown(f"`docker compose {verb}` with services computed at run time")]
    if not services:
        return [scope.unknown(f"`docker compose {verb}` without service names can touch every "
                              "container in the project; name the services explicitly")]
    named = frozenset().union(*(scope.inv.by_container(w.text) for w in services))
    if named:
        return [scope.mutation(named, f"docker compose {verb} {' '.join(_texts(services))}")]
    if scope.ctx.kind in ("host", "container"):
        return [scope.mutation(scope.ctx.targets, f"docker compose {verb} on {scope.ctx.where}")]
    return []


# -- ssh, scp, rsync -------------------------------------------------------------------


def _ssh(args: list[Word], command: Command, scope: Scope) -> list[Finding]:
    i = 0
    option_values: list[str] = []
    while i < len(args):
        text = args[i].text
        if text == "--":
            i += 1
            break
        if not text.startswith("-") or len(text) == 1:
            break
        step = 1
        for k, letter in enumerate(text[1:], start=1):
            if letter in SSH_VALUE:
                if text[k + 1:]:
                    option_values.append(text[k + 1:])
                elif i + 1 < len(args):
                    option_values.append(args[i + 1].text)
                    step = 2
                break
        i += step
    findings: list[Finding] = []
    named = scope.inv.mentioned(option_values)
    if named:
        findings.append(scope.mutation(named, "an ssh option names fleet target(s) "
                                              "(ProxyCommand and LocalCommand run commands)"))
    if i >= len(args):
        return findings
    host_word, remote = args[i], args[i + 1:]
    if host_word.dynamic:
        return findings + [scope.unknown("ssh to a host computed at run time")]
    host = _host_of(host_word.text)
    targets = scope.inv.by_host(host)
    ctx = (Context("host", targets, f"fleet host {host} ({', '.join(sorted(targets))})")
           if targets else Context("remote", frozenset(), f"host {host}"))
    inner = scope.within(ctx)
    if not remote:
        bodies = [r for r in command.redirects if r.op in ("<<", "<<-", "<<<")]
        if bodies:
            for r in bodies:
                if r.op == "<<<" and r.target.dynamic:
                    return findings + [scope.unknown("an ssh here-string computed at run time")]
                findings += inner.classify(r.heredoc if r.op != "<<<" else r.target.text)
            return findings
        if targets:
            findings.append(scope.mutation(targets, f"an interactive ssh session on fleet host "
                                                    f"{host} can change anything there"))
        return findings
    if any(w.dynamic for w in remote):
        if targets or scope.inv.mentioned(_texts(remote)):
            return findings + [scope.unknown(f"the remote command for {host} is computed at "
                                             "run time")]
        return findings
    return findings + inner.classify(" ".join(_texts(remote)))


def _transfer(prog: str, args: list[Word], scope: Scope) -> list[Finding]:
    value_opts = RSYNC_VALUE if prog == "rsync" else SCP_VALUE
    positional: list[Word] = []
    i = 0
    while i < len(args):
        text = args[i].text
        if text == "--":
            positional.extend(args[i + 1:])
            break
        if text.startswith("-") and text != "-":
            i += 2 if text in value_opts else 1
            continue
        positional.append(args[i])
        i += 1
    if prog == "sftp":
        if positional and not positional[0].dynamic:
            host = _host_of(positional[0].text)
            targets = scope.inv.by_host(host)
            if targets:
                return [scope.mutation(targets, f"an sftp session on fleet host {host}")]
        return []
    if len(positional) < 2:
        return []
    dest = positional[-1]
    if dest.dynamic:
        return [scope.unknown(f"`{prog}` to a destination computed at run time")]
    host = _remote_host(dest.text)
    targets = scope.inv.by_host(host) if host else frozenset()
    if targets:
        return [scope.mutation(targets, f"{prog} writes to fleet host {host} "
                                        f"({', '.join(sorted(targets))})")]
    return []


# -- shells and the fleet CLI ------------------------------------------------------------


def _shell(prog: str, args: list[Word], command: Command, scope: Scope) -> list[Finding]:
    script: Word | None = None
    i = 0
    if prog not in (".", "source"):
        while i < len(args):
            text = args[i].text
            if text == "--":
                i += 1
                break
            if text.startswith("-") and len(text) > 1 and not text.startswith("--"):
                if "c" in text[1:]:
                    if i + 1 >= len(args):
                        return [scope.unknown(f"`{prog} -c` without a script")]
                    script = args[i + 1]
                    break
                i += 1
            elif text.startswith(("--", "+")) and len(text) > 1:
                i += 1
            else:
                break
    if script is not None:
        if script.dynamic:
            return [scope.unknown("a shell script computed at run time")]
        return scope.classify(script.text)
    files = args[i:]
    if files:
        if scope.ctx.kind in ("host", "container"):
            return [scope.mutation(scope.ctx.targets,
                                   f"running a script file on {scope.ctx.where}")]
        content = _read_script(files[0], scope.cwd) if scope.ctx.kind == "local" else None
        if content is None:
            return [scope.unknown(f"cannot read the script `{files[0].text}` to inspect it")]
        return scope.classify(content)
    bodies = [r for r in command.redirects if r.op in ("<<", "<<-", "<<<")]
    if bodies:
        findings: list[Finding] = []
        for r in bodies:
            if r.op == "<<<" and r.target.dynamic:
                return [scope.unknown("a here-string computed at run time")]
            findings += scope.classify(r.heredoc if r.op != "<<<" else r.target.text)
        return findings
    if scope.ctx.kind in ("host", "container"):
        return [scope.mutation(scope.ctx.targets,
                               f"a shell on {scope.ctx.where} reading its script from stdin")]
    return [scope.unknown("a shell reading its script from a pipe or a file cannot be "
                          "inspected; run the commands directly")]


def _fleet_cli(args: list[Word], scope: Scope) -> list[Finding]:
    sub = args[0].text if args else ""
    if sub in FLEET_FORBIDDEN:
        return [Finding("forbidden", f"`fleet-rollout {sub}`: {FLEET_FORBIDDEN[sub]}")]
    if sub not in ("apply", "rollback", "unlock"):
        return []                          # read-only verbs; unknown ones fail in the CLI
    rest = args[1:]
    ticket, ticket_dynamic = scope.ticket, scope.ticket_dynamic
    names: list[str] | None = None
    include_customer = False
    positional: list[Word] = []
    i = 0
    while i < len(rest):
        word, text = rest[i], rest[i].text
        value = rest[i + 1] if i + 1 < len(rest) else None
        if text in ("--ticket", "--targets", "--target") and value is not None:
            if value.dynamic:
                return [scope.unknown(f"`fleet-rollout {sub} {text}` computed at run time")]
            if text == "--ticket":
                ticket, ticket_dynamic = value.text, False
            else:
                names = (names or []) + [n for n in value.text.split(",") if n]
            i += 2
            continue
        if text in FLEET_CLI_VALUE_OPTIONS:
            i += 2                          # e.g. --fleet fleet.yaml: the value is no target
            continue
        if text.startswith("--ticket="):
            ticket, ticket_dynamic = text.split("=", 1)[1], word.dynamic
        elif text.startswith(("--targets=", "--target=")):
            names = (names or []) + [n for n in text.split("=", 1)[1].split(",") if n]
        elif text == "--include-customer":
            include_customer = True
        elif not text.startswith("-"):
            positional.append(word)
        i += 1
    if sub == "unlock":                     # no target: the state directory's own lock
        if positional and positional[0].dynamic:
            return [scope.unknown("`fleet-rollout unlock` of a target computed at run time")]
        names = [positional[0].text] if positional else []
    if names is None:
        names = [t.name for t in scope.inv.targets.values()
                 if include_customer or not t.customer_owned]
    targets = frozenset(n for n in names if n in scope.inv.targets)
    return [Finding("mutation", f"fleet-rollout {sub}", targets,
                    None if ticket_dynamic else ticket, ticket_dynamic)]
