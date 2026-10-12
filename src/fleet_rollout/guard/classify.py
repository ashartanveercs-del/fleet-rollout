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
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
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
# The options of every fleet-rollout verb that touches targets, and whether each takes a
# value. The CLI refuses abbreviations, so the guard reads exactly what the CLI will.
FLEET_CLI_OPTIONS: Mapping[str, Mapping[str, bool]] = {
    "apply": {"--fleet": True, "--state": True, "--targets": True, "--canary": True,
              "--include-customer": False, "--ticket": True, "--operator": True,
              "--allow-drift": False, "--bake": True},
    "rollback": {"--fleet": True, "--state": True, "--target": True, "--ticket": True,
                 "--operator": True, "--include-customer": False},
    "unlock": {"--fleet": True, "--state": True, "--run-lock": False, "--ticket": True,
               "--operator": True},
}
FLEET_CLI_MODULES = frozenset({"fleet_rollout", "fleet_rollout.cli", "fleet_rollout.__main__"})
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
    """What the guard knows about the fleet: names, containers, hosts, protected paths, and
    the fleet file it protects (the only one a `fleet-rollout` mutation may use)."""

    def __init__(self, fleet: Fleet | None, protected: Iterable[Path] = (), *,
                 fleet_file: Path | None = None) -> None:
        self.fleet = fleet
        self.fleet_file = fleet_file
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
    # Every directory the shell may be in when a command runs: the payload's cwd, plus
    # each place a `cd` in the script may have moved to. The guard does not model control
    # flow, so it treats them all as possible (`cwd_unknown`: a move computed at run time).
    cwds: tuple[Path, ...]
    ctx: Context = LOCAL
    ticket: str | None = None
    ticket_dynamic: bool = False
    depth: int = 0
    cwd_unknown: bool = False

    @property
    def cwd(self) -> Path:
        return self.cwds[0]

    def mutation(self, targets: Iterable[str], reason: str) -> Finding:
        return Finding("mutation", reason, frozenset(targets), self.ticket, self.ticket_dynamic)

    def unknown(self, reason: str) -> Finding:
        return Finding("unknown", reason)

    def within(self, ctx: Context) -> Scope:
        return replace(self, ctx=ctx, depth=self.depth + 1)

    def classify(self, script: str) -> list[Finding]:
        return _classify(script, replace(self, depth=self.depth + 1))

    def locate(self, text: str) -> list[Path] | None:
        """Where a local path would point from every directory the shell may be in; None
        when a relative path follows a change of directory computed at run time."""
        path = Path(os.path.expanduser(text))
        if path.is_absolute():
            return [path]
        if self.cwd_unknown:
            return None
        return [Path(os.path.normpath(cwd / path)) for cwd in self.cwds]


def classify(script: str, inv: Inventory, *, cwd: Path, ctx: Context = LOCAL,
             ticket: str | None = None, ticket_dynamic: bool = False,
             depth: int = 0) -> list[Finding]:
    """Findings for every command in `script`. Raises ShellSyntaxError if unparseable."""
    return _classify(script, Scope(inv, (Path(cwd),), ctx, ticket, ticket_dynamic, depth))


def _classify(script: str, scope: Scope) -> list[Finding]:
    commands = parse(script, depth=scope.depth)
    if scope.ctx.kind == "local":
        scope = _follow_cd(commands, scope)
    findings: list[Finding] = []
    for command in commands:
        findings.extend(_command(command, scope))
    return findings


def only_reads(script: str) -> bool:
    """True if every command in `script` is a plain read (used when the fleet is unknown)."""
    for command in parse(script):
        run = _unwrap(list(command.words), None, False)
        if run.problem or run.chdir or run.cwd_unknown:
            return False
        if not run.words:
            if _writes(command):
                return False
            continue
        words = run.words
        if words[0].dynamic or not _is_read_only(_base(words[0].text), words[1:], command):
            return False
    return True


# -- the working directory ---------------------------------------------------------------

MAX_CWDS = 16


def _follow_cd(commands: Sequence[Command], scope: Scope, depth: int = 0) -> Scope:
    """Add every directory `cd`/`pushd` may move the shell into, wherever it appears in the
    script (a subshell's `cd` is counted too: over-approximating is the safe direction).
    A sourced or eval'd script runs in the same shell, so its moves count as well."""
    cwds, unknown = list(scope.cwds), scope.cwd_unknown
    cdpath = bool(os.environ.get("CDPATH")) or any(
        "CDPATH" in w.text for c in commands for w in c.words) or any(
        name == "CDPATH" for c in commands for name, _ in c.assignments)
    for command in commands:
        run = _unwrap(list(command.words), None, False)
        if not run.words or run.words[0].dynamic:
            continue
        name, args = _base(run.words[0].text), run.words[1:]
        if name in ("cd", "pushd", "popd", "chdir"):
            operands = [a for a in args if not re.fullmatch(r"-[LPe@n]+|[+-]\d+", a.text)]
            operands = operands[1:] if operands and operands[0].text == "--" else operands
            if name == "popd" or (name == "pushd" and not operands):
                continue                    # back to a directory already counted
            target = operands[0] if operands else Word("~")
            if target.dynamic or target.text == "-":
                unknown = True
                continue
            path = Path(os.path.expanduser(target.text))
            relative = not path.is_absolute()
            if relative and cdpath and not target.text.startswith("."):
                unknown = True              # CDPATH may resolve it anywhere
                continue
            for cwd in list(cwds) if relative else [None]:
                moved = Path(os.path.normpath(cwd / path if cwd is not None else path))
                if moved not in cwds:
                    cwds.append(moved)
        elif name in (".", "source") and args and depth < 4:
            for text in _read_script(args[0], replace(scope, cwds=tuple(cwds))) or ():
                with contextlib.suppress(ValueError):          # ShellSyntaxError
                    inner = _follow_cd(parse(text), replace(scope, cwds=tuple(cwds)), depth + 1)
                    cwds.extend(c for c in inner.cwds if c not in cwds)
                    unknown = unknown or inner.cwd_unknown
        elif name == "eval" and args and not any(a.dynamic for a in args) and depth < 4:
            with contextlib.suppress(ValueError):
                inner = _follow_cd(parse(" ".join(_texts(args))), replace(scope, cwds=tuple(cwds)),
                                   depth + 1)
                cwds.extend(c for c in inner.cwds if c not in cwds)
                unknown = unknown or inner.cwd_unknown
    if len(cwds) > MAX_CWDS:
        unknown = True
    return replace(scope, cwds=tuple(cwds), cwd_unknown=unknown)


def _chdir(scope: Scope, run: _Run) -> Scope:
    """The scope of one command that a wrapper runs in another directory (`env -C`)."""
    if run.cwd_unknown or any(w.dynamic for w in run.chdir):
        return replace(scope, cwd_unknown=True)
    cwds = scope.cwds
    for word in run.chdir:
        path = Path(os.path.expanduser(word.text))
        cwds = tuple(Path(os.path.normpath(c / path)) for c in cwds)
    return replace(scope, cwds=tuple(dict.fromkeys(cwds)))


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


Options = list[tuple[str, Word | None]]


def _getopt(words: list[Word], short: str, longs: Mapping[str, str]
            ) -> tuple[Options, list[Word], str | None]:
    """Leading options, read the way GNU getopt_long reads a wrapper's command line: short
    flags may be clustered (`-iC dir`, `-Cdir`), long ones take `=value` or the next word,
    and a long option may be abbreviated to any unambiguous prefix (`--ch` is `--chdir`).
    Options stop at the first operand. `short` is a getopt string ("C:iS:u:", `::` for an
    optional attached value); `longs` maps names to "", ":" or "::" the same way.
    Returns the options, the remaining words and, for a command line the wrapper itself
    would refuse, the reason."""
    spec: dict[str, str] = {}
    letters = short.lstrip("+")
    k = 0
    while k < len(letters):
        end = k + 1
        while end < len(letters) and letters[end] == ":":
            end += 1
        spec[letters[k]] = letters[k + 1:end]
        k = end
    options: Options = []
    i = 0
    while i < len(words):
        word, text = words[i], words[i].text
        if text == "--":
            return options, words[i + 1:], None
        if text.startswith("--"):
            name, eq, attached = text[2:].partition("=")
            matches = [name] if name in longs else [n for n in longs if n.startswith(name)]
            if len(matches) != 1:
                return options, words[i:], f"unrecognized or ambiguous option {text.split('=')[0]}"
            kind = longs[matches[0]]
            value: Word | None = None
            if eq:
                if not kind:
                    return options, words[i:], f"{text} does not take a value"
                value = Word(attached, word.dynamic, word.quoted)
            elif kind == ":":
                if i + 1 >= len(words):
                    return options, [], f"{text} needs a value"
                i += 1
                value = words[i]
            options.append(("--" + matches[0], value))
            i += 1
            continue
        if not text.startswith("-") or text == "-":
            break
        for k in range(1, len(text)):
            letter = text[k]
            if letter not in spec:
                return options, words[i:], f"unrecognized option -{letter}"
            if not spec[letter]:
                options.append(("-" + letter, None))
                continue
            rest = text[k + 1:]
            if rest:
                options.append(("-" + letter, Word(rest, word.dynamic, word.quoted)))
            elif spec[letter] == ":":
                if i + 1 >= len(words):
                    return options, [], f"-{letter} needs a value"
                i += 1
                options.append(("-" + letter, words[i]))
            else:
                options.append(("-" + letter, None))
            break
        i += 1
    return options, words[i:], None


# Programs that run another command: (getopt string, long options). See `_unwrap`.
_WRAPPERS: Mapping[str, tuple[str, Mapping[str, str]]] = {
    "sudo": ("+Aa:BbC:c:D:Eeg:Hh::iKklNnPp:R:r:SsT:t:U:u:Vv",
             {"askpass": "", "auth-type": ":", "background": "", "bell": "", "close-from": ":",
              "login-class": ":", "chdir": ":", "preserve-env": "::", "edit": "", "group": ":",
              "set-home": "", "help": "", "host": ":", "login": "", "remove-timestamp": "",
              "reset-timestamp": "", "list": "", "no-update": "", "non-interactive": "",
              "preserve-groups": "", "prompt": ":", "chroot": ":", "role": ":", "stdin": "",
              "shell": "", "type": ":", "command-timeout": ":", "other-user": ":",
              "user": ":", "version": "", "validate": ""}),
    "doas": ("+C:Lnsu:", {}),
    "env": ("+C:iS:u:v0", {"chdir": ":", "ignore-environment": "", "split-string": ":",
                           "unset": ":", "debug": "", "null": "", "block-signal": "::",
                           "default-signal": "::", "ignore-signal": "::",
                           "list-signal-handling": "", "help": "", "version": ""}),
    "nohup": ("+", {"help": "", "version": ""}),
    "command": ("+pvV", {}),
    "builtin": ("+", {}),
    "exec": ("+cla:", {}),
    "setsid": ("+cfwhV", {"ctty": "", "fork": "", "wait": "", "help": "", "version": ""}),
    "chronic": ("+ev", {}),
    "unbuffer": ("+p", {}),
    "stdbuf": ("+i:o:e:", {"input": ":", "output": ":", "error": ":", "help": "",
                           "version": ""}),
    "nice": ("+n:", {"adjustment": ":", "help": "", "version": ""}),
    "ionice": ("+c:n:p:P:tu:hV", {"class": ":", "classdata": ":", "pid": ":", "pgid": ":",
                                  "ignore": "", "uid": ":", "help": "", "version": ""}),
    "timeout": ("+fk:ps:v", {"foreground": "", "kill-after": ":", "preserve-status": "",
                             "signal": ":", "verbose": "", "help": "", "version": ""}),
    "watch": ("+bcCd::eghn:pq:rtvwx", {"beep": "", "color": "", "no-color": "",
                                       "differences": "::", "errexit": "", "chgexit": "",
                                       "equexit": ":", "interval": ":", "precise": "",
                                       "no-rerun": "", "no-title": "", "no-wrap": "",
                                       "exec": "", "help": "", "version": ""}),
    "xargs": ("+0a:E:e::hi::I:l::L:n:prs:txP:d:",
              {"null": "", "arg-file": ":", "delimiter": ":", "eof": "::", "replace": "::",
               "max-lines": "::", "max-args": ":", "open-tty": "", "interactive": "",
               "no-run-if-empty": "", "max-chars": ":", "verbose": "", "show-limits": "",
               "exit": "", "max-procs": ":", "process-slot-var": ":", "help": "",
               "version": ""}),
}
_CHDIR_OPTIONS = frozenset({("env", "-C"), ("env", "--chdir"), ("sudo", "-D"),
                            ("sudo", "--chdir")})


@dataclass
class _Run:
    """A simple command with its wrappers peeled off (see `_unwrap`)."""
    words: list[Word]
    tail_dynamic: bool = False          # xargs appends arguments at run time
    ticket: str | None = None
    ticket_dynamic: bool = False
    env: dict[str, Word] = field(default_factory=dict)
    chdir: list[Word] = field(default_factory=list)   # env -C / sudo -D, outermost first
    cwd_unknown: bool = False           # sudo -i: a login shell starts in a home directory
    problem: str | None = None          # a wrapper command line the guard cannot read


def _unwrap(words: list[Word], ticket: str | None, ticket_dynamic: bool) -> _Run:
    """Strip shell keywords and wrapper programs (sudo, env, timeout, xargs, ...), keeping
    what they change about the command they run: the change ticket and other variables
    they assign, the directory they run it in, and arguments appended at run time."""
    run = _Run(list(words), ticket=ticket, ticket_dynamic=ticket_dynamic)
    while run.words:
        head = run.words[0]
        name = _base(head.text)
        if head.text in RESERVED and not head.quoted:
            run.words = run.words[1:]
            continue
        if name in HEADERS:
            run.words = []
            break
        if head.dynamic or name not in _WRAPPERS:
            break
        args = run.words[1:]
        if name == "nice" and args and re.fullmatch(r"-[-+]?\d+", args[0].text):
            args = args[1:]                 # the historical `nice -10 cmd`
        short, longs = _WRAPPERS[name]
        options, rest, problem = _getopt(args, short, longs)
        if problem:
            run.problem = f"`{name}`: {problem}"
            break
        given = {opt for opt, _ in options}
        run.chdir += [value for opt, value in options
                      if (name, opt) in _CHDIR_OPTIONS and value is not None]
        if name == "env" and rest and rest[0].text == "-":
            rest = rest[1:]                 # `env -` is `env -i`
        if name in ("env", "sudo"):
            while rest and (match := _ASSIGN.match(rest[0].text)):
                value = Word(rest[0].text[match.end():], rest[0].dynamic, rest[0].quoted)
                run.env[match.group(1)] = value
                if match.group(1) == "CHANGE_TICKET":
                    run.ticket, run.ticket_dynamic = value.text, value.dynamic
                rest = rest[1:]
        if name == "sudo":
            if given & {"-R", "--chroot"}:
                run.problem = "`sudo --chroot` runs the command against another root directory"
                break
            if given & {"-i", "--login"}:
                run.cwd_unknown = True
            if given & {"-e", "--edit"}:
                rest = [Word("sudoedit"), *rest]
            elif not rest and given & {"-s", "--shell", "-i", "--login"}:
                rest = [Word("sh")]         # an interactive shell, reading from stdin
        if name == "doas" and not rest and "-s" in given:
            rest = [Word("sh")]
        if name == "timeout":
            rest = rest[1:]                 # the duration
        if name == "xargs":
            run.tail_dynamic = True
        run.words = rest
    return run


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


def _read_script(word: Word, scope: Scope) -> list[str] | None:
    """The text of a local script as the shell would find it from each directory it may be
    in. None if it cannot be read, or its location depends on a run-time `cd`."""
    if word.dynamic:
        return None
    places = scope.locate(word.text)
    if places is None:
        return None
    texts = []
    for path in places:
        try:
            if path.stat().st_size > MAX_SCRIPT_BYTES:
                return None
            texts.append(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            continue                        # not there, so it cannot run from there either
        except (OSError, UnicodeDecodeError):
            return None
    return texts or None


def _is_shell_script(text: str) -> bool:
    return text.startswith("#!") and any(shell in text.splitlines()[0] for shell in SHELLS)


def _python_runs(args: list[Word]) -> tuple[str, Word | None, list[Word]]:
    """What a python command line runs: ("module" | "code" | "script" | "stdin", the
    module, code or script word, the arguments after it)."""
    i = 0
    while i < len(args):
        word, text = args[i], args[i].text
        if text == "-" or not text.startswith("-"):
            return ("stdin", None, args[i + 1:]) if text == "-" else ("script", word, args[i + 1:])
        if text == "--":
            nxt = args[i + 1] if i + 1 < len(args) else None
            return ("script", nxt, args[i + 2:]) if nxt else ("stdin", None, [])
        if text.startswith("--"):
            i += 2 if text == "--check-hash-based-pycs" else 1
            continue
        for k in range(1, len(text)):
            letter = text[k]
            if letter in "cmXW":
                attached = text[k + 1:]
                value = (Word(attached, word.dynamic, word.quoted) if attached
                         else args[i + 1] if i + 1 < len(args) else None)
                after = args[i + 1:] if attached else args[i + 2:]
                if letter in "cm":
                    return ("code" if letter == "c" else "module"), value, after
                i += 0 if attached else 1
                break
        i += 1
    return "stdin", None, []


# -- one simple command --------------------------------------------------------------------


def _command(command: Command, scope: Scope) -> list[Finding]:
    ticket, ticket_dynamic = scope.ticket, scope.ticket_dynamic
    for name, value in command.assignments:
        if name == "CHANGE_TICKET":
            ticket, ticket_dynamic = value.text, value.dynamic
    run = _unwrap(list(command.words), ticket, ticket_dynamic)
    if run.problem:
        return [scope.unknown(f"{run.problem}, so the guard cannot tell what it runs")]
    words, tail, env = run.words, run.tail_dynamic, {**dict(command.assignments), **run.env}
    scope = replace(scope, ticket=None if run.ticket_dynamic else run.ticket,
                    ticket_dynamic=run.ticket_dynamic)
    if run.chdir or run.cwd_unknown:
        scope = _chdir(scope, run)
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
    fleet_args: list[Word] | None = args if prog == "fleet-rollout" else None
    if prog in PYTHONS:
        kind, what, after = _python_runs(args)
        if kind == "module" and what is not None and what.dynamic:
            return [scope.unknown("the module python runs is computed at run time")]
        if kind == "module" and what is not None and what.text in FLEET_CLI_MODULES:
            fleet_args = after
        elif kind == "code" and what is not None and "fleet_rollout" in what.text:
            return [scope.unknown("python code that drives fleet_rollout directly cannot be "
                                  "inspected; run the `fleet-rollout` CLI instead")]

    findings: list[Finding] = []
    if scope.ctx.kind == "local" and fleet_args is None:
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
    if fleet_args is not None:
        if tail:
            return findings + [scope.unknown("`fleet-rollout` with arguments appended at run "
                                             "time")]
        return findings + _fleet_cli(fleet_args, scope)
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
        scripts = [text for text in _read_script(head, scope) or () if _is_shell_script(text)]
        if scripts:
            return findings + [f for text in scripts for f in scope.classify(text)]
    if _is_read_only(prog, args, command):
        return findings
    if scope.ctx.kind in ("local", "remote"):
        if scope.ctx.kind == "local" and prog in LOCAL_ONLY:
            return findings
        if any(_base(w.text) == "fleet-rollout" for w in args):
            return findings + [scope.unknown(
                f"`{prog}` runs fleet-rollout in a way the guard cannot inspect; run "
                "`fleet-rollout ...` directly")]
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
            # -execdir/-okdir run the command in the directory of each match.
            inner_scope = (replace(scope, cwd_unknown=True)
                           if args[i].text in ("-execdir", "-okdir") else scope)
            inner: list[Word] = []
            i += 1
            while i < len(args) and args[i].text not in (";", "+"):
                word = args[i]
                inner.append(Word(word.text, True, word.quoted) if "{}" in word.text else word)
                i += 1
            if inner:
                findings += _command(Command(words=inner), inner_scope)
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
        texts = _read_script(files[0], scope) if scope.ctx.kind == "local" else None
        if texts is None:
            where = (" (it is relative to a directory computed at run time)"
                     if scope.cwd_unknown else "")
            return [scope.unknown(f"cannot read the script `{files[0].text}` to inspect "
                                  f"it{where}")]
        return [f for text in texts for f in scope.classify(text)]
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


def _same_file(a: Path, b: Path) -> bool:
    with contextlib.suppress(OSError):
        if os.path.exists(a) and os.path.exists(b):
            return os.path.samefile(a, b)
    return (os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b)))


def _fleet_cli(args: list[Word], scope: Scope) -> list[Finding]:
    """`fleet-rollout <verb> ...`, read the way its argparse parser reads it. A verb that
    touches targets must use the fleet file the guard protects and that fleet's state
    directory: anything else could name targets, tickets, approvals or halts of its own."""
    if not args:
        return []
    if args[0].dynamic:
        return [scope.unknown("the `fleet-rollout` subcommand is computed at run time")]
    sub = args[0].text
    if sub in ("-h", "--help", "--version"):
        return []                           # prints and exits
    if sub.startswith("-"):
        return [scope.unknown(f"`fleet-rollout {sub}` is not an option the guard knows")]
    if sub in FLEET_FORBIDDEN:
        return [Finding("forbidden", f"`fleet-rollout {sub}`: {FLEET_FORBIDDEN[sub]}")]
    known = FLEET_CLI_OPTIONS.get(sub)
    if known is None:
        return []                           # read-only verbs; unknown ones fail in the CLI
    given: dict[str, Word | None] = {}      # the last occurrence wins, as in argparse
    positional: list[Word] = []
    rest = args[1:]
    i = 0
    while i < len(rest):
        word, text = rest[i], rest[i].text
        if text == "--":
            positional += rest[i + 1:]
            break
        if text in ("-h", "--help"):
            return []
        if text.startswith("-") and text != "-":
            name, eq, attached = text.partition("=")
            if name not in known:
                return [scope.unknown(f"`fleet-rollout {sub} {name}` is not an option the guard "
                                      "knows; spell options out in full")]
            if not known[name]:
                if eq:
                    return []               # argparse refuses a value for a flag
                given[name] = None
            else:
                if eq:
                    value = Word(attached, word.dynamic, word.quoted)
                elif i + 1 < len(rest):
                    i += 1
                    value = rest[i]
                else:
                    return []               # argparse: expected one argument
                if value.dynamic:
                    return [scope.unknown(f"`fleet-rollout {sub} {name}` computed at run time")]
                given[name] = value
        else:
            positional.append(word)
        i += 1
    pinned = _fleet_cli_pinned(sub, given, scope)
    if pinned:
        return [pinned]
    if sub == "unlock":                     # no target: the state directory's own lock
        if positional and positional[0].dynamic:
            return [scope.unknown("`fleet-rollout unlock` of a target computed at run time")]
        names = [positional[0].text] if positional else []
    elif sub == "rollback":
        target = given.get("--target")
        names = [target.text] if target is not None else []
    else:
        raw = given.get("--targets")
        names = ([n.strip() for n in raw.text.split(",") if n.strip()]
                 if raw is not None and raw.text else
                 [t.name for t in scope.inv.targets.values()
                  if "--include-customer" in given or not t.customer_owned])
    strangers = sorted(n for n in names if n not in scope.inv.targets)
    if strangers:
        return [scope.unknown(f"`fleet-rollout {sub}` names {', '.join(strangers)}, which the "
                              "fleet file the guard protects does not list")]
    ticket_word = given.get("--ticket")
    ticket, ticket_dynamic = ((ticket_word.text, False) if ticket_word is not None
                              else (scope.ticket, scope.ticket_dynamic))
    return [Finding("mutation", f"fleet-rollout {sub}", frozenset(names),
                    None if ticket_dynamic else ticket, ticket_dynamic)]


def _fleet_cli_pinned(sub: str, given: Mapping[str, Word | None], scope: Scope
                      ) -> Finding | None:
    inv = scope.inv
    if scope.ctx.kind != "local":
        return scope.unknown(f"`fleet-rollout {sub}` on {scope.ctx.where} would read a fleet "
                             "file the guard cannot see; run it from this machine")
    if inv.fleet is None or inv.fleet_file is None:
        return scope.unknown("the guard does not know which fleet file it protects")
    fleet_word = given.get("--fleet") or Word("fleet.yaml")
    places = scope.locate(fleet_word.text)
    if places is None:
        return scope.unknown(f"`fleet-rollout {sub}` reads the fleet file `{fleet_word.text}` "
                             "from a working directory computed at run time; pass --fleet "
                             f"{inv.fleet_file}")
    stray = next((p for p in places if not _same_file(p, inv.fleet_file)), None)
    if stray is not None:
        return scope.unknown(f"`fleet-rollout {sub}` would read the fleet file {stray}, not "
                             f"{inv.fleet_file}, the one the guard protects; another fleet "
                             "file can name its own targets, tickets and state directory")
    state_word = given.get("--state")
    if state_word is not None:
        places = scope.locate(state_word.text)
        if places is None or any(not _same_file(p, inv.fleet.state_dir) for p in places):
            return Finding("forbidden", f"`fleet-rollout {sub} --state {state_word.text}`: "
                                        "approvals, halts and the ledger live in the state "
                                        f"directory {inv.fleet.state_dir}; a {sub} pointed at "
                                        "another state directory would skip them")
    return None
