"""A small POSIX-shell lexer: enough of the grammar to find every command a script runs.

It returns a flat list of simple commands, including the ones hidden in `$(...)`,
backticks, `<(...)`, subshells, groups and unquoted heredoc bodies. Each word keeps
whether its runtime value is knowable: a word containing an expansion (`$X`, `${X}`,
`$(...)`), a glob (`*?[`) or a brace expansion is marked `dynamic`, because the guard
cannot tell which container it will name.

It is deliberately strict. Anything it cannot lex (an unterminated quote, an unbalanced
substitution, runaway nesting) raises `ShellSyntaxError`, and the guard turns that into
a denial: a command the guard cannot read is a command the guard cannot allow.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MAX_DEPTH = 16

_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_REDIRECTS = ("&>>", "<<<", "<<-", "<<", ">>", ">&", "<&", "&>", "<>", ">|", ">", "<")
_OPERATORS = ("&&", "||", ";;", "|&", "|", "&", ";", "(", ")")
_GLOB = frozenset("*?[")


class ShellSyntaxError(ValueError):
    """The script cannot be lexed reliably."""


@dataclass(frozen=True)
class Word:
    text: str
    dynamic: bool = False
    quoted: bool = False


@dataclass
class Redirect:
    op: str
    target: Word
    heredoc: str | None = None


@dataclass
class Command:
    words: list[Word] = field(default_factory=list)
    assignments: list[tuple[str, Word]] = field(default_factory=list)
    redirects: list[Redirect] = field(default_factory=list)

    @property
    def argv(self) -> list[str]:
        return [w.text for w in self.words]


def parse(script: str, *, depth: int = 0) -> list[Command]:
    if depth > MAX_DEPTH:
        raise ShellSyntaxError("command substitutions are nested too deeply")
    return _Lexer(script, depth).run()


class _Lexer:
    def __init__(self, script: str, depth: int) -> None:
        self.s = script
        self.n = len(script)
        self.depth = depth
        self.i = 0
        self.out: list[Command] = []
        self.cmd = Command()
        self.nested: list[Command] = []
        self.pending_redirect: str | None = None
        self.heredocs: list[tuple[Redirect, str, bool, bool]] = []
        self._reset_word()

    # -- word state -----------------------------------------------------------------

    def _reset_word(self) -> None:
        self.buf: list[str] = []
        self.started = False
        self.dynamic = False
        self.quoted = False
        self.first_quote: int | None = None
        self.unquoted: list[str] = []

    def _mark_quote(self) -> None:
        self.quoted = True
        if self.first_quote is None:
            self.first_quote = len("".join(self.buf))
        self.started = True

    def _end_word(self) -> None:
        if not self.started:
            return
        text = "".join(self.buf)
        unquoted = "".join(self.unquoted)
        dynamic = self.dynamic or ("{" in unquoted and "}" in unquoted
                                   and ("," in unquoted or ".." in unquoted))
        word = Word(text, dynamic, self.quoted)
        first_quote = self.first_quote
        self._reset_word()
        if self.pending_redirect:
            redirect = Redirect(self.pending_redirect, word)
            self.cmd.redirects.append(redirect)
            if redirect.op in ("<<", "<<-"):
                self.heredocs.append((redirect, word.text, redirect.op == "<<-", word.quoted))
            self.pending_redirect = None
            return
        if not self.cmd.words and not word.quoted and text in ("{", "}"):
            return  # group delimiters
        match = _ASSIGN.match(text)
        if (not self.cmd.words and match
                and (first_quote is None or first_quote >= match.end())):
            self.cmd.assignments.append(
                (text[:match.end() - 1], Word(text[match.end():], dynamic, word.quoted)))
            return
        self.cmd.words.append(word)

    def _end_command(self) -> None:
        if self.pending_redirect:
            raise ShellSyntaxError(f"redirection {self.pending_redirect!r} has no target")
        if self.cmd.words or self.cmd.assignments or self.cmd.redirects:
            self.out.append(self.cmd)
        self.out.extend(self.nested)            # substitutions run too
        self.cmd = Command()
        self.nested = []

    # -- the main loop ---------------------------------------------------------------

    def run(self) -> list[Command]:
        s = self.s
        while self.i < self.n:
            c = s[self.i]
            if c in " \t":
                self._end_word()
                self.i += 1
            elif c == "\\":
                if s.startswith("\\\n", self.i):
                    self.i += 2
                    continue
                if self.i + 1 >= self.n:
                    raise ShellSyntaxError("trailing backslash")
                self._mark_quote()
                self.buf.append(s[self.i + 1])
                self.i += 2
            elif c == "\n":
                self._end_word()
                self._end_command()
                self.i += 1
                self._read_heredocs()
            elif c == "#" and not self.started:
                end = s.find("\n", self.i)
                self.i = self.n if end < 0 else end
            elif c == "'":
                end = s.find("'", self.i + 1)
                if end < 0:
                    raise ShellSyntaxError("unterminated single quote")
                self._mark_quote()
                self.buf.append(s[self.i + 1:end])
                self.i = end + 1
            elif c == '"':
                self._double_quote()
            elif c == "$":
                self._dollar(in_double=False)
            elif c == "`":
                self._backtick()
            elif c in "<>" and s.startswith("(", self.i + 1) and not self.started:
                inner, end = self._balanced(self.i + 2, "(", ")")
                self._substitute(inner)             # process substitution
                self.buf.append(s[self.i:end + 1])
                self.started = self.dynamic = True
                self.i = end + 1
            elif op := self._match(_REDIRECTS):
                fd_prefix = (self.started and not self.quoted and op[0] in "<>"
                             and "".join(self.buf).isdigit())
                if fd_prefix:
                    self._reset_word()
                else:
                    self._end_word()
                if self.pending_redirect:
                    raise ShellSyntaxError(f"redirection {self.pending_redirect!r} has no "
                                           "target")
                self.pending_redirect = op
                self.i += len(op)
            elif op := self._match(_OPERATORS):
                self._end_word()
                self._end_command()
                self.i += len(op)
            else:
                if c in _GLOB:
                    self.dynamic = True
                self.buf.append(c)
                self.unquoted.append(c)
                self.started = True
                self.i += 1
        self._end_word()
        self._end_command()
        for redirect, *_ in self.heredocs:      # heredoc at end of input: empty body
            redirect.heredoc = ""
        return self.out

    def _match(self, options: tuple[str, ...]) -> str | None:
        return next((op for op in options if self.s.startswith(op, self.i)), None)

    # -- quoting and expansions ------------------------------------------------------

    def _double_quote(self) -> None:
        self._mark_quote()
        s = self.s
        i = self.i + 1
        while True:
            if i >= self.n:
                raise ShellSyntaxError("unterminated double quote")
            c = s[i]
            if c == '"':
                self.i = i + 1
                return
            if c == "\\" and i + 1 < self.n and s[i + 1] in '$`"\\\n':
                if s[i + 1] != "\n":
                    self.buf.append(s[i + 1])
                i += 2
            elif c in "$`":
                self.i = i
                if c == "$":
                    self._dollar(in_double=True)
                else:
                    self._backtick()
                i = self.i
            else:
                self.buf.append(c)
                i += 1

    def _dollar(self, *, in_double: bool) -> None:
        s, i = self.s, self.i
        nxt = s[i + 1] if i + 1 < self.n else ""
        self.started = True
        if nxt == "(":
            inner, end = self._balanced(i + 2, "(", ")")
            if inner.startswith("(") and inner.endswith(")"):
                self._scan_expansions(inner)        # $(( arithmetic ))
            else:
                self._substitute(inner)
            self.buf.append(s[i:end + 1])
            self.dynamic = True
            self.i = end + 1
        elif nxt == "{":
            inner, end = self._balanced(i + 2, "{", "}")
            self._scan_expansions(inner)
            self.buf.append(s[i:end + 1])
            self.dynamic = True
            self.i = end + 1
        elif nxt and (nxt.isalnum() or nxt in "_@*#?$!-"):
            j = i + 1
            if nxt.isalpha() or nxt == "_":
                while j < self.n and (s[j].isalnum() or s[j] == "_"):
                    j += 1
            else:
                j += 1
            self.buf.append(s[i:j])
            self.dynamic = True
            self.i = j
        elif nxt == "'" and not in_double:          # $'...' ANSI-C quoting
            j = i + 2
            while j < self.n and s[j] != "'":
                j += 2 if s[j] == "\\" else 1
            if j >= self.n:
                raise ShellSyntaxError("unterminated $'...' quote")
            self._mark_quote()
            self.buf.append(s[i + 2:j])
            self.i = j + 1
        elif nxt == '"' and not in_double:          # $"..." locale string
            self.i = i + 1
            self._double_quote()
        else:
            self.buf.append("$")
            self.i = i + 1

    def _backtick(self) -> None:
        s = self.s
        j = self.i + 1
        parts = []
        while j < self.n and s[j] != "`":
            if s[j] == "\\" and j + 1 < self.n:
                parts.append(s[j + 1])
                j += 2
                continue
            parts.append(s[j])
            j += 1
        if j >= self.n:
            raise ShellSyntaxError("unterminated backtick substitution")
        self._substitute("".join(parts))
        self.buf.append(s[self.i:j + 1])
        self.started = self.dynamic = True
        self.i = j + 1

    def _skip_double(self, j: int) -> int:
        j += 1
        while j < self.n:
            if self.s[j] == "\\":
                j += 2
                continue
            if self.s[j] == '"':
                return j + 1
            j += 1
        raise ShellSyntaxError("unterminated double quote")

    def _balanced(self, start: int, opening: str, closing: str) -> tuple[str, int]:
        depth, j = 1, start
        while j < self.n:
            c = self.s[j]
            if c == "\\":
                j += 2
                continue
            if c == "'":
                end = self.s.find("'", j + 1)
                if end < 0:
                    raise ShellSyntaxError("unterminated single quote")
                j = end + 1
                continue
            if c == '"':
                j = self._skip_double(j)
                continue
            if c == opening:
                depth += 1
            elif c == closing:
                depth -= 1
                if depth == 0:
                    return self.s[start:j], j
            j += 1
        raise ShellSyntaxError(f"unterminated {opening}...{closing}")

    def _substitute(self, script: str) -> None:
        self.nested.extend(parse(script, depth=self.depth + 1))

    def _scan_expansions(self, text: str) -> None:
        """Find the `$(...)` and backtick substitutions inside expanded text."""
        j = 0
        while j < len(text):
            c = text[j]
            if c == "\\":
                j += 2
            elif text.startswith("$(", j) and not text.startswith("$((", j):
                sub = _Lexer(text, self.depth)
                inner, end = sub._balanced(j + 2, "(", ")")
                self._substitute(inner)
                j = end + 1
            elif c == "`":
                end = text.find("`", j + 1)
                if end < 0:
                    raise ShellSyntaxError("unterminated backtick substitution")
                self._substitute(text[j + 1:end])
                j = end + 1
            else:
                j += 1

    def _read_heredocs(self) -> None:
        while self.heredocs:
            redirect, delimiter, strip_tabs, quoted = self.heredocs.pop(0)
            lines = []
            while self.i < self.n:
                end = self.s.find("\n", self.i)
                line = self.s[self.i:] if end < 0 else self.s[self.i:end]
                self.i = self.n if end < 0 else end + 1
                if strip_tabs:
                    line = line.lstrip("\t")
                if line == delimiter:
                    break
                lines.append(line + "\n")
            redirect.heredoc = "".join(lines)
            if not quoted:
                self._scan_expansions(redirect.heredoc)
                self.out.extend(self.nested)
                self.nested = []
