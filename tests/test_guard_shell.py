import pytest

from fleet_rollout.guard.shell import ShellSyntaxError, parse


def argvs(script):
    return [[w.text for w in c.words] for c in parse(script)]


def test_words_quotes_and_escapes():
    assert argvs("docker exec agent-01 cat '/srv/agent/my file' \"x y\" a\\ b") == [
        ["docker", "exec", "agent-01", "cat", "/srv/agent/my file", "x y", "a b"]]


def test_operators_split_commands():
    assert argvs("a 1; b 2 && c || d | e & f\ng") == [
        ["a", "1"], ["b", "2"], ["c"], ["d"], ["e"], ["f"], ["g"]]


def test_subshells_and_groups_are_flattened():
    assert argvs("(cd /tmp && docker ps); { docker restart agent-01; }") == [
        ["cd", "/tmp"], ["docker", "ps"], ["docker", "restart", "agent-01"]]


def test_leading_assignments_are_separated_from_the_command():
    [cmd] = parse("CHANGE_TICKET=CHG-1042 FOO='a b' docker restart agent-01")
    assert [(k, v.text) for k, v in cmd.assignments] == [("CHANGE_TICKET", "CHG-1042"),
                                                         ("FOO", "a b")]
    assert [w.text for w in cmd.words] == ["docker", "restart", "agent-01"]


def test_an_equals_sign_after_the_command_name_is_just_an_argument():
    [cmd] = parse("docker run -e A=1 image")
    assert cmd.assignments == [] and "A=1" in [w.text for w in cmd.words]


def test_redirections_are_recorded_with_their_targets():
    [cmd] = parse("cat a.txt > out.txt 2>&1 >> log.txt < in.txt")
    assert [w.text for w in cmd.words] == ["cat", "a.txt"]
    assert [(r.op, r.target.text) for r in cmd.redirects] == [
        (">", "out.txt"), (">&", "1"), (">>", "log.txt"), ("<", "in.txt")]


def test_command_substitutions_are_parsed_as_commands_too():
    script = "docker rm -f $(docker ps -aq --filter name=agent) `hostname`"
    cmds = argvs(script)
    assert ["docker", "ps", "-aq", "--filter", "name=agent"] in cmds
    assert ["hostname"] in cmds
    outer = parse(script)[0]
    assert outer.words[3].dynamic and outer.words[4].dynamic


def test_nested_substitutions():
    assert ["inner", "x"] in argvs('echo "$(outer "$(inner x)")"')


def test_process_substitution_is_parsed():
    assert ["docker", "ps"] in argvs("diff <(docker ps) expected.txt")


@pytest.mark.parametrize("word, dynamic", [
    ("$C", True), ("${C}", True), ('"$C"', True), ("'$C'", False), ("agent-0*", True),
    ("agent-0{1,2}", True), ("agent-0[12]", True), ("agent-01", False), ("$((1+2))", True),
    ('"literal"', False),
])
def test_dynamic_words_are_flagged(word, dynamic):
    [cmd] = parse(f"docker restart {word}")
    assert cmd.words[2].dynamic is dynamic


def test_heredoc_bodies_are_attached_not_parsed_as_commands():
    script = "cat <<'EOF' > notes.md\nDon't panic\n$(not run)\nEOF\nls\n"
    cmds = parse(script)
    assert argvs(script) == [["cat"], ["ls"]]
    heredoc = [r for r in cmds[0].redirects if r.op == "<<"][0]
    assert heredoc.heredoc == "Don't panic\n$(not run)\n"


def test_unquoted_heredoc_bodies_still_run_their_substitutions():
    script = "cat <<EOF\nhello $(docker restart agent-01)\nEOF\n"
    assert ["docker", "restart", "agent-01"] in argvs(script)


def test_tab_stripping_heredoc():
    # `<<-` strips leading tabs from the body lines and from the delimiter line.
    [cmd] = parse("cat <<-END\n\tbody\n\tEND\n")
    assert cmd.redirects[0].heredoc == "body\n"


def test_comments_and_line_continuations():
    assert argvs("docker \\\n  restart agent-01  # a comment with 'quote\n") == [
        ["docker", "restart", "agent-01"]]
    assert argvs("echo a#b") == [["echo", "a#b"]]


def test_ansi_c_quoting():
    [cmd] = parse("echo $'a\\nb'")
    assert not cmd.words[1].dynamic


@pytest.mark.parametrize("bad", ["echo 'unterminated", 'echo "unterminated', "echo $(ls",
                                 "echo `ls", "cat >", "echo ${x"])
def test_unparseable_scripts_raise(bad):
    with pytest.raises(ShellSyntaxError):
        parse(bad)


def test_runaway_nesting_is_refused():
    with pytest.raises(ShellSyntaxError, match="nested"):
        parse("echo " + "$(echo " * 30 + "x" + ")" * 30)
