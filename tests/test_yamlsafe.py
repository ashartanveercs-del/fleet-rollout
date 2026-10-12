import pytest

from fleet_rollout.yamlsafe import StrictYAMLError, load_strict


def test_plain_document_loads():
    assert load_strict("id: demo\nsteps:\n  - kind: run\n", source="p.yaml") == {
        "id": "demo", "steps": [{"kind": "run"}]}


def test_duplicate_keys_are_rejected_not_last_one_wins():
    # PyYAML's default behaviour silently keeps the LAST value. A reviewer reads the
    # first `dest`, the loader would use the second one.
    text = "dest: config/greeting.txt\nsource: a.txt\ndest: ../../etc/passwd\n"
    with pytest.raises(StrictYAMLError, match="duplicate key 'dest'"):
        load_strict(text, source="p.yaml")


def test_duplicate_keys_in_nested_mappings_are_rejected():
    text = "steps:\n  - kind: write_file\n    kind: run\n"
    with pytest.raises(StrictYAMLError, match="duplicate key 'kind'"):
        load_strict(text, source="p.yaml")


def test_aliases_are_rejected():
    text = "a: &x [1, 2]\nb: *x\n"
    with pytest.raises(StrictYAMLError, match="anchors and aliases"):
        load_strict(text, source="p.yaml")


def test_billion_laughs_is_rejected_before_expansion():
    text = "a: &a ['lol','lol']\nb: &b [*a,*a]\nc: &c [*b,*b]\n"
    with pytest.raises(StrictYAMLError, match="anchors and aliases"):
        load_strict(text, source="p.yaml")


def test_merge_keys_are_rejected():
    text = "base: {x: 1}\nstep:\n  <<: {x: 2}\n  y: 3\n"
    with pytest.raises(StrictYAMLError, match="merge keys"):
        load_strict(text, source="p.yaml")


def test_non_string_keys_are_rejected():
    with pytest.raises(StrictYAMLError, match="keys must be strings"):
        load_strict("1: one\n", source="p.yaml")


def test_python_object_tags_cannot_construct_objects():
    text = "x: !!python/object/apply:os.system ['echo pwned']\n"
    with pytest.raises(StrictYAMLError):
        load_strict(text, source="p.yaml")


def test_oversized_documents_are_rejected_before_parsing():
    with pytest.raises(StrictYAMLError, match="larger than"):
        load_strict("a: " + "x" * 2000 + "\n", source="p.yaml", max_bytes=1000)


def test_syntax_errors_name_the_source():
    with pytest.raises(StrictYAMLError, match="p.yaml"):
        load_strict("a: [unclosed\n", source="p.yaml")


def test_multiple_documents_are_rejected():
    with pytest.raises(StrictYAMLError, match="single YAML document"):
        load_strict("a: 1\n---\nb: 2\n", source="p.yaml")


def test_empty_document_loads_as_none():
    assert load_strict("", source="p.yaml") is None
