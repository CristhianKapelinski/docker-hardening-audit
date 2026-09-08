"""The exit-code contract and the output formats a pipeline consumes."""

import json
from pathlib import Path

import pytest

from dhaudit import cli

CORPUS = Path(__file__).resolve().parents[1] / "corpus"
REPLAY = str(CORPUS / "raw")


def run(args, capsys):
    code = cli.main(args)
    return code, capsys.readouterr().out


def test_a_hardened_file_exits_zero(capsys):
    code, out = run(
        ["scan", str(CORPUS / "dockerfiles/hardened_02_multistage.Dockerfile"), "--replay", REPLAY],
        capsys,
    )
    assert code == 0
    assert "0 violation(s)" in out


def test_a_critical_finding_exits_one(capsys):
    code, out = run(
        ["scan", str(CORPUS / "dockerfiles/vuln_01_root_user.Dockerfile"), "--replay", REPLAY],
        capsys,
    )
    assert code == 1
    assert "HARD-01" in out


def test_fail_on_none_never_fails_the_pipeline(capsys):
    code, _ = run(
        ["scan", str(CORPUS / "dockerfiles/vuln_01_root_user.Dockerfile"), "--replay", REPLAY,
         "--fail-on", "none"],
        capsys,
    )
    assert code == 0


def test_min_severity_filters(capsys):
    _code, out = run(
        ["scan", str(CORPUS / "dockerfiles/vuln_09_no_healthcheck.Dockerfile"), "--replay", REPLAY,
         "--min-severity", "high"],
        capsys,
    )
    assert "HARD-09" not in out


def test_json_and_sarif_are_valid(capsys):
    for fmt in ("json", "sarif"):
        _code, out = run(
            ["scan", str(CORPUS / "dockerfiles/vuln_13_legacy_stack.Dockerfile"), "--replay", REPLAY,
             "--format", fmt],
            capsys,
        )
        payload = json.loads(out)
        if fmt == "sarif":
            assert payload["runs"][0]["tool"]["driver"]["name"] == "dhaudit"
            assert payload["runs"][0]["results"]
        else:
            assert payload["violations"]


def test_policy_command_lists_the_pinned_backends(capsys):
    code, out = run(["policy"], capsys)
    assert code == 0
    assert "HARD-01" in out and "@sha256:" in out


def test_a_missing_target_is_an_input_error(capsys):
    """Exit 2, not 0: a target that was not read was not audited."""
    code, out = run(["scan", "does-not-exist", "--replay", REPLAY], capsys)
    assert "no such file" in out
    assert code == 2


def test_a_file_with_no_from_is_not_reported_as_clean(tmp_path, capsys):
    target = tmp_path / "Dockerfile"
    target.write_bytes(b"\x7fELF\x02\x01\x01binary garbage")
    code, out = run(["scan", str(target), "--replay", REPLAY], capsys)
    assert "not a Dockerfile" in out
    assert code == 2


def test_from_without_an_image_does_not_crash(tmp_path, capsys):
    target = tmp_path / "Dockerfile"
    target.write_text("FROM\nRUN true\n")
    code, out = run(["scan", str(target), "--replay", REPLAY], capsys)
    assert "FROM without an image" in out
    assert code == 2


def test_an_image_config_target_does_not_check_dockerfile_backends(capsys):
    _code, out = run(["scan", str(CORPUS / "image_configs/hardened.json")], capsys)
    assert "backends: native" in out
    assert "hadolint" not in out


def test_unknown_severity_exits_two(capsys):
    code, _ = run(["scan", str(CORPUS), "--min-severity", "nonsense"], capsys)
    assert code == 2
