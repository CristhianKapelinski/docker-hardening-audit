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


def test_a_missing_target_is_a_reported_error(capsys):
    code, out = run(["scan", "does-not-exist", "--replay", REPLAY], capsys)
    assert "no such file" in out
    assert code == 0


def test_unknown_severity_exits_two(capsys):
    code, _ = run(["scan", str(CORPUS), "--min-severity", "nonsense"], capsys)
    assert code == 2
