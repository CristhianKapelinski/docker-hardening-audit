"""Aggregation: normalize, deduplicate, arbitrate, and never hide a failure."""

import json
from pathlib import Path

from dhaudit import aggregate, policy
from dhaudit.backends import BackendStatus

CORPUS = Path(__file__).resolve().parents[1] / "corpus"
REPLAY = CORPUS / "raw"


def audit(relative):
    result = aggregate.AuditResult()
    statuses = {"hadolint": BackendStatus("hadolint", False, "not run in tests"),
                "trivy": BackendStatus("trivy", False, "not run in tests")}
    aggregate.audit_dockerfile(CORPUS / relative, result, statuses, replay_dir=REPLAY)
    return result


def test_one_property_reported_by_two_sources_is_one_violation():
    result = audit("dockerfiles/vuln_01_root_user.Dockerfile")
    root = [v for v in result.violations if v.property_id == "HARD-01"]
    assert len(root) == 1
    assert set(root[0].sources) == {"native", "trivy"}, root[0].sources


def test_out_of_policy_codes_are_kept_not_dropped():
    result = audit("dockerfiles/hardened_01_python.Dockerfile")
    assert result.violations == []
    codes = {f"{o.source}:{o.source_id}" for o in result.out_of_policy}
    assert "hadolint:DL3025" in codes
    assert all(policy.property_of(o.source, o.source_id) is None for o in result.out_of_policy)


def test_arbitration_removes_the_arg_without_default():
    result = audit("dockerfiles/hardened_05_arg_without_default.Dockerfile")
    assert [v.property_id for v in result.violations] == []
    reported = {(item["source"], item["source_id"]) for item in result.suppressed}
    assert ("hadolint", "DL3064") in reported
    assert ("trivy", "DS-0031") in reported


def test_backend_parse_failure_is_surfaced():
    result = audit("dockerfiles/vuln_15_heredoc_pipe.Dockerfile")
    assert any(f["source"] == "hadolint" for f in result.parse_failures)


def test_severity_of_a_violation_comes_from_the_policy_not_the_backend():
    result = audit("dockerfiles/vuln_09_no_healthcheck.Dockerfile")
    healthcheck = [v for v in result.violations if v.property_id == "HARD-09"][0]
    assert healthcheck.severity is policy.get("HARD-09").severity


def test_json_output_is_valid_and_complete():
    result = audit("dockerfiles/vuln_13_legacy_stack.Dockerfile")
    payload = json.loads(aggregate.as_json(result))
    assert payload["counts"]["CRITICAL"] >= 1
    assert {v["property"] for v in payload["violations"]} >= {"HARD-01", "HARD-03", "HARD-04"}
    for violation in payload["violations"]:
        assert violation["evidence"], "every violation names its evidence"


def test_image_config_path_needs_no_docker():
    config = json.dumps([{"RepoTags": ["x:1"], "Config": {"User": "", "Env": ["DB_PASSWORD=abc"]}}])
    result = aggregate.AuditResult()
    aggregate.audit_image("x:1", result, config_json=config)
    assert {v.property_id for v in result.violations} == {"HARD-13", "HARD-14"}
