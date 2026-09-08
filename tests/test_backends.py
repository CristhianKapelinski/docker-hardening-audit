"""Digest verification, including the branch that refuses a compromised release."""

from dhaudit import backends


def test_a_compromised_version_is_refused_before_docker_is_touched(monkeypatch):
    monkeypatch.setitem(backends.PINNED, "trivy", ("aquasec/trivy:0.69.4", "sha256:" + "0" * 64))
    status = backends.verify("trivy")
    assert not status.available
    assert "compromised" in status.reason


def test_a_missing_image_reports_the_pull_command(monkeypatch):
    monkeypatch.setitem(backends.PINNED, "hadolint", ("hadolint/hadolint:v0.0.0", "sha256:" + "1" * 64))
    status = backends.verify("hadolint")
    assert not status.available
    if backends.docker_available():
        assert "docker pull" in status.reason
    else:
        assert "docker" in status.reason


def test_pinned_reference_is_the_full_digest_form():
    reference = backends.pinned_reference("trivy")
    assert "@sha256:" in reference
