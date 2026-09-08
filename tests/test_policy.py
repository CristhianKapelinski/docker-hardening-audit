"""The policy must stay internally consistent: nothing points at nothing."""

from dhaudit import policy
from dhaudit.backends import KNOWN_COMPROMISED, PINNED


def test_every_backend_mapping_points_at_a_real_property():
    for key, property_id in policy.BACKEND_MAP.items():
        assert property_id in policy.PROPERTIES, key


def test_every_native_justification_points_at_a_real_property():
    for property_id in policy.NATIVE_JUSTIFICATION:
        assert property_id in policy.PROPERTIES


def test_every_property_carries_the_text_a_report_needs():
    for prop in policy.PROPERTIES.values():
        assert prop.title and prop.rationale and prop.remediation
        assert prop.target in {"dockerfile", "image"}


def test_every_dockerfile_property_is_answered_by_someone():
    answered = set(policy.BACKEND_MAP.values()) | set(policy.NATIVE_JUSTIFICATION)
    for prop in policy.properties_for("dockerfile"):
        assert prop.property_id in answered, prop.property_id


def test_pinned_backends_are_pinned_by_digest():
    for name, (image, digest) in PINNED.items():
        assert digest.startswith("sha256:") and len(digest) == 71, name
        assert ":" in image and not image.endswith(":latest"), name


def test_no_pinned_backend_is_a_known_compromised_release():
    for name, (image, _digest) in PINNED.items():
        tag = image.rsplit(":", 1)[-1].lstrip("v")
        assert tag not in KNOWN_COMPROMISED.get(name, ()), f"{name} {tag} is compromised"
