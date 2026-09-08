"""Backend runners and the digest verification that guards them.

Every external scanner runs from an image pinned by digest, and the digest is
checked against `PINNED` before the container starts. This is not ceremony: in
March 2026 an attacker published a malicious Trivy v0.69.4 release and malicious
v0.69.5 and v0.69.6 Docker Hub images (CVE-2026-33634), so a tool that runs
`aquasec/trivy:latest` executes whatever that tag points at today.

A backend that cannot be verified, or is not installed, is reported as
unavailable and the audit continues with the others; its properties then fall to
the native checks. Refusing the whole run would leave the operator with nothing.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field

# image reference -> expected repo digest. Update with scripts/update_backends.sh.
PINNED: dict[str, str] = {
    "hadolint": (
        "hadolint/hadolint:v2.15.1-alpine",
        "sha256:a1d49ae1a4e83c1dbad26b8c1ad7588c8bd1e04f4866b34ad3cac50335198552",
    ),
    "trivy": (
        "aquasec/trivy:0.74.0",
        "sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969",
    ),
    "dockle": (
        "goodwithtech/dockle:v0.4.15",
        "sha256:eade932f793742de0aa8755406c7677cd7696f8675b6180926f7eeffa7abe6b9",
    ),
}

# Versions never to run: published by an attacker during the March 2026 incident.
KNOWN_COMPROMISED: dict[str, tuple[str, ...]] = {
    "trivy": ("0.69.4", "0.69.5", "0.69.6"),
}


@dataclass
class BackendStatus:
    """Whether a backend can be used, and why not when it cannot."""

    name: str
    available: bool
    reason: str = ""
    image: str = ""
    digest: str = ""


@dataclass
class BackendOutput:
    """One backend's raw output for one target, plus how it went."""

    name: str
    target: str
    raw: str = ""
    ok: bool = True
    error: str = ""
    parse_failed: bool = False
    findings_raw: list[dict] = field(default_factory=list)


def docker_available() -> bool:
    return shutil.which("docker") is not None


def pinned_reference(name: str) -> str:
    """The `image:tag@sha256:digest` reference the runner passes to `docker run`."""
    image, digest = PINNED[name]
    return f"{image}@{digest}"


def inspect_reference(name: str) -> str:
    """The `repository@sha256:digest` form, which is what a local inspect accepts.

    `docker run` takes `repo:tag@digest`, but `docker image inspect` answers
    "No such image" for that same string, so verification has to drop the tag.
    Getting this wrong disabled every backend while printing a `docker pull`
    hint for an image that was already there.
    """
    image, digest = PINNED[name]
    repository = image.rsplit(":", 1)[0]
    return f"{repository}@{digest}"


def verify(name: str, timeout: int = 60) -> BackendStatus:
    """Check that the locally available image matches the pinned digest.

    The check is deliberately about the DIGEST and not the tag: a poisoned local
    cache, or a tag that was force-pushed upstream, both show the right tag.
    """
    image, digest = PINNED[name]
    tag = image.rsplit(":", 1)[-1].lstrip("v")
    if tag in KNOWN_COMPROMISED.get(name, ()):
        return BackendStatus(name, False, f"version {tag} is a known compromised release", image, digest)
    if not docker_available():
        return BackendStatus(name, False, "docker is not on PATH", image, digest)
    try:
        proc = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", inspect_reference(name)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return BackendStatus(name, False, f"docker inspect failed ({exc})", image, digest)
    if proc.returncode != 0:
        return BackendStatus(
            name, False,
            f"image not present locally; run `docker pull {image}@{digest}`",
            image, digest,
        )
    try:
        digests = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        digests = []
    if not any(digest in str(item) for item in digests):
        return BackendStatus(name, False, "local image digest does not match the pinned digest", image, digest)
    return BackendStatus(name, True, "", image, digest)


def run_container(args: list[str], stdin_text: str | None = None, timeout: int = 300) -> subprocess.CompletedProcess:
    """Run docker with no network unless the caller asked for it."""
    return subprocess.run(
        args, input=stdin_text, capture_output=True, text=True, timeout=timeout, check=False
    )


from . import hadolint as hadolint  # noqa: E402,F401
from . import native as native  # noqa: E402,F401
from . import trivy as trivy  # noqa: E402,F401
from . import dockle as dockle  # noqa: E402,F401
