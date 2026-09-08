"""The hardening policy: what the tool checks, and which backend check answers it.

The policy is the unit of the report. A reader does not want to know that
hadolint said DL3009 and trivy said DS-0029 about the same line; they want to
know that the property "package manager cache removed" fails, and which tools
agree. Every mapping in `BACKEND_MAP` was decided by RUNNING the backends over
`corpus/`, not by reading their documentation, and `docs/COVERAGE.md` records the
measurement.

A backend code that is not in `BACKEND_MAP` is out of policy: it is style advice
(`DL3025`, use JSON notation for CMD) or a concern the policy does not cover
(`DL3059`, consecutive RUN instructions). Out-of-policy codes are counted and
kept in the JSON output under `out_of_policy`, never dropped in silence.

The operating-system package pins (`DL3008` apt, `DL3018` apk, `DL3028` gem) are
deliberately out of policy while the pip and npm pins are in it. Debian and
Ubuntu remove superseded versions from their repositories, so a Dockerfile that
pins `apt-get install curl=7.88.1-10` stops building within weeks, and the base
image digest required by HARD-02 already freezes the package snapshot the build
sees. Language dependencies have no such constraint: the index keeps every
version, and a lock file is the normal practice.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Severity


@dataclass(frozen=True)
class Property:
    """One hardening property the audit reports on."""

    property_id: str
    severity: Severity
    title: str
    rationale: str
    remediation: str
    target: str  # "dockerfile" or "image"


PROPERTIES: dict[str, Property] = {
    p.property_id: p
    for p in [
        Property(
            "HARD-01", Severity.CRITICAL, "The image does not run as root",
            "A process that starts as uid 0 turns a container escape into host root.",
            "create an unprivileged account and switch to it with `USER` in the final stage",
            "dockerfile",
        ),
        Property(
            "HARD-02", Severity.HIGH, "Every base image is pinned by digest",
            "A mutable tag lets the content of a build change without the Dockerfile changing, "
            "which is the entry point that the Trivy supply-chain compromise of March 2026 used.",
            "pin the base as `image:tag@sha256:<digest>`",
            "dockerfile",
        ),
        Property(
            "HARD-03", Severity.CRITICAL, "No secret literal in ENV or ARG",
            "A value written in the Dockerfile stays in the image history and travels with every pull.",
            "pass secrets with `--mount=type=secret` or inject them at run time",
            "dockerfile",
        ),
        Property(
            "HARD-04", Severity.HIGH, "No remote script piped into a shell",
            "`curl | sh` executes whatever the server serves at build time, unverified.",
            "download to a file, verify its checksum or signature, then execute it",
            "dockerfile",
        ),
        Property(
            "HARD-05", Severity.MEDIUM, "Package manager cache and recommends cleaned",
            "Cache and recommended packages enlarge the image and its vulnerable surface.",
            "use `--no-install-recommends` and remove the package lists in the same RUN",
            "dockerfile",
        ),
        Property(
            "HARD-06", Severity.MEDIUM, "No ADD from a remote URL",
            "`ADD https://...` fetches at build time with no integrity check and no cache control.",
            "use `RUN curl` plus a checksum check, or vendor the file and use COPY",
            "dockerfile",
        ),
        Property(
            "HARD-07", Severity.HIGH, "No world-writable path",
            "A world-writable path lets any process in the container rewrite the application.",
            "give the owning user the narrowest mode that works, such as 0755 or 0640",
            "dockerfile",
        ),
        Property(
            "HARD-08", Severity.LOW, "No sensitive port exposed",
            "An exposed management or database port advertises a service that should not be reachable.",
            "expose only the application port",
            "dockerfile",
        ),
        Property(
            "HARD-09", Severity.LOW, "A healthcheck is declared",
            "Without it the platform cannot tell a hung service from a healthy one.",
            "add a `HEALTHCHECK` that exercises the service, not just the process",
            "dockerfile",
        ),
        Property(
            "HARD-10", Severity.HIGH, "No sudo in the image",
            "sudo is a privilege-escalation path that a container does not need.",
            "drop sudo and do privileged work before the final `USER`",
            "dockerfile",
        ),
        Property(
            "HARD-11", Severity.MEDIUM, "Dependencies installed with a pinned version",
            "An unpinned dependency makes the build non-reproducible and hijackable.",
            "pin the version, or install from a lock file",
            "dockerfile",
        ),
        Property(
            "HARD-12", Severity.MEDIUM, "The build context has a .dockerignore",
            "Without it `COPY . .` ships `.git`, `.env` and whatever else sits in the directory.",
            "add a `.dockerignore` with at least `.git`, `.env`, `*.pem` and the local virtualenv",
            "dockerfile",
        ),
        Property(
            "HARD-13", Severity.CRITICAL, "The built image does not run as root",
            "The shipped config is what the daemon obeys, and it may disagree with the Dockerfile.",
            "ship the image with an unprivileged user",
            "image",
        ),
        Property(
            "HARD-14", Severity.CRITICAL, "The built image carries no credential",
            "Anything in the image environment or filesystem is readable by whoever can pull it.",
            "remove the credential from the image and inject it at run time",
            "image",
        ),
    ]
}

# Backend check -> policy property. Measured against corpus/, see docs/COVERAGE.md.
BACKEND_MAP: dict[str, str] = {
    # hadolint
    "hadolint:DL3007": "HARD-02",   # only catches :latest, not other mutable tags
    "hadolint:DL3064": "HARD-03",
    "hadolint:DL3004": "HARD-10",   # only catches `RUN sudo`, not installing sudo
    "hadolint:DL3009": "HARD-05",
    "hadolint:DL3015": "HARD-05",
    "hadolint:DL3013": "HARD-11",   # pip
    "hadolint:DL3016": "HARD-11",   # npm
    # trivy config
    "trivy:DS-0001": "HARD-02",     # only catches :latest
    "trivy:DS-0002": "HARD-01",
    "trivy:DS-0004": "HARD-08",     # only port 22
    "trivy:DS-0026": "HARD-09",
    "trivy:DS-0029": "HARD-05",
    "trivy:DS-0031": "HARD-03",
    # dockle (built image)
    "dockle:CIS-DI-0001": "HARD-13",
    "dockle:CIS-DI-0005": "HARD-13",
    "dockle:CIS-DI-0010": "HARD-14",
    "dockle:DKL-DI-0005": "HARD-14",
    "dockle:DKL-LI-0003": "HARD-14",
    "dockle:CIS-DI-0009": "HARD-02",
    "dockle:CIS-DI-0006": "HARD-09",
}

# Native checks fill the properties no backend covers, or complete a partial one.
# The reason is recorded here so a reader can see why the code exists at all.
NATIVE_JUSTIFICATION: dict[str, str] = {
    "HARD-01": "fallback when trivy is unavailable, and resolves the user through the stage alias chain",
    "HARD-02": "hadolint DL3007 and trivy DS-0001 only fire on :latest; any other mutable tag passes",
    "HARD-03": "arbitration: both backends flag `ARG SECRET` with no default, which leaks nothing",
    "HARD-04": "no backend check exists; hadolint DL4006 is about pipefail, not unverified download",
    "HARD-06": "no backend check exists",
    "HARD-07": "no backend check exists",
    "HARD-08": "trivy DS-0004 covers port 22 only",
    "HARD-10": "hadolint DL3004 fires on `RUN sudo`, not on installing the sudo package",
    "HARD-12": "a repository-level fact that neither backend looks at",
}


def property_of(source: str, code: str) -> str | None:
    """The policy property a backend check maps to, or None when out of policy."""
    return BACKEND_MAP.get(f"{source}:{code}")


def get(property_id: str) -> Property:
    return PROPERTIES[property_id]


def properties_for(target: str) -> list[Property]:
    return [p for p in PROPERTIES.values() if p.target == target]
