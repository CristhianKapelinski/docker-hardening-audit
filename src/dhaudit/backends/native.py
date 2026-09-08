"""Native checks: only the gaps the measurement found, plus one arbitration.

Every check here exists because running hadolint v2.15.1 and trivy 0.74.0 over
`corpus/` showed that no backend answers that property, or answers only part of
it. `policy.NATIVE_JUSTIFICATION` records the reason per property and
`docs/COVERAGE.md` shows the measurement. Nothing here duplicates a backend: the
first version of this tool reimplemented apt hygiene, healthcheck and dependency
pinning, and those checks were deleted once the corpus run proved hadolint and
trivy already cover them.

The arbitration is the other half of aggregation. Both backends flag
`ARG API_TOKEN` with no default as a leaked secret, which is wrong: with no
default the value comes from the build command and never enters a layer of the
image. `suppressed_secret_lines` gives the aggregator the lines where a HARD-03
finding must be dropped whoever reported it.
"""

from __future__ import annotations

import re

from ..model import Dockerfile, Stage

SENSITIVE_PORTS = {
    "22": "SSH",
    "23": "telnet",
    "2375": "Docker daemon without TLS",
    "2376": "Docker daemon",
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "6379": "Redis",
    "9200": "Elasticsearch",
    "11211": "memcached",
    "27017": "MongoDB",
}

SECRET_KEY = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)",
    re.IGNORECASE,
)
_PLACEHOLDER = re.compile(r"^(?:\$\{?\w+\}?|\"\"|''|)$")
_PIPE_TO_SHELL = re.compile(
    r"(?:curl|wget)\b[^|;]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|"
    r"(?:ba|z|da)?sh\s+-c\s+[\"']?\$\((?:curl|wget)\b",
    re.IGNORECASE,
)
_WORLD_WRITABLE = re.compile(
    r"chmod\s+(?:-[A-Za-z]+\s+)*(?:0?777|0?666|[ugoa]*[+=][rwx]*w[rwx]*)\b"
)
_REMOTE_SOURCE = re.compile(r"\b(?:https?|ftp)://|\bgit@", re.IGNORECASE)

NAME = "native"


def _row(check: str, property_id: str, severity: str, doc: Dockerfile, line: int, message: str) -> dict:
    return {
        "source": NAME,
        "source_id": check,
        "property": property_id,
        "path": doc.path,
        "line": line,
        "severity": severity,
        "message": message,
    }


def _effective_user(doc: Dockerfile) -> tuple[str | None, int]:
    """The user the shipped image runs as, following the stage alias chain.

    A final stage that inherits from a local alias (`FROM base`) also inherits
    its `USER`, so reading one stage reports a false positive on the multi-stage
    build that drops privileges in the base stage.
    """
    stage: Stage | None = doc.final_stage
    seen: set[int] = set()
    while stage is not None and stage.index not in seen:
        seen.add(stage.index)
        users = stage.of("USER")
        if users:
            last = users[-1]
            return (last.words[0] if last.words else ""), last.line
        parent_alias = stage.base_image.lower()
        stage = next((s for s in doc.stages if s.alias and s.alias.lower() == parent_alias), None)
    fallback = doc.final_stage.line if doc.final_stage else 1
    return None, fallback


def check(doc: Dockerfile) -> list[dict]:
    """Run every native check over a parsed Dockerfile."""
    rows: list[dict] = []
    rows += _user(doc)
    rows += _digest(doc)
    rows += _pipe_to_shell(doc)
    rows += _add_remote(doc)
    rows += _world_writable(doc)
    rows += _sensitive_port(doc)
    rows += _sudo(doc)
    rows += _dockerignore(doc)
    return rows


def _user(doc: Dockerfile) -> list[dict]:
    if not doc.final_stage:
        return []
    user, line = _effective_user(doc)
    if user is None:
        return [_row("NAT-USER", "HARD-01", "CRITICAL", doc, line,
                     "the final stage never sets USER, so the image runs as the base image user")]
    if user.split(":")[0] in {"root", "0"}:
        return [_row("NAT-USER", "HARD-01", "CRITICAL", doc, line, f"the final stage runs as {user!r}")]
    return []


def _digest(doc: Dockerfile) -> list[dict]:
    aliases = doc.stage_aliases
    rows = []
    for stage in doc.stages:
        image = stage.base_image
        if not image or image.startswith("$") or image.lower() in aliases or image.lower() == "scratch":
            continue
        if "@sha256:" in image:
            continue
        reference, _, tag = image.rpartition(":")
        detail = f"mutable tag :{tag}" if reference and "/" not in tag else "no tag, which resolves to :latest"
        rows.append(_row("NAT-DIGEST", "HARD-02", "HIGH", doc, stage.line,
                         f"base image {image!r} is not pinned by digest ({detail})"))
    return rows


def _pipe_to_shell(doc: Dockerfile) -> list[dict]:
    rows = []
    for instruction in doc.all_instructions():
        if instruction.keyword == "RUN" and _PIPE_TO_SHELL.search(instruction.raw):
            rows.append(_row("NAT-PIPE", "HARD-04", "HIGH", doc, instruction.line,
                             "RUN pipes a downloaded script straight into a shell"))
    return rows


def _add_remote(doc: Dockerfile) -> list[dict]:
    rows = []
    for instruction in doc.all_instructions():
        if instruction.keyword == "ADD" and _REMOTE_SOURCE.search(instruction.raw):
            rows.append(_row("NAT-ADD-REMOTE", "HARD-06", "MEDIUM", doc, instruction.line,
                             "ADD downloads a remote resource without verifying it"))
    return rows


def _world_writable(doc: Dockerfile) -> list[dict]:
    rows = []
    for instruction in doc.all_instructions():
        if instruction.keyword in {"RUN", "COPY", "ADD"} and _WORLD_WRITABLE.search(instruction.raw):
            rows.append(_row("NAT-WORLD-WRITABLE", "HARD-07", "HIGH", doc, instruction.line,
                             "grants write permission to every user in the image"))
    return rows


def _sensitive_port(doc: Dockerfile) -> list[dict]:
    stage = doc.final_stage
    if stage is None:
        return []
    rows = []
    for instruction in stage.of("EXPOSE"):
        for token in instruction.words:
            port = token.split("/")[0]
            service = SENSITIVE_PORTS.get(port)
            if service:
                rows.append(_row("NAT-PORT", "HARD-08", "LOW", doc, instruction.line,
                                 f"exposes port {port} ({service})"))
    return rows


def _sudo(doc: Dockerfile) -> list[dict]:
    stage = doc.final_stage
    if stage is None:
        return []
    installs = re.compile(
        r"(?:apt(?:-get)?\s+install|apk\s+add|yum\s+install|dnf\s+install)\b[^&|;]*\bsudo\b"
    )
    invokes = re.compile(r"(?:^|&&\s*|;\s*|\|\s*)sudo\s")
    for instruction in stage.of("RUN"):
        lowered = instruction.raw.lower()
        if installs.search(lowered) or invokes.search(lowered):
            return [_row("NAT-SUDO", "HARD-10", "HIGH", doc, instruction.line,
                         "sudo is installed or invoked in the final stage")]
    return []


def _dockerignore(doc: Dockerfile) -> list[dict]:
    if doc.has_dockerignore:
        return []
    for instruction in doc.all_instructions():
        if instruction.keyword not in {"COPY", "ADD"}:
            continue
        sources = [token for token in instruction.words if not token.startswith("--")]
        if sources and sources[0] in {".", "./", "*"}:
            return [_row("NAT-DOCKERIGNORE", "HARD-12", "MEDIUM", doc, instruction.line,
                         "copies the whole build context and the directory has no .dockerignore")]
    return []


def suppressed_secret_lines(doc: Dockerfile) -> set[int]:
    """Lines where a HARD-03 finding is a false positive, whoever reported it.

    `ARG API_TOKEN` with no default declares a build argument; the value arrives
    with `--build-arg` and never lands in an image layer. Both hadolint (DL3064)
    and trivy (DS-0031) report it anyway.
    """
    lines: set[int] = set()
    for instruction in doc.all_instructions():
        if instruction.keyword not in {"ARG", "ENV"}:
            continue
        pairs = _key_values(instruction.raw)
        if not pairs:
            continue
        secretish = [(key, value) for key, value in pairs if SECRET_KEY.search(key)]
        if secretish and all(_PLACEHOLDER.match(value.strip()) for _, value in secretish):
            lines.add(instruction.line)
    return lines


def _key_values(raw: str) -> list[tuple[str, str]]:
    """Both ENV forms: `ENV k=v k2=v2` and the legacy `ENV k v`."""
    if "=" not in raw:
        parts = raw.split(None, 1)
        return [(parts[0], parts[1] if len(parts) > 1 else "")] if parts else []
    pairs: list[tuple[str, str]] = []
    for token in raw.split():
        key, sep, value = token.partition("=")
        if sep:
            pairs.append((key, value.strip("\"'")))
        else:
            pairs.append((key, ""))
    return pairs
