"""Aggregation: run the backends, map their output onto the policy, arbitrate.

The three jobs that make this more than a wrapper around three CLIs:

1. **Normalize.** Three tools with three schemas and three severity vocabularies
   become one list of findings keyed by policy property.
2. **Deduplicate.** The same property on the same file, reported by hadolint,
   trivy and the native check, is ONE violation carrying three pieces of
   evidence, not three rows.
3. **Arbitrate.** A backend finding known to be wrong is dropped, and the reason
   is reported, so the operator sees why the count differs from running the tool
   by hand.

A replay directory makes the whole pipeline run offline from committed backend
output, which is what the reproducibility path uses.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from . import parser, policy
from .backends import BackendStatus, dockle, hadolint, native, trivy, verify
from .model import Dockerfile, OutOfPolicy, Severity

DOCKERFILE_BACKENDS = ("hadolint", "trivy", "native")


@dataclass
class Evidence:
    """One source's account of a violation."""

    source: str
    source_id: str
    message: str
    line: int


@dataclass
class Violation:
    """One policy property that fails on one file, with all the evidence."""

    property_id: str
    severity: Severity
    path: str
    line: int
    evidence: list[Evidence] = field(default_factory=list)

    @property
    def sources(self) -> list[str]:
        return sorted({item.source for item in self.evidence})

    def to_dict(self) -> dict:
        prop = policy.get(self.property_id)
        return {
            "property": self.property_id,
            "title": prop.title,
            "severity": self.severity.name,
            "path": self.path,
            "line": self.line,
            "remediation": prop.remediation,
            "sources": self.sources,
            "evidence": [
                {"source": e.source, "source_id": e.source_id, "line": e.line, "message": e.message}
                for e in sorted(self.evidence, key=lambda e: (e.source, e.source_id))
            ],
        }


@dataclass
class AuditResult:
    """Everything one audit produced."""

    violations: list[Violation] = field(default_factory=list)
    out_of_policy: list[OutOfPolicy] = field(default_factory=list)
    suppressed: list[dict] = field(default_factory=list)
    backends: list[BackendStatus] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    parse_failures: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def sorted_violations(self) -> list[Violation]:
        return sorted(self.violations, key=lambda v: (-v.severity.value, v.path, v.property_id))

    def counts_by_severity(self) -> dict[str, int]:
        counts = {severity.name: 0 for severity in Severity}
        for violation in self.violations:
            counts[violation.severity.name] += 1
        return counts

    def worst(self) -> Severity | None:
        return max((v.severity for v in self.violations), key=lambda s: s.value, default=None)

    def properties_by_file(self) -> dict[str, set[str]]:
        grouped: dict[str, set[str]] = {path: set() for path in self.files}
        for violation in self.violations:
            grouped.setdefault(violation.path, set()).add(violation.property_id)
        return grouped


def check_backends(names=DOCKERFILE_BACKENDS, replay_dir: Path | None = None) -> list[BackendStatus]:
    """Verify each backend's pinned image; `native` needs nothing.

    In replay mode no image is needed, and saying "unavailable, run docker pull"
    would send the operator after an image the run never touches.
    """
    statuses = []
    for name in names:
        if name == "native":
            statuses.append(BackendStatus("native", True, "", "in-tree", ""))
        elif replay_dir is not None:
            statuses.append(BackendStatus(name, True, f"replayed from {replay_dir}", "replay", ""))
        else:
            statuses.append(verify(name))
    return statuses


def _replay(directory: Path, backend: str, filename: str) -> str | None:
    candidate = directory / backend / f"{filename}.json"
    return candidate.read_text(encoding="utf-8") if candidate.exists() else None


def audit_dockerfile(
    path: str | Path,
    result: AuditResult,
    statuses: dict[str, BackendStatus],
    replay_dir: Path | None = None,
) -> None:
    """Audit one Dockerfile, appending to `result`."""
    target = Path(path)
    try:
        document = parser.parse_file(target)
        source_text = target.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        result.errors.append(f"{target}: cannot read ({exc.strerror})")
        return
    result.files.append(str(target))
    rows: list[dict] = []

    if replay_dir is not None:
        raw = _replay(replay_dir, "hadolint", target.name)
        if raw is not None:
            output = hadolint.BackendOutput(
                "hadolint", str(target), raw=raw, findings_raw=hadolint._parse(raw),
                parse_failed=any(i.get("code") == hadolint.PARSE_ERROR_CODE for i in hadolint._parse(raw)),
            )
            rows += _collect(output, hadolint.normalize, result)
        raw = _replay(replay_dir, "trivy", target.name)
        if raw is not None:
            output = trivy.BackendOutput("trivy", str(target), raw=raw, findings_raw=trivy._parse(raw))
            rows += _collect(output, trivy.normalize, result)
    else:
        if statuses.get("hadolint") and statuses["hadolint"].available:
            rows += _collect(hadolint.run(str(target), source_text), hadolint.normalize, result)
        if statuses.get("trivy") and statuses["trivy"].available:
            rows += _collect(trivy.run(str(target)), trivy.normalize, result)

    rows += native.check(document)
    _merge(rows, document, result)


def audit_image(image: str, result: AuditResult, config_json: str | None = None) -> None:
    """Audit a built image with dockle, or a committed `docker inspect` config."""
    if config_json is not None:
        from .model import ImageConfig

        try:
            config = ImageConfig.from_json(image, config_json)
        except ValueError as exc:
            result.errors.append(str(exc))
            return
        result.files.append(image)
        rows = _from_image_config(config)
        _merge(rows, None, result)
        return
    status = verify("dockle")
    result.backends.append(status)
    if not status.available:
        result.errors.append(f"dockle unavailable: {status.reason}")
        return
    result.files.append(image)
    rows = _collect(dockle.run(image), dockle.normalize, result)
    _merge(rows, None, result)


def _from_image_config(config) -> list[dict]:
    """Native equivalent of the dockle checks, for the offline config path."""
    rows: list[dict] = []
    user = config.user.strip()
    if not user or user.split(":")[0] in {"root", "0"}:
        rows.append(
            {
                "source": "native", "source_id": "NAT-IMAGE-USER", "property": "HARD-13",
                "path": config.path, "line": 1, "severity": "CRITICAL",
                "message": f"image config user is {user or 'empty, which means root'!r}",
            }
        )
    for key, value in sorted(config.env.items()):
        if native.SECRET_KEY.search(key) and value.strip():
            rows.append(
                {
                    "source": "native", "source_id": "NAT-IMAGE-ENV", "property": "HARD-14",
                    "path": config.path, "line": 1, "severity": "CRITICAL",
                    "message": f"environment variable {key} carries a value and travels with the image",
                }
            )
    return rows


def _collect(output, normalizer, result: AuditResult) -> list[dict]:
    """Turn one backend output into rows, recording failures instead of hiding them."""
    result.backends = [status for status in result.backends]
    if not output.ok:
        result.errors.append(f"{output.name} failed on {output.target}: {output.error}")
        return []
    if getattr(output, "parse_failed", False):
        result.parse_failures.append(
            {
                "source": output.name,
                "path": output.target,
                "note": "the backend could not parse the file, so its silence is not a clean result",
            }
        )
    return normalizer(output)


def _merge(rows: list[dict], document: Dockerfile | None, result: AuditResult) -> None:
    """Map rows onto policy properties, arbitrate, and deduplicate."""
    suppressed_lines = native.suppressed_secret_lines(document) if document else set()
    index: dict[tuple[str, str], Violation] = {
        (v.property_id, v.path): v for v in result.violations
    }
    for row in rows:
        property_id = row.get("property") or policy.property_of(row["source"], row["source_id"])
        if property_id is None:
            result.out_of_policy.append(
                OutOfPolicy(row["source"], row["source_id"], row["path"], row["line"], row["message"])
            )
            continue
        if property_id == "HARD-03" and row["line"] in suppressed_lines:
            result.suppressed.append(
                {
                    "property": property_id,
                    "source": row["source"],
                    "source_id": row["source_id"],
                    "path": row["path"],
                    "line": row["line"],
                    "reason": "ARG/ENV declares a secret name with no value, so nothing is baked into the image",
                }
            )
            continue
        prop = policy.get(property_id)
        key = (property_id, row["path"])
        violation = index.get(key)
        if violation is None:
            violation = Violation(property_id, prop.severity, row["path"], row["line"])
            index[key] = violation
            result.violations.append(violation)
        violation.line = min(violation.line, row["line"]) if violation.line else row["line"]
        violation.evidence.append(
            Evidence(row["source"], row["source_id"], row["message"], row["line"])
        )


def audit(
    targets: list[str],
    min_severity: Severity = Severity.LOW,
    replay_dir: Path | None = None,
) -> AuditResult:
    """Audit files and directories of Dockerfiles."""
    result = AuditResult()
    statuses = {status.name: status for status in check_backends(replay_dir=replay_dir)}
    result.backends = list(statuses.values())
    for target in targets:
        path = Path(target)
        if path.is_dir():
            for found in parser.discover(path):
                audit_dockerfile(found, result, statuses, replay_dir)
        elif path.suffix == ".json":
            audit_image(str(path), result, config_json=path.read_text(encoding="utf-8"))
        elif path.exists():
            audit_dockerfile(path, result, statuses, replay_dir)
        else:
            result.errors.append(f"{target}: no such file or directory")
    result.violations = [v for v in result.violations if v.severity.value >= min_severity.value]
    return result


def load_replay(directory: str | Path) -> Path:
    path = Path(directory)
    if not path.is_dir():
        raise ValueError(f"{directory}: not a replay directory")
    return path


def dump_raw(result_dir: str | Path, backend: str, filename: str, raw: str) -> None:
    """Store one backend's raw output as the run of record."""
    out = Path(result_dir) / backend
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{filename}.json").write_text(raw or "", encoding="utf-8")


def backend_versions() -> dict[str, str]:
    """The pinned reference of every backend, for the report header."""
    from .backends import PINNED

    return {name: f"{image}@{digest}" for name, (image, digest) in PINNED.items()}


def as_json(result: AuditResult) -> str:
    return json.dumps(
        {
            "files": result.files,
            "violations": [v.to_dict() for v in result.sorted_violations()],
            "counts": result.counts_by_severity(),
            "out_of_policy": [o.to_dict() for o in result.out_of_policy],
            "suppressed": result.suppressed,
            "parse_failures": result.parse_failures,
            "backends": [
                {"name": b.name, "available": b.available, "reason": b.reason, "image": b.image}
                for b in result.backends
            ],
            "errors": result.errors,
        },
        indent=2,
        ensure_ascii=False,
    )
