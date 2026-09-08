"""Corpus evaluation: what each backend detects, and what the aggregate adds.

The corpus is a set of Dockerfiles with a hand-written ground truth: for each
file, the policy properties that a correct audit must report and no other. The
evaluation compares five configurations over that ground truth — hadolint alone,
trivy alone, their union, the native checks alone, and the full aggregate — and
reports precision, recall and F1 per configuration, plus which properties each
configuration can answer at all.

Every configuration is computed from the SAME committed backend output, so the
comparison is not affected by a backend running on a different day.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from . import parser, policy
from .backends import hadolint, native, trivy

CONFIGURATIONS = ("hadolint", "trivy", "union", "native", "dhaudit")


@dataclass
class Metrics:
    """Counts and derived rates for one configuration."""

    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0

    @property
    def precision(self) -> float:
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator if denominator else 1.0

    @property
    def recall(self) -> float:
        denominator = self.true_positive + self.false_negative
        return self.true_positive / denominator if denominator else 1.0

    @property
    def f1(self) -> float:
        precision, recall = self.precision, self.recall
        return 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    def to_dict(self) -> dict:
        return {
            "tp": self.true_positive,
            "fp": self.false_positive,
            "fn": self.false_negative,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


@dataclass
class Evaluation:
    """The whole corpus evaluation."""

    metrics: dict[str, Metrics] = field(default_factory=dict)
    detected: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    coverage: dict[str, list[str]] = field(default_factory=dict)
    files: list[str] = field(default_factory=list)
    parse_failures: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "files": len(self.files),
            "metrics": {name: self.metrics[name].to_dict() for name in CONFIGURATIONS},
            "coverage": {name: sorted(self.coverage[name]) for name in CONFIGURATIONS},
            "parse_failures": {k: sorted(v) for k, v in self.parse_failures.items()},
        }


def _replayed(replay_dir: Path, backend: str, filename: str) -> str:
    path = replay_dir / backend / f"{filename}.json"
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _mapped(rows: list[dict]) -> set[str]:
    properties = set()
    for row in rows:
        property_id = row.get("property") or policy.property_of(row["source"], row["source_id"])
        if property_id:
            properties.add(property_id)
    return properties


def detect(dockerfile: Path, replay_dir: Path) -> tuple[dict[str, set[str]], list[str]]:
    """The property set each configuration reports for one file."""
    document = parser.parse_file(dockerfile)
    failures: list[str] = []

    hadolint_raw = _replayed(replay_dir, "hadolint", dockerfile.name)
    hadolint_items = hadolint._parse(hadolint_raw)
    if any(item.get("code") == hadolint.PARSE_ERROR_CODE for item in hadolint_items):
        failures.append("hadolint")
    hadolint_out = hadolint.BackendOutput(
        "hadolint", str(dockerfile), raw=hadolint_raw, findings_raw=hadolint_items
    )
    trivy_raw = _replayed(replay_dir, "trivy", dockerfile.name)
    trivy_out = trivy.BackendOutput(
        "trivy", str(dockerfile), raw=trivy_raw, findings_raw=trivy._parse(trivy_raw)
    )

    hadolint_rows = hadolint.normalize(hadolint_out)
    trivy_rows = trivy.normalize(trivy_out)
    native_rows = native.check(document)
    suppressed = native.suppressed_secret_lines(document)

    def without_suppressed(rows: list[dict]) -> list[dict]:
        keep = []
        for row in rows:
            property_id = row.get("property") or policy.property_of(row["source"], row["source_id"])
            if property_id == "HARD-03" and row["line"] in suppressed:
                continue
            keep.append(row)
        return keep

    detected = {
        "hadolint": _mapped(hadolint_rows),
        "trivy": _mapped(trivy_rows),
        "union": _mapped(hadolint_rows + trivy_rows),
        "native": _mapped(native_rows),
        "dhaudit": _mapped(without_suppressed(hadolint_rows + trivy_rows + native_rows)),
    }
    return detected, failures


def evaluate(labels_path: str | Path, replay_dir: str | Path) -> Evaluation:
    """Run the evaluation over the labelled corpus."""
    labels = json.loads(Path(labels_path).read_text(encoding="utf-8"))
    base = Path(labels_path).parent
    replay = Path(replay_dir)
    evaluation = Evaluation(
        metrics={name: Metrics() for name in CONFIGURATIONS},
        detected={name: {} for name in CONFIGURATIONS},
        coverage={name: set() for name in CONFIGURATIONS},
    )
    for entry in labels["files"]:
        dockerfile = (base / entry["path"]).resolve()
        expected = set(entry["expected"])
        detected, failures = detect(dockerfile, replay)
        evaluation.files.append(entry["path"])
        for backend in failures:
            evaluation.parse_failures.setdefault(backend, []).append(entry["path"])
        for name in CONFIGURATIONS:
            found = detected[name]
            evaluation.detected[name][entry["path"]] = found
            metrics = evaluation.metrics[name]
            metrics.true_positive += len(found & expected)
            metrics.false_positive += len(found - expected)
            metrics.false_negative += len(expected - found)
            evaluation.coverage[name] |= found & expected
    return evaluation


def format_report(evaluation: Evaluation, expected_values: dict | None = None) -> tuple[str, bool]:
    """The comparison table, and whether every published value reproduced."""
    lines: list[str] = []
    lines.append("Detection over the labelled corpus")
    lines.append(f"files: {len(evaluation.files)}   properties in policy: {len(policy.PROPERTIES)}")
    lines.append("")
    header = f"{'configuration':<14}{'TP':>4}{'FP':>4}{'FN':>4}{'precision':>11}{'recall':>9}{'F1':>7}{'properties':>12}"
    lines.append(header)
    lines.append("-" * len(header))
    for name in CONFIGURATIONS:
        metrics = evaluation.metrics[name]
        lines.append(
            f"{name:<14}{metrics.true_positive:>4}{metrics.false_positive:>4}{metrics.false_negative:>4}"
            f"{metrics.precision:>11.3f}{metrics.recall:>9.3f}{metrics.f1:>7.3f}"
            f"{len(evaluation.coverage[name]):>12}"
        )
    lines.append("")
    lines.append("Properties answered, by configuration")
    for name in CONFIGURATIONS:
        answered = sorted(evaluation.coverage[name])
        lines.append(f"  {name:<10}{len(answered):>3}  {', '.join(answered) if answered else '(none)'}")
    if evaluation.parse_failures:
        lines.append("")
        lines.append("Backend parse failures (silence that must not be read as a clean file)")
        for backend, files in sorted(evaluation.parse_failures.items()):
            for name in sorted(files):
                lines.append(f"  {backend}: {name}")

    ok = True
    if expected_values:
        lines.append("")
        lines.append("Published value  ·  obtained  ·  expected  ·  ok")
        for key, expected in sorted(expected_values["metrics"].items()):
            obtained = evaluation.metrics[key].to_dict()
            for field_name, value in sorted(expected.items()):
                got = obtained[field_name]
                matches = abs(got - value) < 1e-9 if isinstance(value, float) else got == value
                ok = ok and matches
                lines.append(
                    f"  {key}.{field_name:<10} {got!s:>8}   {value!s:>8}   {'ok' if matches else 'MISMATCH'}"
                )
        for key, expected in sorted(expected_values.get("coverage", {}).items()):
            got = sorted(evaluation.coverage[key])
            matches = got == sorted(expected)
            ok = ok and matches
            lines.append(
                f"  {key}.coverage  {len(got):>8}   {len(expected):>8}   {'ok' if matches else 'MISMATCH'}"
            )
        lines.append("")
        lines.append(f"RESULT: {'OK' if ok else 'FAIL'}")
    return "\n".join(lines), ok
