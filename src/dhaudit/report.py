"""Output formats: human table, machine JSON, and SARIF for code-scanning UIs.

Three things appear in every format because leaving them out would misrepresent
the run: which backends actually ran, which files a backend could not parse (its
silence is not a clean result), and which backend findings were suppressed by
arbitration.
"""

from __future__ import annotations

import json

from . import policy
from .aggregate import AuditResult

TOOL_NAME = "dhaudit"
_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}


def format_table(result: AuditResult, tool_version: str) -> str:
    lines: list[str] = []
    for violation in result.sorted_violations():
        prop = policy.get(violation.property_id)
        sources = ", ".join(violation.sources)
        lines.append(
            f"{violation.property_id}  {violation.severity.name:<8}  "
            f"{violation.path}:{violation.line}  [{sources}]"
        )
        lines.append(f"    {prop.title}")
        for item in sorted(violation.evidence, key=lambda e: (e.source, e.source_id)):
            lines.append(f"      - {item.source}:{item.source_id} line {item.line}: {item.message}")
        lines.append(f"    fix: {prop.remediation}")
        lines.append("")

    counts = result.counts_by_severity()
    summary = "  ".join(
        f"{name.lower()}={counts[name]}" for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    )
    lines.append(
        f"{TOOL_NAME} {tool_version}: {len(result.violations)} violation(s) "
        f"in {len(result.files)} file(s)"
    )
    lines.append(summary)
    ran = ", ".join(
        f"{b.name}"
        + ("" if b.available and b.image != "replay" else (" (replay)" if b.image == "replay" else " (unavailable)"))
        for b in result.backends
    )
    lines.append(f"backends: {ran}")
    for backend in result.backends:
        if not backend.available:
            lines.append(f"  ! {backend.name}: {backend.reason}")
    for failure in result.parse_failures:
        lines.append(f"  ! {failure['source']} could not parse {failure['path']}: {failure['note']}")
    if result.suppressed:
        lines.append(f"suppressed by arbitration: {len(result.suppressed)}")
        for item in result.suppressed:
            lines.append(
                f"  - {item['source']}:{item['source_id']} on {item['path']}:{item['line']} ({item['reason']})"
            )
    if result.out_of_policy:
        codes = sorted({f"{o.source}:{o.source_id}" for o in result.out_of_policy})
        lines.append(
            f"out of policy: {len(result.out_of_policy)} backend finding(s) "
            f"({', '.join(codes)}); see the json output for the detail"
        )
    for error in result.errors:
        lines.append(f"error: {error}")
    return "\n".join(lines)


def format_json(result: AuditResult, tool_version: str) -> str:
    from .aggregate import as_json

    payload = json.loads(as_json(result))
    payload["tool"] = TOOL_NAME
    payload["version"] = tool_version
    return json.dumps(payload, indent=2, ensure_ascii=False)


def format_sarif(result: AuditResult, tool_version: str) -> str:
    used = sorted({v.property_id for v in result.violations})
    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": tool_version,
                        "rules": [
                            {
                                "id": property_id,
                                "name": policy.get(property_id).title,
                                "shortDescription": {"text": policy.get(property_id).title},
                                "fullDescription": {"text": policy.get(property_id).rationale},
                                "help": {"text": policy.get(property_id).remediation},
                                "defaultConfiguration": {
                                    "level": _SARIF_LEVEL[policy.get(property_id).severity.name]
                                },
                            }
                            for property_id in used
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": violation.property_id,
                        "level": _SARIF_LEVEL[violation.severity.name],
                        "message": {
                            "text": policy.get(violation.property_id).title
                            + " ("
                            + ", ".join(
                                f"{e.source}:{e.source_id}"
                                for e in sorted(violation.evidence, key=lambda e: e.source)
                            )
                            + ")"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": violation.path},
                                    "region": {"startLine": max(violation.line, 1)},
                                }
                            }
                        ],
                    }
                    for violation in result.sorted_violations()
                ],
            }
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def format_policy() -> str:
    """The policy catalogue: property, severity, and who answers it."""
    from .backends import PINNED
    from .policy import BACKEND_MAP, NATIVE_JUSTIFICATION

    by_property: dict[str, list[str]] = {}
    for key, property_id in BACKEND_MAP.items():
        by_property.setdefault(property_id, []).append(key)
    for property_id in NATIVE_JUSTIFICATION:
        by_property.setdefault(property_id, []).append("native")

    lines = [f"{'PROPERTY':<10}{'SEVERITY':<10}{'TARGET':<12}TITLE"]
    for prop in policy.PROPERTIES.values():
        lines.append(f"{prop.property_id:<10}{prop.severity.name:<10}{prop.target:<12}{prop.title}")
        answered = ", ".join(sorted(by_property.get(prop.property_id, ["(nothing)"])))
        lines.append(f"{'':<10}answered by: {answered}")
    lines.append("")
    lines.append("pinned backends:")
    for name, (image, digest) in PINNED.items():
        lines.append(f"  {name:<10}{image}@{digest}")
    return "\n".join(lines)


def render(result: AuditResult, fmt: str, tool_version: str) -> str:
    formatters = {"table": format_table, "json": format_json, "sarif": format_sarif}
    if fmt not in formatters:
        raise ValueError(f"unknown format {fmt!r}")
    return formatters[fmt](result, tool_version)
