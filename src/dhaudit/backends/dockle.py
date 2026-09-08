"""dockle runner: the only backend that reads a BUILT image, not a Dockerfile.

It answers the two properties a Dockerfile cannot: what the shipped config
actually says, and what the layers actually contain. It needs the Docker socket
because it inspects the local image, so it is opt-in (`--image`), and the audit
of a Dockerfile never requires it.
"""

from __future__ import annotations

import json

from . import BackendOutput, pinned_reference, run_container

NAME = "dockle"
_LEVEL = {"FATAL": "CRITICAL", "WARN": "HIGH", "INFO": "MEDIUM", "SKIP": "LOW", "PASS": "LOW"}


def run(image: str, timeout: int = 300) -> BackendOutput:
    """Run dockle against a local image reference."""
    args = [
        "docker", "run", "--rm",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        pinned_reference(NAME), "--format", "json", "--exit-code", "0", image,
    ]
    try:
        proc = run_container(args, timeout=timeout)
    except Exception as exc:
        return BackendOutput(NAME, image, ok=False, error=str(exc))
    raw = proc.stdout.strip()
    if not raw.startswith("{"):
        return BackendOutput(NAME, image, ok=False, error=(proc.stderr or raw or "").strip()[:200])
    return BackendOutput(NAME, image, raw=raw, findings_raw=_parse(raw))


def _parse(raw: str) -> list[dict]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return [item for item in (payload.get("details") or []) if str(item.get("level")) not in {"PASS", "SKIP"}]


def normalize(output: BackendOutput) -> list[dict]:
    rows = []
    for item in output.findings_raw:
        alerts = item.get("alerts") or []
        rows.append(
            {
                "source": NAME,
                "source_id": str(item.get("code", "")),
                "path": output.target,
                "line": 1,
                "severity": _LEVEL.get(str(item.get("level", "")).upper(), "LOW"),
                "message": (str(item.get("title", "")) + (f": {alerts[0]}" if alerts else "")).strip(),
            }
        )
    return rows
