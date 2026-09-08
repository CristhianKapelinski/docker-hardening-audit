"""hadolint runner and output normalizer.

hadolint reads the Dockerfile from stdin, which keeps the container free of any
mount and makes the run independent of where the file lives on the host.

The parse error matters more than it looks: hadolint reports `DL1000` and NO
other finding when it cannot parse the file, which happens with BuildKit heredoc
syntax (`RUN <<EOF`). An aggregator that treats "no findings" as "clean" would
call such a file hardened. `parse_failed` carries that distinction up.
"""

from __future__ import annotations

import json

from . import BackendOutput, pinned_reference, run_container

NAME = "hadolint"
PARSE_ERROR_CODE = "DL1000"
_LEVEL = {"error": "HIGH", "warning": "MEDIUM", "info": "LOW", "style": "LOW"}


def run(dockerfile: str, source_text: str, timeout: int = 120) -> BackendOutput:
    """Run hadolint over `source_text`, labelling results with `dockerfile`."""
    args = [
        "docker", "run", "--rm", "-i", "--network", "none",
        pinned_reference(NAME), "hadolint", "-f", "json", "--no-color", "-",
    ]
    try:
        proc = run_container(args, stdin_text=source_text, timeout=timeout)
    except Exception as exc:  # timeout, docker missing, OS error
        return BackendOutput(NAME, dockerfile, ok=False, error=str(exc))
    raw = proc.stdout.strip()
    # hadolint exits non-zero when it has findings, which is not an error
    if not raw and proc.returncode not in (0, 1):
        return BackendOutput(NAME, dockerfile, ok=False, error=(proc.stderr or "").strip()[:200])
    return BackendOutput(NAME, dockerfile, raw=raw, findings_raw=_parse(raw), **_parse_flags(raw))


def _parse_flags(raw: str) -> dict:
    items = _parse(raw)
    failed = any(item.get("code") == PARSE_ERROR_CODE for item in items)
    return {"parse_failed": failed}


def _parse(raw: str) -> list[dict]:
    if not raw:
        return []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return payload if isinstance(payload, list) else []


def normalize(output: BackendOutput) -> list[dict]:
    """Backend rows in the shape the aggregator consumes."""
    rows = []
    for item in output.findings_raw:
        code = str(item.get("code", ""))
        if code == PARSE_ERROR_CODE:
            continue
        rows.append(
            {
                "source": NAME,
                "source_id": code,
                "path": output.target,
                "line": int(item.get("line") or 1),
                "severity": _LEVEL.get(str(item.get("level", "")).lower(), "LOW"),
                "message": str(item.get("message", "")).strip(),
            }
        )
    return rows
