"""trivy config runner and output normalizer.

trivy needs its checks bundle, which it fetches from a registry on the first run
and caches afterwards. The runner mounts a cache directory and passes
`--skip-check-update` so a warmed cache makes the scan work with the container
network disabled; when the cache is cold it retries once with the network on and
says so, which keeps the first run from failing on a fresh machine.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from . import BackendOutput, pinned_reference, run_container

NAME = "trivy"
DEFAULT_CACHE = Path(os.environ.get("DHAUDIT_TRIVY_CACHE", str(Path.home() / ".cache" / "dhaudit-trivy")))


def _args(directory: Path, filename: str, cache: Path, offline: bool) -> list[str]:
    args = [
        "docker", "run", "--rm",
        "-v", f"{cache}:/root/.cache",
        "-v", f"{directory}:/scan:ro",
    ]
    if offline:
        args += ["--network", "none"]
    args += [pinned_reference(NAME), "config", "--quiet", "--format", "json"]
    if offline:
        args += ["--skip-check-update"]
    args += [f"/scan/{filename}"]
    return args


def run(dockerfile: str, cache: Path | None = None, timeout: int = 300) -> BackendOutput:
    """Run `trivy config` over one Dockerfile."""
    path = Path(dockerfile).resolve()
    cache = cache or DEFAULT_CACHE
    cache.mkdir(parents=True, exist_ok=True)
    warmed = any(cache.rglob("*.json")) or any(cache.iterdir())
    attempts = [True, False] if warmed else [False]
    last_error = ""
    for offline in attempts:
        try:
            proc = run_container(_args(path.parent, path.name, cache, offline), timeout=timeout)
        except Exception as exc:
            last_error = str(exc)
            continue
        raw = proc.stdout.strip()
        if raw.startswith("{"):
            return BackendOutput(NAME, dockerfile, raw=raw, findings_raw=_parse(raw))
        last_error = (proc.stderr or proc.stdout or "").strip()[:200]
    return BackendOutput(NAME, dockerfile, ok=False, error=last_error or "no JSON output")


def _parse(raw: str) -> list[dict]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return []
    rows: list[dict] = []
    for result in payload.get("Results") or []:
        for item in result.get("Misconfigurations") or []:
            rows.append(item)
    return rows


def normalize(output: BackendOutput) -> list[dict]:
    rows = []
    for item in output.findings_raw:
        cause = item.get("CauseMetadata") or {}
        rows.append(
            {
                "source": NAME,
                "source_id": str(item.get("ID", "")),
                "path": output.target,
                "line": int(cause.get("StartLine") or 1),
                "severity": str(item.get("Severity", "LOW")).upper(),
                "message": str(item.get("Title", "")).strip(),
            }
        )
    return rows
