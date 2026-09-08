"""Core data model: severities, findings, and the parsed Dockerfile document.

Two decisions are baked in here.

A Dockerfile is modelled as a list of *stages*, not as a flat list of
instructions, because most hardening properties belong to the FINAL stage only
(the one that becomes the shipped image); a check that ignores stage boundaries
reports the build stage of a multi-stage build and is wrong.

A finding carries both the policy property it violates and the source that saw
it, so the same property reported by two backends collapses into one row without
losing the evidence of either.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable


class Severity(Enum):
    """Finding severity, ordered from most to least serious."""

    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1

    def __str__(self) -> str:
        return self.name

    @classmethod
    def parse(cls, text: str) -> "Severity":
        try:
            return cls[text.strip().upper()]
        except KeyError as exc:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {text!r}; expected one of {valid}") from exc


@dataclass(frozen=True)
class Finding:
    """One policy violation, as seen by one source, anchored at a file and line."""

    property_id: str
    severity: Severity
    path: str
    line: int
    source: str      # hadolint | trivy | dockle | native
    source_id: str   # the backend's own code, or the native check name
    message: str

    def to_dict(self) -> dict:
        return {
            "property": self.property_id,
            "severity": self.severity.name,
            "path": self.path,
            "line": self.line,
            "source": self.source,
            "source_id": self.source_id,
            "message": self.message,
        }


@dataclass(frozen=True)
class OutOfPolicy:
    """A backend check that fired but is not mapped to any policy property."""

    source: str
    source_id: str
    path: str
    line: int
    message: str

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "source_id": self.source_id,
            "path": self.path,
            "line": self.line,
            "message": self.message,
        }


@dataclass(frozen=True)
class Instruction:
    """A single Dockerfile instruction after joining line continuations.

    `line` is the 1-based line where the instruction STARTS, which is what an
    editor jumps to; `raw` keeps the argument text with continuations already
    collapsed into single spaces.
    """

    keyword: str
    raw: str
    line: int

    @property
    def words(self) -> list[str]:
        return self.raw.split()


@dataclass
class Stage:
    """One `FROM` block of a Dockerfile."""

    index: int
    base_image: str
    alias: str | None
    line: int
    instructions: list[Instruction] = field(default_factory=list)

    def of(self, *keywords: str) -> list[Instruction]:
        wanted = {k.upper() for k in keywords}
        return [i for i in self.instructions if i.keyword in wanted]


@dataclass
class Dockerfile:
    """A parsed Dockerfile: its stages plus the facts the native checks need.

    `source_text` carries the bytes the parser already read, so a caller that
    also needs the raw text (hadolint reads it from stdin) does not open the
    file a second time and cannot disagree with the parser about decoding.

    `parse_errors` is not cosmetic: an instruction the parser cannot make sense
    of has to reach the report, or the file comes back as clean.
    """

    path: str
    stages: list[Stage]
    has_dockerignore: bool
    unparsed_heredocs: int = 0
    source_text: str = ""
    parse_errors: list[str] = field(default_factory=list)

    @property
    def final_stage(self) -> Stage | None:
        """The stage that becomes the image."""
        return self.stages[-1] if self.stages else None

    @property
    def stage_aliases(self) -> set[str]:
        return {s.alias.lower() for s in self.stages if s.alias}

    def all_instructions(self) -> Iterable[Instruction]:
        for stage in self.stages:
            yield from stage.instructions


@dataclass
class ImageConfig:
    """The subset of a `docker inspect` / OCI image config that checks look at."""

    path: str
    name: str
    user: str
    env: dict[str, str]
    exposed_ports: list[str]
    has_healthcheck: bool
    repo_tags: list[str]

    @classmethod
    def from_json(cls, path: str, payload: str) -> "ImageConfig":
        """Read either a `docker inspect` array or a bare OCI image config."""
        data = json.loads(payload)
        if isinstance(data, list):
            if not data:
                raise ValueError(f"{path}: empty docker inspect array")
            data = data[0]
        if not isinstance(data, dict):
            raise ValueError(f"{path}: expected a JSON object or array of objects")
        config = data.get("Config") or data.get("config") or {}
        env: dict[str, str] = {}
        for item in config.get("Env") or []:
            key, _, value = str(item).partition("=")
            env[key] = value
        exposed = sorted((config.get("ExposedPorts") or {}).keys())
        tags = data.get("RepoTags") or []
        return cls(
            path=path,
            name=str(tags[0] if tags else data.get("Id", path)),
            user=str(config.get("User") or ""),
            env=env,
            exposed_ports=[str(p) for p in exposed],
            has_healthcheck=bool(config.get("Healthcheck") or {}),
            repo_tags=[str(t) for t in tags],
        )
