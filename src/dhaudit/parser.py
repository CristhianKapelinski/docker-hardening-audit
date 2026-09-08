"""Dockerfile parser: text to `Dockerfile` stages, with no external dependency.

It handles the three things that make naive line-by-line scanning wrong: comment
lines, line continuations (the instruction that spans five physical lines is ONE
instruction), and multi-stage builds (`FROM x AS build`), because most hardening
rules only apply to the stage that becomes the image.

Known gap, deliberate and documented: BuildKit heredoc bodies
(`RUN <<EOF ... EOF`) are counted, not parsed. The count reaches the rules so a
report can say how much of the file was not analysed.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .model import Dockerfile, Instruction, Stage

_KEYWORDS = {
    "FROM", "RUN", "CMD", "LABEL", "MAINTAINER", "EXPOSE", "ENV", "ADD", "COPY",
    "ENTRYPOINT", "VOLUME", "USER", "WORKDIR", "ARG", "ONBUILD", "STOPSIGNAL",
    "HEALTHCHECK", "SHELL",
}
_ESCAPE_DIRECTIVE = re.compile(r"^\s*#\s*escape\s*=\s*(\S)\s*$", re.IGNORECASE)
_HEREDOC_START = re.compile(r"<<-?\s*'?([A-Za-z_][A-Za-z0-9_]*)'?")
_FROM_ALIAS = re.compile(r"^(?P<image>\S+)(?:\s+(?i:as)\s+(?P<alias>\S+))?\s*$")


def _logical_lines(text: str, escape: str = "\\") -> list[tuple[int, str]]:
    """Join continuations and drop comments, keeping the starting line number."""
    out: list[tuple[int, str]] = []
    buffer: list[str] = []
    start = 0
    for number, physical in enumerate(text.splitlines(), start=1):
        stripped = physical.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if not buffer:
            start = number
        continues = stripped.endswith(escape)
        if continues:
            stripped = stripped[: -len(escape)].rstrip()
        # a comment INSIDE a continuation is dropped by the daemon too
        if buffer and stripped.startswith("#"):
            if not continues:
                out.append((start, " ".join(p for p in buffer if p)))
                buffer = []
            continue
        buffer.append(stripped)
        if not continues:
            out.append((start, " ".join(p for p in buffer if p)))
            buffer = []
    if buffer:
        out.append((start, " ".join(p for p in buffer if p)))
    return out


def parse_text(text: str, path: str = "Dockerfile", has_dockerignore: bool = True) -> Dockerfile:
    """Parse Dockerfile source into stages.

    Instructions that appear before the first `FROM` (only `ARG` is legal there)
    are attached to a synthetic stage so that a rule scanning for secrets in
    build arguments still sees them.
    """
    escape = "\\"
    for line in text.splitlines():
        match = _ESCAPE_DIRECTIVE.match(line)
        if match:
            escape = match.group(1)
            break
        if line.strip() and not line.strip().startswith("#"):
            break

    stages: list[Stage] = []
    preamble = Stage(index=-1, base_image="", alias=None, line=0)
    heredocs = 0
    inside_heredoc: str | None = None
    parse_errors: list[str] = []

    for number, logical in _logical_lines(text, escape):
        if inside_heredoc is not None:
            if logical.strip() == inside_heredoc:
                inside_heredoc = None
            continue
        keyword, _, rest = logical.partition(" ")
        keyword = keyword.upper()
        if keyword not in _KEYWORDS:
            continue
        instruction = Instruction(keyword=keyword, raw=rest.strip(), line=number)
        heredoc = _HEREDOC_START.search(instruction.raw)
        if heredoc:
            heredocs += 1
            inside_heredoc = heredoc.group(1)
        if keyword == "FROM":
            match = _FROM_ALIAS.match(instruction.raw)
            words = instruction.raw.split()
            if match:
                image, alias = match.group("image"), match.group("alias")
            elif words:
                image, alias = words[0], None
            else:
                # `FROM` with no argument is not a Dockerfile the daemon builds,
                # and indexing the empty word list here used to raise IndexError
                # and take the whole scan down with a traceback.
                parse_errors.append(f"line {number}: FROM without an image")
                image, alias = "", None
            stages.append(
                Stage(index=len(stages), base_image=image, alias=alias, line=number)
            )
            continue
        target = stages[-1] if stages else preamble
        target.instructions.append(instruction)

    if preamble.instructions and stages:
        stages[0].instructions[:0] = preamble.instructions
    elif preamble.instructions:
        stages.append(preamble)

    if not stages:
        parse_errors.append("no FROM instruction found; this is not a Dockerfile")

    return Dockerfile(
        path=path,
        stages=stages,
        has_dockerignore=has_dockerignore,
        unparsed_heredocs=heredocs,
        source_text=text,
        parse_errors=parse_errors,
    )


def parse_file(path: str | os.PathLike[str]) -> Dockerfile:
    """Parse a Dockerfile from disk, recording whether a `.dockerignore` sits next to it."""
    target = Path(path)
    text = target.read_text(encoding="utf-8", errors="replace")
    ignore = (target.parent / ".dockerignore").exists()
    return parse_text(text, path=str(target), has_dockerignore=ignore)


def looks_like_dockerfile(path: Path) -> bool:
    """Whether a path is a Dockerfile by name, covering the common variants."""
    name = path.name.lower()
    return name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile")


def discover(root: str | os.PathLike[str]) -> list[Path]:
    """Every Dockerfile under `root`, sorted, skipping version-control noise.

    A single file path is returned as itself, so the CLI accepts both a file and
    a directory without the caller having to care.
    """
    base = Path(root)
    if base.is_file():
        return [base]
    skip = {".git", "__pycache__", ".pytest_cache", "node_modules", ".venv", "venv"}
    found = [
        candidate
        for candidate in sorted(base.rglob("*"))
        if candidate.is_file()
        and looks_like_dockerfile(candidate)
        and not skip.intersection(candidate.parts)
    ]
    return found
