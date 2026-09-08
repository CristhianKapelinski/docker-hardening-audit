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

from dataclasses import dataclass

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
_PERMISSIVE_MODE = re.compile(r"\b(?:0?777|0?666|[ugoa]*[+=][rwx]*w[rwx]*)\b")
_SUBSTITUTED_DOWNLOAD = re.compile(r"[$<]\(\s*(?:curl|wget)\b|`\s*(?:curl|wget)\b", re.IGNORECASE)
_DOWNLOADERS = {"curl", "wget"}
_SHELLS = {"sh", "bash", "zsh", "dash", "ash", "busybox"}
# Commands whose arguments are TEXT, not execution. Dropping their segments is
# what keeps `RUN echo "do not run: curl x | sh"` from being reported as a
# download piped into a shell, and `RUN echo "chmod 777 was used" > NOTES` from
# being reported as a permission change. Both were real false positives.
_TEXT_ONLY = {"echo", "printf", ":", "true", "false", "#"}
_REMOTE_SOURCE = re.compile(r"\b(?:https?|ftp)://|\bgit@", re.IGNORECASE)

NAME = "native"


@dataclass(frozen=True)
class Segment:
    """One command in a shell line: the operator before it, and its words."""

    operator: str   # "", "&&", "||", ";", "|"
    text: str

    @property
    def words(self) -> list[str]:
        return self.text.split()

    @property
    def program(self) -> str:
        """The first word that is a program, skipping `VAR=value` prefixes."""
        for word in self.words:
            if "=" in word and not word.startswith("-"):
                continue          # VAR=value prefix
            return word.split("/")[-1]
        return ""

    @property
    def command(self) -> str:
        """The program being run, looking PAST `sudo`.

        `sudo chmod 777 /app` is a chmod for every check except the one that
        cares about sudo itself, which reads `program` instead.
        """
        words = self.words
        for index, word in enumerate(words):
            if "=" in word and not word.startswith("-"):
                continue
            if word.split("/")[-1] == "sudo":
                continue
            return word.split("/")[-1]
        return ""


def split_command(command: str) -> list[Segment]:
    """Split a shell command on `&&`, `||`, `;` and `|` OUTSIDE quotes.

    Matching a regex against the whole `RUN` line cannot tell a command from a
    string that mentions one. This scanner tracks quoting, so text inside `echo`
    stays inside the `echo` segment and is dropped by `_executable`.
    """
    segments: list[Segment] = []
    quote: str | None = None
    escaped = False
    buffer: list[str] = []
    operator = ""
    index = 0
    while index < len(command):
        char = command[index]
        if escaped:
            buffer.append(char)
            escaped = False
        elif char == "\\":
            buffer.append(char)
            escaped = True
        elif quote:
            buffer.append(char)
            if char == quote:
                quote = None
        elif char in "\"'":
            buffer.append(char)
            quote = char
        else:
            two = command[index : index + 2]
            if two in ("&&", "||"):
                segments.append(Segment(operator, "".join(buffer).strip()))
                operator, buffer, index = two, [], index + 2
                continue
            if char in ";|":
                segments.append(Segment(operator, "".join(buffer).strip()))
                operator, buffer = char if char == ";" else "|", []
            else:
                buffer.append(char)
        index += 1
    segments.append(Segment(operator, "".join(buffer).strip()))
    return [segment for segment in segments if segment.text]


def _executable(command: str) -> list[Segment]:
    """The segments that actually run something."""
    return [s for s in split_command(command) if s.program not in _TEXT_ONLY]


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
    """A download whose output is executed, in either of the two usual forms."""
    rows = []
    for instruction in doc.all_instructions():
        if instruction.keyword != "RUN":
            continue
        segments = _executable(instruction.raw)
        for position, segment in enumerate(segments):
            piped_into_shell = (
                segment.operator == "|"
                and segment.command in _SHELLS
                and position > 0
                and segments[position - 1].command in _DOWNLOADERS
            )
            substituted = segment.command in _SHELLS and _SUBSTITUTED_DOWNLOAD.search(segment.text)
            if piped_into_shell or substituted:
                rows.append(_row("NAT-PIPE", "HARD-04", "HIGH", doc, instruction.line,
                                 "RUN executes the output of a download without verifying it"))
                break
    return rows


def _add_remote(doc: Dockerfile) -> list[dict]:
    rows = []
    for instruction in doc.all_instructions():
        if instruction.keyword == "ADD" and _REMOTE_SOURCE.search(instruction.raw):
            rows.append(_row("NAT-ADD-REMOTE", "HARD-06", "MEDIUM", doc, instruction.line,
                             "ADD downloads a remote resource without verifying it"))
    return rows


def _world_writable(doc: Dockerfile) -> list[dict]:
    """A real `chmod` to a permissive mode, or `COPY --chmod=` with one."""
    rows = []
    for instruction in doc.all_instructions():
        if instruction.keyword == "RUN":
            for segment in _executable(instruction.raw):
                if segment.command != "chmod":
                    continue
                arguments = " ".join(word for word in segment.words if word != "chmod")
                if _PERMISSIVE_MODE.search(arguments):
                    rows.append(_row("NAT-WORLD-WRITABLE", "HARD-07", "HIGH", doc, instruction.line,
                                     "chmod grants write permission to every user in the image"))
                    break
        elif instruction.keyword in {"COPY", "ADD"}:
            for word in instruction.words:
                if word.startswith("--chmod=") and _PERMISSIVE_MODE.search(word):
                    rows.append(_row("NAT-WORLD-WRITABLE", "HARD-07", "HIGH", doc, instruction.line,
                                     "COPY sets a mode writable by every user in the image"))
                    break
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
    installers = {"apt", "apt-get", "apk", "yum", "dnf", "zypper"}
    for instruction in stage.of("RUN"):
        for segment in _executable(instruction.raw):
            words = [word.lower() for word in segment.words]
            if segment.program == "sudo":
                return [_row("NAT-SUDO", "HARD-10", "HIGH", doc, instruction.line,
                             "sudo is invoked in the final stage")]
            if segment.command in installers and "sudo" in words:
                return [_row("NAT-SUDO", "HARD-10", "HIGH", doc, instruction.line,
                             "the sudo package is installed in the final stage")]
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
