"""Native checks, each with a positive and a negative control.

A check that only ever sees the failing case is not evidence that it works, so
every test asserts both that the finding appears where it should and that it
does NOT appear on the hardened variant.
"""

import pytest

from dhaudit import parser
from dhaudit.backends import native

PIN = "python:3.12-slim@sha256:af4e85f1cac90dd3771e47292ea7c8a9830abfabbe4faa5c53f158854c2e819d"


def properties(text, has_dockerignore=True):
    doc = parser.parse_text(text, path="Dockerfile", has_dockerignore=has_dockerignore)
    return {row["property"] for row in native.check(doc)}


def test_root_user_reported_and_not_reported():
    assert "HARD-01" in properties(f"FROM {PIN}\nCMD [\"x\"]\n")
    assert "HARD-01" not in properties(f"FROM {PIN}\nUSER app\nCMD [\"x\"]\n")


def test_explicit_user_root_is_reported():
    assert "HARD-01" in properties(f"FROM {PIN}\nUSER app\nUSER root\n")


def test_user_inherited_through_the_stage_alias_chain():
    text = f"FROM {PIN} AS base\nUSER app\n\nFROM base\nWORKDIR /app\n"
    assert "HARD-01" not in properties(text)


def test_digest_pinning_covers_any_mutable_tag():
    assert "HARD-02" in properties("FROM python:3.12-slim\nUSER app\n")
    assert "HARD-02" in properties("FROM python\nUSER app\n")
    assert "HARD-02" not in properties(f"FROM {PIN}\nUSER app\n")
    assert "HARD-02" not in properties("FROM scratch\nUSER 10001\n")


def test_digest_pinning_also_covers_build_stages():
    text = f"FROM python:3.12-slim AS build\nRUN true\n\nFROM {PIN}\nUSER app\n"
    assert "HARD-02" in properties(text)


@pytest.mark.parametrize(
    "command",
    [
        "curl -fsSL https://x.invalid/i.sh | sh",
        "wget -qO- https://x.invalid/i.sh | bash",
        'sh -c "$(curl -fsSL https://x.invalid/i.sh)"',
    ],
)
def test_pipe_to_shell_variants(command):
    assert "HARD-04" in properties(f"FROM {PIN}\nRUN {command}\nUSER app\n")


def test_pipe_to_shell_not_reported_when_the_download_is_verified():
    text = (
        f"FROM {PIN}\n"
        "RUN curl -fsSL -o /tmp/i.sh https://x.invalid/i.sh "
        "&& echo 'abc /tmp/i.sh' | sha256sum -c - && sh /tmp/i.sh\n"
        "USER app\n"
    )
    assert "HARD-04" not in properties(text)


def test_add_remote_versus_local_archive():
    assert "HARD-06" in properties(f"FROM {PIN}\nADD https://x.invalid/a.tgz /opt/\nUSER app\n")
    assert "HARD-06" not in properties(f"FROM {PIN}\nADD vendor/a.tgz /opt/\nUSER app\n")


@pytest.mark.parametrize("mode", ["777", "0777", "-R 777", "a+w", "o+w"])
def test_world_writable_modes(mode):
    assert "HARD-07" in properties(f"FROM {PIN}\nRUN chmod {mode} /app\nUSER app\n")


def test_narrow_mode_is_not_reported():
    assert "HARD-07" not in properties(f"FROM {PIN}\nRUN chmod 0750 /app\nUSER app\n")


def test_sensitive_port_beyond_the_one_trivy_covers():
    assert "HARD-08" in properties(f"FROM {PIN}\nUSER app\nEXPOSE 5432\n")
    assert "HARD-08" in properties(f"FROM {PIN}\nUSER app\nEXPOSE 6379/tcp\n")
    assert "HARD-08" not in properties(f"FROM {PIN}\nUSER app\nEXPOSE 8000\n")


def test_sudo_installed_and_invoked():
    assert "HARD-10" in properties(f"FROM {PIN}\nRUN apt-get install -y sudo\nUSER app\n")
    assert "HARD-10" in properties(f"FROM {PIN}\nRUN sudo chown app /app\nUSER app\n")
    assert "HARD-10" not in properties(f"FROM {PIN}\nRUN chown app /app\nUSER app\n")


def test_sudo_in_a_build_stage_is_not_shipped():
    text = f"FROM {PIN} AS build\nRUN apt-get install -y sudo\n\nFROM {PIN}\nUSER app\n"
    assert "HARD-10" not in properties(text)


def test_dockerignore_only_when_the_whole_context_is_copied():
    assert "HARD-12" in properties(f"FROM {PIN}\nCOPY . .\nUSER app\n", has_dockerignore=False)
    assert "HARD-12" not in properties(f"FROM {PIN}\nCOPY . .\nUSER app\n", has_dockerignore=True)
    assert "HARD-12" not in properties(f"FROM {PIN}\nCOPY src/ ./src/\nUSER app\n", has_dockerignore=False)


def test_secret_arbitration_suppresses_arg_without_default():
    doc = parser.parse_text(f"FROM {PIN}\nARG API_TOKEN\nENV DB_PASSWORD=hunter2\nUSER app\n")
    suppressed = native.suppressed_secret_lines(doc)
    assert 2 in suppressed, "ARG with no default leaks nothing"
    assert 3 not in suppressed, "ENV with a literal value must stay reported"
