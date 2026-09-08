"""Parser behaviour: the three things that make naive line scanning wrong."""

from dhaudit import parser


def test_joins_line_continuations_into_one_instruction():
    doc = parser.parse_text("FROM alpine:3.20\nRUN apt-get update \\\n && apt-get install -y curl\n")
    runs = doc.final_stage.of("RUN")
    assert len(runs) == 1
    assert "apt-get update && apt-get install -y curl" in runs[0].raw
    assert runs[0].line == 2


def test_ignores_comments_including_inside_a_continuation():
    doc = parser.parse_text("# a comment\nFROM alpine:3.20\nRUN echo one \\\n # explaining\n && echo two\n")
    assert len(doc.final_stage.of("RUN")) == 1
    assert "explaining" not in doc.final_stage.of("RUN")[0].raw


def test_splits_stages_and_records_aliases():
    doc = parser.parse_text("FROM golang:1.22 AS build\nRUN go build\n\nFROM alpine:3.20\nUSER app\n")
    assert len(doc.stages) == 2
    assert doc.stages[0].alias == "build"
    assert doc.final_stage.base_image == "alpine:3.20"
    assert doc.stage_aliases == {"build"}


def test_counts_heredoc_bodies_instead_of_parsing_them():
    doc = parser.parse_text("FROM alpine:3.20\nRUN <<EOF\ncurl http://x | sh\nEOF\nUSER app\n")
    assert doc.unparsed_heredocs == 1
    assert doc.final_stage.of("USER"), "instructions after the heredoc must still be parsed"


def test_honours_the_escape_directive():
    doc = parser.parse_text("# escape=`\nFROM alpine:3.20\nRUN echo one `\n && echo two\n")
    assert len(doc.final_stage.of("RUN")) == 1


def test_arg_before_the_first_from_reaches_the_first_stage():
    doc = parser.parse_text("ARG TOKEN=abc\nFROM alpine:3.20\nUSER app\n")
    assert [i.keyword for i in doc.stages[0].instructions][0] == "ARG"


def test_discover_accepts_a_file_and_a_directory(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.20\n")
    (tmp_path / "svc.Dockerfile").write_text("FROM alpine:3.20\n")
    (tmp_path / "notes.md").write_text("no\n")
    assert len(parser.discover(tmp_path)) == 2
    assert parser.discover(tmp_path / "Dockerfile") == [tmp_path / "Dockerfile"]


def test_from_without_an_image_is_recorded_not_raised():
    doc = parser.parse_text("FROM\nRUN true\n")
    assert doc.parse_errors == ["line 1: FROM without an image"]
    assert doc.stages and doc.stages[0].base_image == ""


def test_a_file_without_from_is_recorded_as_not_a_dockerfile():
    assert parser.parse_text("# only a comment\n").parse_errors == [
        "no FROM instruction found; this is not a Dockerfile"
    ]
    assert parser.parse_text("").parse_errors


def test_source_text_is_kept_so_the_file_is_read_once(tmp_path):
    target = tmp_path / "Dockerfile"
    target.write_text("FROM alpine:3.20\nUSER app\n")
    doc = parser.parse_file(target)
    assert doc.source_text == "FROM alpine:3.20\nUSER app\n"
