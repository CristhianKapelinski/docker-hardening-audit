"""The corpus claim is gated by the test suite, not only by the reproduce script."""

import json
from pathlib import Path

from dhaudit import evaluate

ROOT = Path(__file__).resolve().parents[1]


def run():
    return evaluate.evaluate(ROOT / "corpus" / "labels.json", ROOT / "corpus" / "raw")


def test_the_aggregate_has_no_false_positive_on_the_corpus():
    assert run().metrics["dhaudit"].false_positive == 0


def test_the_aggregate_answers_every_dockerfile_property():
    evaluation = run()
    assert len(evaluation.coverage["dhaudit"]) == 12


def test_the_aggregate_beats_the_union_of_the_backends():
    evaluation = run()
    assert evaluation.metrics["dhaudit"].recall > evaluation.metrics["union"].recall
    assert evaluation.metrics["dhaudit"].precision >= evaluation.metrics["union"].precision


def test_the_only_missed_property_is_the_documented_heredoc_case():
    evaluation = run()
    assert evaluation.metrics["dhaudit"].false_negative == 1
    missed = [
        path
        for path, found in evaluation.detected["dhaudit"].items()
        if "HARD-04" not in found and path.endswith("vuln_15_heredoc_pipe.Dockerfile")
    ]
    assert missed


def test_published_values_match_the_recomputed_ones():
    expected = json.loads((ROOT / "expected" / "values.json").read_text(encoding="utf-8"))
    _text, ok = evaluate.format_report(run(), expected)
    assert ok
