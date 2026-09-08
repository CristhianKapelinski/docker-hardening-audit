"""Command line interface.

Exit codes are the contract a pipeline depends on: 0 clean, 1 a violation at or
above the failure threshold, 2 a usage or input error. A backend that could not
run does not change the exit code by itself, but it is always printed, so a
green pipeline can never hide a scanner that never started.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, aggregate, evaluate, report
from .backends import PINNED, verify
from .model import Severity


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dhaudit",
        description=(
            "Audit Docker image hardening by orchestrating hadolint, trivy and dockle, "
            "mapping their output onto one policy, and filling the gaps they leave."
        ),
    )
    parser.add_argument("--version", action="version", version=f"dhaudit {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="audit Dockerfiles or a docker inspect config")
    scan.add_argument("targets", nargs="+", help="Dockerfile, directory, or *.json image config")
    scan.add_argument("--format", choices=("table", "json", "sarif"), default="table")
    scan.add_argument("--min-severity", default="low", help="low, medium, high or critical")
    scan.add_argument("--fail-on", default="high", help="exit 1 at this severity or above; `none` disables")
    scan.add_argument("--replay", metavar="DIR", help="read backend output from DIR instead of running them")
    scan.add_argument("--output", metavar="FILE", help="write the report to FILE instead of stdout")

    image = sub.add_parser("image", help="audit a built image with dockle")
    image.add_argument("reference", help="local image reference, such as dhaudit:local")
    image.add_argument("--format", choices=("table", "json", "sarif"), default="table")
    image.add_argument("--fail-on", default="high")

    sub.add_parser("policy", help="print the policy and the pinned backends")

    backends = sub.add_parser("backends", help="verify the pinned backend images")
    backends.add_argument("--json", action="store_true")

    corpus = sub.add_parser("evaluate", help="score the corpus and compare with the published values")
    corpus.add_argument("--labels", default="corpus/labels.json")
    corpus.add_argument("--replay", default="corpus/raw")
    corpus.add_argument("--expected", default="expected/values.json")
    corpus.add_argument("--json", action="store_true")
    return parser


def _severity(text: str) -> Severity | None:
    if text.strip().lower() == "none":
        return None
    return Severity.parse(text)


def _exit_code(result: aggregate.AuditResult, fail_on: Severity | None) -> int:
    """0 clean, 1 violation at or above the threshold, 2 input error.

    The input error wins over the violation: a run that could not read one of
    its targets did not audit it, and returning 0 or 1 would tell the pipeline
    that it did.
    """
    if result.errors:
        return 2
    if fail_on is None:
        return 0
    worst = result.worst()
    return 1 if worst is not None and worst.value >= fail_on.value else 0


def cmd_scan(args) -> int:
    replay = Path(args.replay) if args.replay else None
    result = aggregate.audit(
        args.targets, min_severity=Severity.parse(args.min_severity), replay_dir=replay
    )
    text = report.render(result, args.format, __version__)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        print(text)
    return _exit_code(result, _severity(args.fail_on))


def cmd_image(args) -> int:
    result = aggregate.AuditResult()
    aggregate.audit_image(args.reference, result)
    print(report.render(result, args.format, __version__))
    return _exit_code(result, _severity(args.fail_on))


def cmd_policy(_args) -> int:
    print(report.format_policy())
    return 0


def cmd_backends(args) -> int:
    statuses = [verify(name) for name in PINNED]
    if args.json:
        import json

        print(json.dumps([status.__dict__ for status in statuses], indent=2))
    else:
        for status in statuses:
            mark = "ok" if status.available else "unavailable"
            print(f"{status.name:<10}{mark:<14}{status.image}@{status.digest}")
            if not status.available:
                print(f"{'':<10}{status.reason}")
    return 0 if all(status.available for status in statuses) else 1


def cmd_evaluate(args) -> int:
    import json

    evaluation = evaluate.evaluate(args.labels, args.replay)
    expected = None
    expected_path = Path(args.expected)
    if expected_path.exists():
        expected = json.loads(expected_path.read_text(encoding="utf-8"))
    if args.json:
        print(json.dumps(evaluation.to_dict(), indent=2))
        return 0
    text, ok = evaluate.format_report(evaluation, expected)
    print(text)
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "scan": cmd_scan,
        "image": cmd_image,
        "policy": cmd_policy,
        "backends": cmd_backends,
        "evaluate": cmd_evaluate,
    }
    try:
        return handlers[args.command](args)
    except (ValueError, OSError) as exc:
        print(f"dhaudit: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
