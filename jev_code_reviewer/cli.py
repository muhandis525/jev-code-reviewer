from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .diff import DiffError, changed_lines, filter_changed
from .jev_client import (
    MODEL,
    JevClient,
    JevError,
    cascade_review,
    load_api_key,
    local_review,
)
from .models import ReviewStats
from .reporters import (
    SEVERITY_ORDER,
    json_report,
    sarif_report,
    text_report,
    write_report,
)
from .scanner import DEFAULT_RULES, ScanError, scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jev-review",
        description="Find exact code issues locally, then use Jev to validate and classify them.",
    )
    parser.add_argument(
        "paths", nargs="+", type=Path, help="source files or directories to review"
    )
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument("--output", type=Path, help="write the report to a file")
    parser.add_argument(
        "--engine", choices=("hybrid", "semgrep", "builtin"), default="hybrid"
    )
    parser.add_argument(
        "--semgrep-config",
        default=str(DEFAULT_RULES),
        help="bundled YAML, registry pack, or auto",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.55,
        help="minimum Jev issue probability (default: 0.55)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=8,
        help="candidates per Jev request (default: 8)",
    )
    parser.add_argument(
        "--key-file",
        type=Path,
        help="read the Jev key from PATH (environment variables are preferred)",
    )
    parser.add_argument(
        "--model", default=MODEL, help=f"Jev model name (default: {MODEL})"
    )
    parser.add_argument(
        "--triage",
        choices=("smart", "all"),
        default="smart",
        help="smart sends only ambiguous candidates to Jev; all sends every candidate (default: smart)",
    )
    parser.add_argument(
        "--local-confidence",
        type=float,
        default=0.90,
        help="smart-mode confidence required for a zero-token local decision (default: 0.90)",
    )
    parser.add_argument(
        "--max-jev-candidates",
        type=int,
        help="hard per-run Jev review budget; highest-risk candidates are sent first",
    )
    parser.add_argument(
        "--cache",
        type=Path,
        default=Path(".jev-review-cache.json"),
        help="content-addressed decision cache; contains no source code",
    )
    parser.add_argument(
        "--no-cache", action="store_true", help="disable the Jev decision cache"
    )
    parser.add_argument(
        "--changed-since",
        metavar="GIT_REF",
        help="report only findings that intersect lines changed since a Git revision",
    )
    parser.add_argument(
        "--offline", action="store_true", help="skip Jev and report raw local findings"
    )
    parser.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "info", "never"),
        default="high",
        help="exit 1 when this severity or worse is found (default: high)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not 0.0 <= args.threshold <= 1.0:
        raise SystemExit("--threshold must be between 0 and 1")
    if not 1 <= args.batch_size <= 8:
        raise SystemExit("--batch-size must be between 1 and 8")
    if not 0.0 <= args.local_confidence <= 1.0:
        raise SystemExit("--local-confidence must be between 0 and 1")
    if args.max_jev_candidates is not None and args.max_jev_candidates < 0:
        raise SystemExit("--max-jev-candidates cannot be negative")
    missing = [str(path) for path in args.paths if not path.exists()]
    if missing:
        print(f"error: path does not exist: {', '.join(missing)}", file=sys.stderr)
        return 2
    try:
        candidates = scan(args.paths, args.engine, args.semgrep_config)
        if args.changed_since:
            candidates = filter_changed(
                candidates, changed_lines(args.paths, args.changed_since)
            )
        if args.offline:
            findings = local_review(candidates)
            stats = ReviewStats(
                candidates=len(candidates), locally_decided=len(candidates)
            )
        else:
            if args.triage == "smart" and all(
                candidate.detector_confidence >= args.local_confidence
                for candidate in candidates
            ):
                findings = local_review(candidates)
                stats = ReviewStats(
                    candidates=len(candidates), locally_decided=len(candidates)
                )
            elif args.max_jev_candidates == 0:
                local_candidates = (
                    [
                        item
                        for item in candidates
                        if item.detector_confidence >= args.local_confidence
                    ]
                    if args.triage == "smart"
                    else []
                )
                findings = local_review(local_candidates)
                stats = ReviewStats(
                    candidates=len(candidates),
                    locally_decided=len(local_candidates),
                    budget_skipped=len(candidates) - len(local_candidates),
                )
            else:
                key = load_api_key(args.key_file)
                client = JevClient(
                    key,
                    batch_size=args.batch_size,
                    model=args.model,
                    cache_path=None if args.no_cache else args.cache,
                )
                if args.triage == "all":
                    selected = sorted(
                        candidates,
                        key=lambda item: (
                            SEVERITY_ORDER.get(item.suggested_severity, 9),
                            -item.detector_confidence,
                            str(item.path),
                            item.start_line,
                        ),
                    )
                    if args.max_jev_candidates is not None:
                        selected = selected[: args.max_jev_candidates]
                    findings = client.review(selected, args.threshold)
                    stats = client.stats
                    stats.candidates = len(candidates)
                    stats.budget_skipped = len(candidates) - len(selected)
                else:
                    findings, stats = cascade_review(
                        candidates,
                        client,
                        args.threshold,
                        args.local_confidence,
                        args.max_jev_candidates,
                    )
    except (ScanError, JevError, DiffError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        content = json_report(findings, len(candidates), stats)
    elif args.format == "sarif":
        content = sarif_report(findings)
    else:
        content = text_report(
            findings,
            len(candidates),
            use_color=args.output is None and sys.stdout.isatty(),
            stats=stats,
        )
    write_report(content, args.output)

    if args.fail_on == "never":
        return 0
    limit = SEVERITY_ORDER[args.fail_on]
    return (
        1
        if any(
            SEVERITY_ORDER.get(finding.severity, 99) <= limit for finding in findings
        )
        else 0
    )


if __name__ == "__main__":
    raise SystemExit(main())
