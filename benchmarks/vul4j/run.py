"""Run jev-review on exactly the Java files listed by a Vul4J manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from jev_code_reviewer.cli import main as review


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=root / ".benchmarks" / "vul4j-cases" / "manifest.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=root / ".benchmarks" / "vul4j-report.json",
    )
    parser.add_argument("--semgrep-config", default=None)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    case_root = args.manifest.parent
    paths = [
        str(case_root / case["vul_id"] / "vulnerable" / changed["path"])
        for case in manifest["cases"]
        for changed in case.get("files", [])
    ]
    if not paths:
        raise SystemExit("manifest contains no materialized Java files")
    review_args = [
        *paths,
        "--offline",
        "--engine",
        "semgrep",
        "--format",
        "json",
        "--fail-on",
        "never",
        "--output",
        str(args.output),
    ]
    if args.semgrep_config:
        review_args.extend(("--semgrep-config", args.semgrep_config))
    return review(review_args)


if __name__ == "__main__":
    raise SystemExit(main())
