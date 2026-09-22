#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def same_file(expected: dict[str, Any], finding: dict[str, Any]) -> bool:
    return Path(finding["path"]).name == Path(expected["path"]).name


def location_matches(expected: dict[str, Any], finding: dict[str, Any]) -> bool:
    valid_lines = expected.get("lines", [expected["line"]])
    return same_file(expected, finding) and any(
        int(finding["start_line"]) <= int(line) <= int(finding["end_line"])
        for line in valid_lines
    )


def score(truth: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    expected = truth["issues"]
    findings = report["findings"]
    unmatched_expected = set(range(len(expected)))
    unmatched_findings = set(range(len(findings)))
    matches: list[tuple[int, int]] = []

    # Match the narrowest source ranges first so a broad finding cannot steal a
    # more precise expected issue from a line-specific finding.
    finding_order = sorted(
        unmatched_findings,
        key=lambda index: findings[index]["end_line"] - findings[index]["start_line"],
    )
    for finding_index in finding_order:
        finding = findings[finding_index]
        options = [
            index
            for index in unmatched_expected
            if location_matches(expected[index], finding)
        ]
        if not options:
            continue
        options.sort(
            key=lambda index: (
                expected[index]["category"] != finding["category"],
                abs(
                    SEVERITY[expected[index]["severity"]]
                    - SEVERITY[finding["severity"]]
                ),
            )
        )
        expected_index = options[0]
        matches.append((expected_index, finding_index))
        unmatched_expected.remove(expected_index)
        unmatched_findings.remove(finding_index)

    tp = len(matches)
    precision = tp / len(findings) if findings else 1.0
    recall = tp / len(expected) if expected else 1.0
    classification = (
        sum(expected[e]["category"] == findings[f]["category"] for e, f in matches) / tp
        if tp
        else 0.0
    )
    severity_exact = (
        sum(expected[e]["severity"] == findings[f]["severity"] for e, f in matches) / tp
        if tp
        else 0.0
    )
    severity_near = (
        sum(
            abs(SEVERITY[expected[e]["severity"]] - SEVERITY[findings[f]["severity"]])
            <= 1
            for e, f in matches
        )
        / tp
        if tp
        else 0.0
    )
    overall = 100 * (
        0.30 * precision + 0.45 * recall + 0.15 * classification + 0.10 * severity_near
    )
    grade = (
        "A"
        if overall >= 90
        else "B"
        if overall >= 80
        else "C"
        if overall >= 65
        else "D"
        if overall >= 50
        else "F"
    )

    return {
        "expected_issues": len(expected),
        "reported_findings": len(findings),
        "true_positive_locations": tp,
        "false_positives": [findings[index] for index in sorted(unmatched_findings)],
        "false_negatives": [expected[index] for index in sorted(unmatched_expected)],
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "classification_accuracy": round(classification, 4),
        "severity_exact_accuracy": round(severity_exact, 4),
        "severity_within_one_level": round(severity_near, 4),
        "overall_score": round(overall, 1),
        "grade": grade,
        "matches": [
            {
                "expected": expected[expected_index],
                "reported": {
                    "path": findings[finding_index]["path"],
                    "line": findings[finding_index]["start_line"],
                    "category": findings[finding_index]["category"],
                    "severity": findings[finding_index]["severity"],
                    "title": findings[finding_index]["title"],
                    "issue_probability": findings[finding_index]["issue_probability"],
                },
            }
            for expected_index, finding_index in matches
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument(
        "--truth",
        type=Path,
        default=Path(__file__).parent / "complex" / "ground_truth.json",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = score(
        json.loads(args.truth.read_text(encoding="utf-8")),
        json.loads(args.report.read_text(encoding="utf-8")),
    )
    rendered = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
