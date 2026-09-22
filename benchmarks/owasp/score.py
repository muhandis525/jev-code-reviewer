"""Score a jev-review JSON report against OWASP Benchmark Java labels."""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

TEST_ID = re.compile(r"BenchmarkTest(\d{5})")


def read_labels(path: Path) -> list[dict[str, Any]]:
    labels: list[dict[str, Any]] = []
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.reader(line for line in handle if not line.startswith("#")):
            if not row:
                continue
            match = TEST_ID.fullmatch(row[0].strip())
            if not match:
                raise ValueError(f"invalid test name: {row[0]!r}")
            labels.append(
                {
                    "name": row[0].strip(),
                    "number": int(match.group(1)),
                    "category": row[1].strip(),
                    "vulnerable": row[2].strip().lower() == "true",
                    "cwe": int(row[3]),
                }
            )
    return labels


def finding_cwe(finding: dict[str, Any]) -> int | None:
    match = re.search(r"CWE-(\d+)", str(finding.get("cwe") or ""), re.IGNORECASE)
    return int(match.group(1)) if match else None


def index_findings(
    findings: Iterable[dict[str, Any]],
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    indexed: dict[str, list[dict[str, Any]]] = defaultdict(list)
    unassigned: list[dict[str, Any]] = []
    for finding in findings:
        match = TEST_ID.search(str(finding.get("path") or ""))
        if match:
            indexed[f"BenchmarkTest{match.group(1)}"].append(finding)
        else:
            unassigned.append(finding)
    return dict(indexed), unassigned


def safe_ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def rounded(value: float | None) -> float | None:
    return round(value, 4) if value is not None else None


def metric_set(labels: list[dict[str, Any]], predicted: set[str]) -> dict[str, Any]:
    tp = sum(label["vulnerable"] and label["name"] in predicted for label in labels)
    fp = sum(not label["vulnerable"] and label["name"] in predicted for label in labels)
    fn = sum(label["vulnerable"] and label["name"] not in predicted for label in labels)
    tn = sum(
        not label["vulnerable"] and label["name"] not in predicted for label in labels
    )
    recall = safe_ratio(tp, tp + fn)
    false_positive_rate = safe_ratio(fp, fp + tn)
    precision = safe_ratio(tp, tp + fp)
    specificity = safe_ratio(tn, tn + fp)
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    balanced_accuracy = (
        (recall + specificity) / 2
        if recall is not None and specificity is not None
        else None
    )
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn - fp * fn) / denominator) if denominator else None
    benchmark_score = (
        recall - false_positive_rate
        if recall is not None and false_positive_rate is not None
        else None
    )
    return {
        "cases": len(labels),
        "vulnerable": tp + fn,
        "non_vulnerable": fp + tn,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "precision": rounded(precision),
        "recall": rounded(recall),
        "false_positive_rate": rounded(false_positive_rate),
        "specificity": rounded(specificity),
        "f1": rounded(f1),
        "balanced_accuracy": rounded(balanced_accuracy),
        "mcc": rounded(mcc),
        "owasp_score": rounded(benchmark_score),
    }


def score(labels: list[dict[str, Any]], report: dict[str, Any]) -> dict[str, Any]:
    findings = report.get("findings", [])
    indexed, unassigned = index_findings(findings)
    predicted: set[str] = set()
    wrong_cwe: list[dict[str, Any]] = []
    duplicate_matches = 0
    label_by_name = {label["name"]: label for label in labels}

    for name, matches in indexed.items():
        label = label_by_name.get(name)
        if label is None:
            unassigned.extend(matches)
            continue
        correct = [
            finding for finding in matches if finding_cwe(finding) == label["cwe"]
        ]
        if correct:
            predicted.add(name)
            duplicate_matches += max(0, len(correct) - 1)
        for finding in matches:
            cwe = finding_cwe(finding)
            if cwe != label["cwe"]:
                wrong_cwe.append(
                    {
                        "test": name,
                        "expected_cwe": label["cwe"],
                        "reported_cwe": cwe,
                        "rule_id": finding.get("rule_id"),
                    }
                )

    development = [label for label in labels if label["number"] % 5 == 0]
    held_out = [label for label in labels if label["number"] % 5 != 0]
    by_cwe = {
        str(cwe): metric_set(
            [label for label in labels if label["cwe"] == cwe], predicted
        )
        for cwe in sorted({label["cwe"] for label in labels})
    }
    return {
        "methodology": {
            "prediction": "at least one finding in the test file with the expected CWE",
            "development_split": "numeric test ID modulo 5 equals 0",
            "held_out_split": "numeric test ID modulo 5 does not equal 0",
            "owasp_score": "recall - false_positive_rate",
        },
        "report_summary": {
            "findings": len(findings),
            "tests_predicted_positive": len(predicted),
            "duplicate_matching_findings": duplicate_matches,
            "wrong_cwe_findings": len(wrong_cwe),
            "unassigned_findings": len(unassigned),
        },
        "all": metric_set(labels, predicted),
        "development": metric_set(development, predicted),
        "held_out": metric_set(held_out, predicted),
        "by_cwe": by_cwe,
        "diagnostics": {
            "wrong_cwe": wrong_cwe,
            "unassigned": unassigned,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = score(
        read_labels(args.labels),
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
