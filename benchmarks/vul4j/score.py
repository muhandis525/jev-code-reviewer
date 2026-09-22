"""Measure case/file/patch-line recall on materialized Vul4J cases."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

CASE_ID = re.compile(r"VUL4J-\d+(?:-S)?")


def overlaps(line: int, ranges: list[list[int]]) -> bool:
    return any(start <= line <= end for start, end in ranges)


def score(manifest: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    findings_by_case: dict[str, list[dict[str, Any]]] = {}
    for finding in report.get("findings", []):
        match = CASE_ID.search(str(finding.get("path") or ""))
        if match:
            findings_by_case.setdefault(match.group(0), []).append(finding)

    materialized = [case for case in manifest["cases"] if case.get("files")]
    rows = []
    for case in materialized:
        findings = findings_by_case.get(case["vul_id"], [])
        expected_cwe = case.get("cwe")
        correct_cwe = [
            f for f in findings if expected_cwe and f.get("cwe") == expected_cwe
        ]
        file_hits = []
        line_hits = []
        for finding in findings:
            path = str(finding.get("path") or "")
            for changed in case["files"]:
                if path.endswith(changed["path"]):
                    file_hits.append(finding)
                    if overlaps(int(finding["start_line"]), changed["ranges"]):
                        line_hits.append(finding)
                    break
        strict_line_hits = [
            f for f in line_hits if expected_cwe and f.get("cwe") == expected_cwe
        ]
        rows.append(
            {
                "vul_id": case["vul_id"],
                "cve_id": case["cve_id"],
                "expected_cwe": expected_cwe,
                "findings": len(findings),
                "any_file_hit": bool(file_hits),
                "any_patch_line_hit": bool(line_hits),
                "correct_cwe_anywhere": bool(correct_cwe),
                "correct_cwe_patch_line_hit": bool(strict_line_hits),
            }
        )

    mapped = [row for row in rows if row["expected_cwe"]]
    total = len(rows)
    file_hits = sum(row["any_file_hit"] for row in rows)
    patch_line_hits = sum(row["any_patch_line_hit"] for row in rows)
    strict_hits = sum(row["correct_cwe_patch_line_hit"] for row in mapped)
    return {
        "methodology": {
            "unit": "one Vul4J vulnerability",
            "patch_line_hit": "finding start line overlaps a line removed or anchored by the human patch",
            "limitation": "positive-only dataset: recall can be measured, precision cannot",
        },
        "cases_requested": manifest.get("cases_requested", len(manifest["cases"])),
        "cases_materialized": total,
        "cases_excluded": len(manifest["cases"]) - total,
        "cases_with_expected_cwe": len(mapped),
        "file_hits": file_hits,
        "file_hit_recall": round(file_hits / total, 4) if total else None,
        "patch_line_hits": patch_line_hits,
        "patch_line_recall": round(patch_line_hits / total, 4) if total else None,
        "strict_cwe_patch_line_hits": strict_hits,
        "strict_cwe_recall": round(strict_hits / len(mapped), 4) if mapped else None,
        "results": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = score(
        json.loads(args.manifest.read_text(encoding="utf-8")),
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
