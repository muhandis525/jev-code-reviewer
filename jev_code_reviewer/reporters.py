from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from . import __version__
from .models import Finding, ReviewStats, portable_path
from .privacy import redact

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[37m",
}
RESET = "\033[0m"


def sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(finding.severity, 9),
            str(finding.candidate.path),
            finding.candidate.start_line,
        ),
    )


def _stats_text(stats: ReviewStats | None) -> str:
    if not stats:
        return ""
    return (
        f" · local={stats.locally_decided} · Jev={stats.jev_reviewed} "
        f"(cache={stats.cache_hits}, calls={stats.api_calls}, input_tokens={stats.input_tokens}, "
        f"cost≈${stats.estimated_cost_usd:.6f}) · budget_skipped={stats.budget_skipped}"
    )


def text_report(
    findings: list[Finding],
    candidates_count: int,
    use_color: bool = True,
    stats: ReviewStats | None = None,
) -> str:
    if not findings:
        return f"No confirmed issues from {candidates_count} candidate(s){_stats_text(stats)}."
    lines: list[str] = []
    for finding in sorted_findings(findings):
        candidate = finding.candidate
        color = COLORS.get(finding.severity, "") if use_color else ""
        reset = RESET if color else ""
        location = f"{candidate.path}:{candidate.start_line}"
        if candidate.end_line != candidate.start_line:
            location += f"-{candidate.end_line}"
        cwe = f" · {candidate.cwe}" if candidate.cwe else ""
        lines.extend(
            [
                f"{color}{finding.severity.upper():8}{reset} {location}",
                f"  [{finding.category}] {candidate.title}{cwe}",
                f"  {candidate.rationale}",
                f"  Review: {finding.review_method} · issue {finding.issue_probability:.0%} · classification {finding.classification_confidence:.0%} · severity {finding.severity_confidence:.0%}",
                *[f"    {line}" for line in redact(candidate.snippet).splitlines()],
                "",
            ]
        )
    by_severity = Counter(finding.severity for finding in findings)
    by_category = Counter(finding.category for finding in findings)
    severity_text = ", ".join(
        f"{key}={value}"
        for key, value in sorted(
            by_severity.items(), key=lambda item: SEVERITY_ORDER.get(item[0], 9)
        )
    )
    category_text = ", ".join(
        f"{key}={value}" for key, value in sorted(by_category.items())
    )
    lines.append(
        f"Confirmed {len(findings)}/{candidates_count} candidate(s) · {severity_text} · {category_text}{_stats_text(stats)}"
    )
    return "\n".join(lines)


def json_report(
    findings: list[Finding], candidates_count: int, stats: ReviewStats | None = None
) -> str:
    return json.dumps(
        {
            "tool": "jev-code-reviewer",
            "candidates_reviewed": candidates_count,
            "issues_found": len(findings),
            "review_stats": stats.to_dict() if stats else None,
            "findings": [finding.to_dict() for finding in sorted_findings(findings)],
        },
        indent=2,
    )


def sarif_report(findings: list[Finding]) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for finding in sorted_findings(findings):
        candidate = finding.candidate
        rule_id = candidate.rule_id
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": candidate.title,
                "shortDescription": {"text": candidate.title},
                "fullDescription": {"text": candidate.rationale},
                "defaultConfiguration": {"level": SARIF_LEVEL[finding.severity]},
                "properties": {
                    "tags": [
                        value for value in (finding.category, candidate.cwe) if value
                    ],
                    "precision": "high" if finding.confidence >= 0.8 else "medium",
                },
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": SARIF_LEVEL[finding.severity],
                "message": {"text": f"{candidate.title}: {candidate.rationale}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": portable_path(candidate.path)},
                            "region": {
                                "startLine": candidate.start_line,
                                "startColumn": candidate.start_column,
                                "endLine": candidate.end_line,
                                "snippet": {"text": redact(candidate.snippet)},
                            },
                        }
                    }
                ],
                "properties": {
                    "category": finding.category,
                    "severity": finding.severity,
                    "cwe": candidate.cwe,
                    "jevIssueProbability": round(finding.issue_probability, 4),
                    "jevConfidence": round(finding.confidence, 4),
                    "reviewMethod": finding.review_method,
                },
                "partialFingerprints": {
                    "jevCodeReviewer/v1": candidate.fingerprint(),
                },
            }
        )
    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Jev Code Reviewer",
                            "informationUri": "https://typesafe.ai/",
                            "version": __version__,
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        },
        indent=2,
    )


def write_report(content: str, output: Path | None) -> None:
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content + "\n", encoding="utf-8")
    else:
        print(content)
