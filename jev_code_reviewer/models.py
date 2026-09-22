from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from .privacy import redact


def portable_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.as_posix()


@dataclass(frozen=True)
class Candidate:
    rule_id: str
    path: Path
    start_line: int
    end_line: int
    start_column: int
    title: str
    rationale: str
    detector: str
    suggested_category: str
    suggested_severity: str
    cwe: str | None
    snippet: str
    context: str
    language: str = "unknown"
    detector_confidence: float = 0.75

    def identity(self) -> tuple[str, int, str]:
        return (
            str(self.path.resolve()),
            self.start_line,
            self.cwe or self.title.lower(),
        )

    def fingerprint(self) -> str:
        material = "\0".join(
            (
                self.rule_id,
                portable_path(self.path),
                str(self.start_line),
                self.language,
                self.snippet.strip(),
            )
        )
        return sha256(material.encode("utf-8")).hexdigest()

    def content_fingerprint(self) -> str:
        material = "\0".join(
            (
                self.rule_id,
                self.language,
                self.title,
                self.rationale,
                self.suggested_category,
                self.suggested_severity,
                self.cwe or "",
                self.snippet.strip(),
            )
        )
        return sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Finding:
    candidate: Candidate
    category: str
    severity: str
    issue_probability: float
    classification_confidence: float
    severity_confidence: float
    review_method: str = "jev"

    @property
    def confidence(self) -> float:
        return min(
            self.issue_probability,
            self.classification_confidence,
            self.severity_confidence,
        )

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self.candidate)
        result["path"] = portable_path(self.candidate.path)
        result["snippet"] = redact(self.candidate.snippet)
        result["context"] = redact(self.candidate.context)
        result.update(
            {
                "category": self.category,
                "severity": self.severity,
                "issue_probability": round(self.issue_probability, 4),
                "classification_confidence": round(self.classification_confidence, 4),
                "severity_confidence": round(self.severity_confidence, 4),
                "confidence": round(self.confidence, 4),
                "review_method": self.review_method,
                "fingerprint": self.candidate.fingerprint(),
            }
        )
        return result


@dataclass
class ReviewStats:
    candidates: int = 0
    locally_decided: int = 0
    jev_reviewed: int = 0
    jev_confirmed: int = 0
    cache_hits: int = 0
    budget_skipped: int = 0
    api_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def estimated_cost_usd(self) -> float:
        # Jev public price as of 2026-09: $42 per billion input tokens.
        return self.input_tokens * 42 / 1_000_000_000

    def to_dict(self) -> dict[str, int | float]:
        return {
            **asdict(self),
            "estimated_cost_usd": round(self.estimated_cost_usd, 8),
        }
