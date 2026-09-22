from __future__ import annotations

import json
import os
from collections.abc import Iterable
from hashlib import sha256
from pathlib import Path
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import __version__
from .models import Candidate, Finding, ReviewStats
from .privacy import redact

API_URL = "https://api.typesafe.ai/v1/systemone"
MODEL = "jev-latest"
CATEGORIES = {
    "security": "Injection, auth, trust boundary, data exposure, or unsafe API.",
    "correctness": "Wrong result, state, control flow, or crash.",
    "reliability": "Error handling, cleanup, concurrency, or availability failure.",
    "performance": "Material avoidable CPU, memory, I/O, or scale cost.",
    "maintainability": "Design debt with concrete future defect risk.",
    "testing": "Defective test or material verification gap.",
    "none": "False positive, speculative, or style-only.",
}
SEVERITIES = {
    "critical": "Immediate exploit or catastrophic failure.",
    "high": "Likely serious failure; release-blocking.",
    "medium": "Moderate impact or constrained preconditions.",
    "low": "Minor concrete risk; non-blocking.",
    "info": "Observation without direct runtime impact.",
    "none": "Not an issue.",
}


class JevError(RuntimeError):
    pass


class DecisionCache:
    """Content-addressed cache containing decisions, never source code."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self.data: dict[str, dict[str, Any]] = {}
        if path and path.is_file():
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(value, dict):
                    self.data = value
            except (OSError, ValueError):
                self.data = {}

    def key(self, candidate: Candidate, model: str) -> str:
        value = f"v2\0{model}\0{candidate.content_fingerprint()}"
        return sha256(value.encode("utf-8")).hexdigest()

    def get(self, candidate: Candidate, model: str) -> dict[str, Any] | None:
        return self.data.get(self.key(candidate, model))

    def put(self, candidate: Candidate, model: str, decision: dict[str, Any]) -> None:
        self.data[self.key(candidate, model)] = decision

    def save(self) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix(self.path.suffix + ".tmp")
            temporary.write_text(
                json.dumps(self.data, separators=(",", ":")), encoding="utf-8"
            )
            temporary.replace(self.path)
        except OSError as exc:
            raise JevError(
                f"could not write decision cache {self.path}: {exc}"
            ) from exc


def load_api_key(key_file: Path | None) -> str:
    key = os.environ.get("TYPESAFE_API_KEY") or os.environ.get("JEV_API_KEY")
    if key:
        return key.strip()
    if key_file and key_file.is_file():
        key = key_file.read_text(encoding="utf-8").strip()
        if key:
            return key
    raise JevError("No Jev key found. Set TYPESAFE_API_KEY or pass --key-file PATH.")


def _chunks(items: list[Candidate], size: int) -> Iterable[list[Candidate]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]


class JevClient:
    def __init__(
        self,
        api_key: str,
        timeout: float = 20.0,
        batch_size: int = 8,
        model: str = MODEL,
        cache_path: Path | None = None,
    ) -> None:
        self.timeout = timeout
        self.batch_size = batch_size
        self.model = model
        self.cache = DecisionCache(cache_path)
        self.stats = ReviewStats()
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": f"jev-code-reviewer/{__version__}",
            }
        )
        retry = Retry(
            total=3,
            backoff_factor=0.4,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"POST"}),
            respect_retry_after_header=True,
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    def review(self, candidates: list[Candidate], threshold: float) -> list[Finding]:
        findings: list[Finding] = []
        self.stats.candidates = len(candidates)
        for batch in _chunks(candidates, self.batch_size):
            findings.extend(self._review_batch(batch, threshold))
        self.cache.save()
        return findings

    def _review_batch(self, batch: list[Candidate], threshold: float) -> list[Finding]:
        findings: list[Finding] = []
        misses: list[Candidate] = []
        for candidate in batch:
            cached = self.cache.get(candidate, self.model)
            if cached is None:
                misses.append(candidate)
            else:
                self.stats.cache_hits += 1
                finding = parse_decision(
                    candidate, cached, threshold, review_method="jev-cache"
                )
                if finding:
                    findings.append(finding)
                    self.stats.jev_confirmed += 1
        if not misses:
            return findings

        state_candidates = []
        questions: dict[str, dict[str, Any]] = {}
        for index, candidate in enumerate(misses):
            candidate_id = f"c{index}"
            state_candidates.append(
                {
                    "id": candidate_id,
                    "lang": candidate.language,
                    "loc": f"{candidate.path.name}:{candidate.start_line}-{candidate.end_line}",
                    "rule": candidate.rule_id,
                    "claim": candidate.title,
                    "why": candidate.rationale,
                    "hint": f"{candidate.suggested_category}/{candidate.suggested_severity}/{candidate.cwe or '-'}",
                    "code": redact(candidate.context)[:1200],
                }
            )
            questions[f"{candidate_id}_issue"] = {
                "type": "noul",
                "instructions": (
                    f"Is {candidate_id} a concrete, actionable issue here? Reject style-only or speculative claims."
                ),
            }
            questions[f"{candidate_id}_category"] = {
                "type": "choice",
                "instructions": f"Primary type for {candidate_id}.",
                "criteria": CATEGORIES,
            }
            questions[f"{candidate_id}_severity"] = {
                "type": "choice",
                "instructions": f"Practical severity for {candidate_id}, considering reachability.",
                "criteria": SEVERITIES,
            }

        response: requests.Response | None = None
        try:
            response = self.session.post(
                API_URL,
                json={
                    "model": self.model,
                    "state": {
                        "task": "Validate static-analysis evidence. Prefer precision; reject false positives.",
                        "candidates": state_candidates,
                    },
                    "questions": questions,
                },
                timeout=(4.0, self.timeout),
            )
            response.raise_for_status()
            payload = response.json()
            answers = payload["answers"]
            usage = payload.get("usage") or {}
            self.stats.api_calls += 1
            self.stats.input_tokens += int(usage.get("input_tokens", 0))
            self.stats.output_tokens += int(usage.get("output_tokens", 0))
        except (requests.RequestException, ValueError, KeyError) as exc:
            body = response.text[:300] if response is not None else ""
            raise JevError(f"Jev request failed: {exc}; response={body!r}") from exc
        self.stats.jev_reviewed += len(misses)
        decisions = decisions_from_answers(misses, answers)
        for candidate, decision in zip(misses, decisions):
            self.cache.put(candidate, self.model, decision)
            finding = parse_decision(candidate, decision, threshold)
            if finding:
                findings.append(finding)
        self.stats.jev_confirmed += sum(
            1 for item in findings if item.candidate in misses
        )
        return findings


def decisions_from_answers(
    batch: list[Candidate], answers: dict[str, Any]
) -> list[dict[str, Any]]:
    decisions: list[dict[str, Any]] = []
    for index, _candidate in enumerate(batch):
        prefix = f"c{index}"
        try:
            issue = answers[f"{prefix}_issue"]
            category = answers[f"{prefix}_category"]
            severity = answers[f"{prefix}_severity"]
            decisions.append(
                {
                    "probability": float(issue["noul"]),
                    "category": str(category["choice"]).lower(),
                    "severity": str(severity["choice"]).lower(),
                    "category_confidence": float(category.get("confidence", 0.0)),
                    "severity_confidence": float(severity.get("confidence", 0.0)),
                }
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise JevError(
                f"Malformed Jev response for candidate {prefix}: {exc}"
            ) from exc
    return decisions


def parse_decision(
    candidate: Candidate,
    decision: dict[str, Any],
    threshold: float,
    review_method: str = "jev",
) -> Finding | None:
    try:
        probability = float(decision["probability"])
        category = str(decision["category"])
        severity = str(decision["severity"])
        category_confidence = float(decision["category_confidence"])
        severity_confidence = float(decision["severity_confidence"])
    except (KeyError, TypeError, ValueError) as exc:
        raise JevError(f"Malformed cached Jev decision: {exc}") from exc
    if probability < threshold or category == "none" or severity == "none":
        return None
    if category not in CATEGORIES or severity not in SEVERITIES:
        raise JevError(f"Jev returned unsupported labels: {category}/{severity}")
    return Finding(
        candidate=candidate,
        category=category,
        severity=severity,
        issue_probability=probability,
        classification_confidence=category_confidence,
        severity_confidence=severity_confidence,
        review_method=review_method,
    )


def parse_answers(
    batch: list[Candidate], answers: dict[str, Any], threshold: float
) -> list[Finding]:
    return [
        finding
        for candidate, decision in zip(batch, decisions_from_answers(batch, answers))
        if (finding := parse_decision(candidate, decision, threshold)) is not None
    ]


def local_review(candidates: list[Candidate]) -> list[Finding]:
    return [
        Finding(
            candidate=candidate,
            category=candidate.suggested_category,
            severity=candidate.suggested_severity,
            issue_probability=candidate.detector_confidence,
            classification_confidence=candidate.detector_confidence,
            severity_confidence=candidate.detector_confidence,
            review_method="local",
        )
        for candidate in candidates
    ]


def cascade_review(
    candidates: list[Candidate],
    client: JevClient,
    threshold: float,
    local_confidence: float = 0.90,
    max_jev_candidates: int | None = None,
) -> tuple[list[Finding], ReviewStats]:
    """Resolve precise evidence locally and spend model tokens on ambiguity."""
    local = [
        candidate
        for candidate in candidates
        if candidate.detector_confidence >= local_confidence
    ]
    uncertain = [
        candidate
        for candidate in candidates
        if candidate.detector_confidence < local_confidence
    ]
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    uncertain.sort(
        key=lambda item: (
            severity_rank.get(item.suggested_severity, 9),
            -item.detector_confidence,
            str(item.path),
            item.start_line,
        )
    )
    selected = (
        uncertain if max_jev_candidates is None else uncertain[:max_jev_candidates]
    )
    findings = local_review(local)
    findings.extend(client.review(selected, threshold))
    client.stats.candidates = len(candidates)
    client.stats.locally_decided = len(local)
    client.stats.budget_skipped = len(uncertain) - len(selected)
    return findings, client.stats
