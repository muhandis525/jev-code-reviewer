from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .models import Candidate

DEFAULT_RULES = Path(__file__).with_name("rules.yml")
SUPPORTED_SUFFIXES = {
    ".py",
    ".pyi",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".java",
    ".kt",
    ".kts",
    ".go",
    ".rs",
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".cxx",
    ".hpp",
    ".cs",
    ".php",
    ".rb",
    ".swift",
    ".scala",
    ".sh",
    ".bash",
    ".sql",
    ".vue",
    ".svelte",
    ".html",
    ".yaml",
    ".yml",
    ".json",
    ".tf",
}
SUPPORTED_FILENAMES = {"Dockerfile", "Containerfile"}
LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".go": "go",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".php": "php",
    ".rb": "ruby",
    ".swift": "swift",
    ".scala": "scala",
    ".sh": "shell",
    ".bash": "shell",
    ".sql": "sql",
    ".vue": "vue",
    ".svelte": "svelte",
    ".html": "html",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".tf": "terraform",
}


def language_for_path(path: Path) -> str:
    if path.name in SUPPORTED_FILENAMES:
        return "dockerfile"
    return LANGUAGE_BY_SUFFIX.get(path.suffix.lower(), "unknown")


SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    "target",
    "__pycache__",
}
SUPPRESSION = re.compile(r"\b(?:nosemgrep|jev-ignore)\b", re.IGNORECASE)


class ScanError(RuntimeError):
    pass


def _safe_lines(path: Path) -> list[str]:
    try:
        if path.stat().st_size > 1_000_000:
            return []
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _excerpt(
    lines: list[str], start: int, end: int, radius: int = 2
) -> tuple[str, str]:
    if not lines:
        return "", ""
    start = max(1, min(start, len(lines)))
    end = max(start, min(end, len(lines)))
    snippet = "\n".join(line[:300] for line in lines[start - 1 : end])
    low, high = max(1, start - radius), min(len(lines), end + radius)
    context = "\n".join(
        f"{number:>5} | {lines[number - 1][:300]}" for number in range(low, high + 1)
    )
    return snippet, context


def _normal_category(value: object) -> str:
    text = str(value or "").lower()
    for category in (
        "security",
        "correctness",
        "reliability",
        "performance",
        "maintainability",
        "testing",
    ):
        if category in text:
            return category
    return "correctness"


def _normal_severity(value: object) -> str:
    text = str(value or "medium").lower()
    aliases = {"error": "high", "warning": "medium", "recommendation": "low"}
    text = aliases.get(text, text)
    return text if text in {"critical", "high", "medium", "low", "info"} else "medium"


def _normal_confidence(value: object, default: float = 0.82) -> float:
    labels = {"high": 0.90, "medium": 0.75, "low": 0.60}
    if isinstance(value, str) and value.lower() in labels:
        return labels[value.lower()]
    try:
        return min(1.0, max(0.0, float(value)))
    except (TypeError, ValueError):
        return default


def _normal_cwe(rule_id: str, value: object) -> str | None:
    rule = rule_id.lower()
    # Some community rules attach a secondary implementation CWE even though
    # their rule family names a more specific vulnerability. Prefer the
    # actionable root weakness so equivalent source/sink alerts deduplicate.
    families = (
        (("sql-injection", "tainted-sql", "formatted-sql", "raw-query"), "CWE-89"),
        (("command-injection", "shell-injection"), "CWE-78"),
        (("xss", "cross-site-scripting"), "CWE-79"),
        (("hardcoded-secret", "hardcoded-password"), "CWE-798"),
    )
    for needles, cwe in families:
        if any(needle in rule for needle in needles):
            return cwe
    values = value if isinstance(value, list) else [value]
    for item in values:
        match = re.search(r"CWE-\d+", str(item or ""), re.IGNORECASE)
        if match:
            return match.group(0).upper()
    return None


def scan_with_semgrep(
    paths: list[Path], config: str | Path = DEFAULT_RULES
) -> list[Candidate]:
    sibling = Path(sys.executable).with_name("semgrep")
    executable = str(sibling) if sibling.is_file() else shutil.which("semgrep")
    if not executable:
        raise ScanError(
            "Semgrep is not installed; run ./setup.sh or use --engine builtin"
        )
    command = [executable, "scan"]
    if str(config) == "auto":
        command.extend(("--config", "auto", "--config", str(DEFAULT_RULES)))
    else:
        command.extend(("--config", str(config)))
    command.extend(
        ("--json", "--quiet", "--no-rewrite-rule-ids", "--max-target-bytes", "1000000")
    )
    # Semgrep's registry-backed auto selection requires anonymous metrics.
    # Explicit and bundled configurations keep metrics disabled.
    if str(config) != "auto":
        command.append("--metrics=off")
    command.extend(str(path) for path in paths)
    env = os.environ.copy()
    env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    try:
        process = subprocess.run(
            command, capture_output=True, text=True, env=env, check=False, timeout=180
        )
    except subprocess.TimeoutExpired as exc:
        raise ScanError("Semgrep exceeded the 180 second scan timeout") from exc
    try:
        payload = json.loads(process.stdout or "{}")
    except json.JSONDecodeError as exc:
        detail = process.stderr.strip()[-500:]
        raise ScanError(f"Semgrep returned invalid output: {detail}") from exc
    if process.returncode not in (0, 1):
        errors = (
            payload.get("errors") or process.stderr.strip() or "unknown Semgrep error"
        )
        raise ScanError(f"Semgrep failed: {errors}")

    candidates: list[Candidate] = []
    cache: dict[Path, list[str]] = {}
    for result in payload.get("results", []):
        path = Path(result["path"]).resolve()
        lines = cache.setdefault(path, _safe_lines(path))
        extra = result.get("extra", {})
        metadata = extra.get("metadata") or {}
        start = int(result.get("start", {}).get("line", 1))
        end = int(result.get("end", {}).get("line", start))
        snippet, context = _excerpt(lines, start, end)
        rule_id = str(result.get("check_id", "semgrep.unknown"))
        cwe_value = _normal_cwe(rule_id, metadata.get("cwe"))
        candidates.append(
            Candidate(
                rule_id=rule_id,
                path=path,
                start_line=start,
                end_line=end,
                start_column=int(result.get("start", {}).get("col", 1)),
                title=str(
                    metadata.get("title")
                    or extra.get("message")
                    or result.get("check_id")
                ),
                rationale=str(extra.get("message") or "Structure-aware rule match."),
                detector="semgrep",
                suggested_category=_normal_category(metadata.get("category")),
                suggested_severity=_normal_severity(extra.get("severity")),
                cwe=str(cwe_value) if cwe_value else None,
                snippet=snippet,
                context=context,
                language=language_for_path(path),
                detector_confidence=_normal_confidence(metadata.get("confidence")),
            )
        )
    return candidates


@dataclass(frozen=True)
class RegexRule:
    rule_id: str
    pattern: re.Pattern[str]
    title: str
    rationale: str
    category: str
    severity: str
    cwe: str | None = None
    suffixes: frozenset[str] | None = None
    confidence: float = 0.72


REGEX_RULES = (
    RegexRule(
        "builtin.hardcoded-secret",
        re.compile(
            r"(?i)\b(password|passwd|api[_-]?key|secret|access[_-]?token)\s*[:=]\s*['\"][^'\"\n]{8,}['\"]"
        ),
        "Possible hardcoded credential",
        "Credentials in source can leak through repositories, logs, and build artifacts; load them from a secret store or environment.",
        "security",
        "high",
        "CWE-798",
    ),
    RegexRule(
        "builtin.insecure-http",
        re.compile(
            r"['\"]http://(?!localhost\b|127\.0\.0\.1\b)[^'\"]+['\"]", re.IGNORECASE
        ),
        "Unencrypted HTTP endpoint",
        "Network traffic and credentials may be exposed or modified in transit.",
        "security",
        "medium",
        "CWE-319",
    ),
    RegexRule(
        "builtin.js-loose-equality",
        re.compile(r"(?<![=!])==(?!=)|(?<![=!])!=(?!=)"),
        "JavaScript coercive equality",
        "Coercive equality can produce unexpected comparisons; prefer strict equality unless coercion is intentional.",
        "correctness",
        "low",
        None,
        frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}),
        0.62,
    ),
    RegexRule(
        "builtin.dom-xss",
        re.compile(r"\b(innerHTML\s*=|dangerouslySetInnerHTML|v-html\s*=|\{@html\b)"),
        "HTML injection escape hatch",
        "Rendering unsanitized HTML can enable cross-site scripting.",
        "security",
        "high",
        "CWE-79",
        frozenset({".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".html"}),
        0.70,
    ),
    RegexRule(
        "builtin.unsafe-c-function",
        re.compile(r"\b(gets|strcpy|strcat|sprintf)\s*\("),
        "Unsafe C string operation",
        "This API cannot enforce destination bounds and can lead to memory corruption.",
        "security",
        "high",
        "CWE-120",
        frozenset({".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"}),
        0.94,
    ),
    RegexRule(
        "builtin.weak-password-hash",
        re.compile(r"(?i)\b(md5|sha1)\s*\([^\n]*(password|passwd|credential)"),
        "Weak password hashing",
        "Fast general-purpose hashes are unsuitable for password storage; use a password-hashing function such as Argon2 or bcrypt.",
        "security",
        "critical",
        "CWE-916",
    ),
)


def iter_source_files(paths: Iterable[Path]) -> Iterable[Path]:
    seen: set[Path] = set()
    for supplied in paths:
        path = supplied.resolve()
        if path.is_file():
            files = [path]
        elif path.is_dir():
            files = (
                item
                for item in path.rglob("*")
                if item.is_file() and not any(part in SKIP_DIRS for part in item.parts)
            )
        else:
            continue
        for item in files:
            if (
                item.suffix.lower() not in SUPPORTED_SUFFIXES
                and item.name not in SUPPORTED_FILENAMES
            ) or item.is_symlink():
                continue
            resolved = item.resolve()
            if resolved not in seen:
                seen.add(resolved)
                yield resolved


def _candidate(
    path: Path,
    lines: list[str],
    line: int,
    rule_id: str,
    title: str,
    rationale: str,
    category: str,
    severity: str,
    cwe: str | None = None,
    end_line: int | None = None,
    confidence: float = 0.90,
) -> Candidate:
    end = end_line or line
    snippet, context = _excerpt(lines, line, end)
    return Candidate(
        rule_id=rule_id,
        path=path,
        start_line=line,
        end_line=end,
        start_column=1,
        title=title,
        rationale=rationale,
        detector="builtin",
        suggested_category=category,
        suggested_severity=severity,
        cwe=cwe,
        snippet=snippet,
        context=context,
        language=language_for_path(path),
        detector_confidence=confidence,
    )


class PythonVisitor(ast.NodeVisitor):
    def __init__(self, path: Path, lines: list[str]) -> None:
        self.path, self.lines = path, lines
        self.results: list[Candidate] = []

    def add(self, node: ast.AST, *details: str | None) -> None:
        start = max(1, node.lineno)
        if start <= len(self.lines) and SUPPRESSION.search(self.lines[start - 1]):
            return
        self.results.append(
            _candidate(
                self.path,
                self.lines,
                node.lineno,
                *details,
                end_line=getattr(node, "end_lineno", node.lineno),
            )
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function(node)
        self.generic_visit(node)

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        defaults = [
            *node.args.defaults,
            *[value for value in node.args.kw_defaults if value],
        ]
        if any(isinstance(value, (ast.List, ast.Dict, ast.Set)) for value in defaults):
            self.add(
                node,
                "builtin.python.mutable-default",
                "Mutable default argument",
                "The same mutable object is reused across calls, which can leak state between callers.",
                "correctness",
                "high",
                "CWE-1188",
            )

    def visit_Try(self, node: ast.Try) -> None:
        for handler in node.handlers:
            if handler.type is None:
                self.add(
                    handler,
                    "builtin.python.bare-except",
                    "Bare exception handler",
                    "A bare except also catches process-control exceptions and can hide unexpected failures.",
                    "reliability",
                    "medium",
                    "CWE-396",
                )
            if len(handler.body) == 1 and isinstance(handler.body[0], ast.Pass):
                self.add(
                    handler,
                    "builtin.python.swallowed-exception",
                    "Swallowed exception",
                    "Silently discarding an exception hides failures and makes the program state difficult to trust.",
                    "reliability",
                    "high",
                    "CWE-390",
                )
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        for operator, comparator in zip(node.ops, node.comparators):
            if (
                isinstance(operator, (ast.Is, ast.IsNot))
                and isinstance(comparator, ast.Constant)
                and comparator.value not in (None, True, False, Ellipsis)
            ):
                self.add(
                    node,
                    "builtin.python.identity-value",
                    "Identity comparison with a value",
                    "Identity compares object identity rather than value and can behave unpredictably for literals.",
                    "correctness",
                    "medium",
                    None,
                )
                break
        self.generic_visit(node)


def scan_builtin(paths: list[Path]) -> list[Candidate]:
    results: list[Candidate] = []
    for path in iter_source_files(paths):
        lines = _safe_lines(path)
        if not lines:
            continue
        for number, line in enumerate(lines, 1):
            if SUPPRESSION.search(line):
                continue
            for rule in REGEX_RULES:
                if rule.suffixes and path.suffix.lower() not in rule.suffixes:
                    continue
                if rule.pattern.search(line):
                    results.append(
                        _candidate(
                            path,
                            lines,
                            number,
                            rule.rule_id,
                            rule.title,
                            rule.rationale,
                            rule.category,
                            rule.severity,
                            rule.cwe,
                            confidence=rule.confidence,
                        )
                    )
        if path.suffix.lower() in {".py", ".pyi"}:
            try:
                tree = ast.parse("\n".join(lines), filename=str(path))
            except SyntaxError as exc:
                results.append(
                    _candidate(
                        path,
                        lines,
                        exc.lineno or 1,
                        "builtin.python.syntax-error",
                        "Python syntax error",
                        exc.msg,
                        "correctness",
                        "critical",
                        "CWE-670",
                    )
                )
            else:
                visitor = PythonVisitor(path, lines)
                visitor.visit(tree)
                results.extend(visitor.results)
    return results


def scan(
    paths: list[Path], engine: str, semgrep_config: str | Path = DEFAULT_RULES
) -> list[Candidate]:
    candidates: list[Candidate] = []
    if engine in {"hybrid", "semgrep"}:
        candidates.extend(scan_with_semgrep(paths, semgrep_config))
    if engine in {"hybrid", "builtin"}:
        candidates.extend(scan_builtin(paths))
    unique: list[Candidate] = []
    for candidate in candidates:
        marker = candidate.cwe or candidate.title.lower()
        adjacency = 1 if candidate.cwe else 0
        duplicate_index = next(
            (
                index
                for index, current in enumerate(unique)
                if current.path.resolve() == candidate.path.resolve()
                and (current.cwe or current.title.lower()) == marker
                and current.start_line <= candidate.end_line + adjacency
                and candidate.start_line <= current.end_line + adjacency
            ),
            None,
        )
        if duplicate_index is None:
            unique.append(candidate)
        elif (
            unique[duplicate_index].detector == "builtin"
            and candidate.detector == "semgrep"
        ):
            unique[duplicate_index] = candidate
    return sorted(
        unique, key=lambda item: (str(item.path), item.start_line, item.rule_id)
    )
