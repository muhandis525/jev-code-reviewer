"""Materialize vulnerable Java files and patch-line labels from Vul4J."""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

VUL4J_REVISION = "376411da11fa705019f731404de1d0679fe73537"
COMMIT_PATH = re.compile(r"^/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})$")
COMPARE_PATH = re.compile(
    r"^/([^/]+)/([^/]+)/compare/([0-9a-fA-F]{7,40})\.\.([0-9a-fA-F]{7,40})$"
)
DIFF_HEADER = re.compile(r"^diff --git a/(.+) b/(.+)$")
OLD_FILE = re.compile(r"^--- (?:a/)?(.+)$")
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
PATCH_FROM = re.compile(r"^From ([0-9a-f]{40}) ", re.MULTILINE)


def run(*command: str, cwd: Path | None = None, text: bool = True) -> str | bytes:
    result = subprocess.run(
        command,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=text,
    )
    return result.stdout


def parse_patch_url(url: str) -> tuple[str, str, str | None]:
    parsed = urlparse(url)
    match = COMMIT_PATH.fullmatch(parsed.path.rstrip("/"))
    comparison = COMPARE_PATH.fullmatch(parsed.path.rstrip("/"))
    if parsed.scheme != "https" or parsed.netloc != "github.com":
        raise ValueError(f"unsupported human patch URL: {url}")
    if match:
        return f"{match.group(1)}/{match.group(2)}", match.group(3).lower(), None
    if comparison:
        return (
            f"{comparison.group(1)}/{comparison.group(2)}",
            comparison.group(4).lower(),
            comparison.group(3).lower(),
        )
    raise ValueError(f"unsupported human patch URL: {url}")


def resolve_commit(slug: str, commit: str) -> str:
    if len(commit) == 40:
        return commit
    request = Request(
        f"https://github.com/{slug}/commit/{commit}.patch",
        headers={"User-Agent": "jev-code-reviewer-benchmark/0.3"},
    )
    with urlopen(request, timeout=30) as response:
        header = response.read(200).decode("ascii", errors="replace")
    match = PATCH_FROM.search(header)
    if not match or not match.group(1).startswith(commit):
        raise ValueError(f"could not resolve abbreviated commit {slug}@{commit}")
    return match.group(1)


def ensure_commit(repo: Path, commit: str, depth: int) -> None:
    try:
        run("git", "cat-file", "-e", f"{commit}^{{commit}}", cwd=repo)
    except subprocess.CalledProcessError:
        run(
            "git",
            "fetch",
            "--quiet",
            "--filter=blob:none",
            f"--depth={depth}",
            "origin",
            commit,
            cwd=repo,
        )


def ensure_repo(
    cache: Path, slug: str, commit: str, vulnerable: str | None = None
) -> tuple[Path, str]:
    repo = cache / slug.replace("/", "__")
    if not repo.exists():
        repo.mkdir(parents=True)
        run("git", "init", "-q", cwd=repo)
        run(
            "git", "remote", "add", "origin", f"https://github.com/{slug}.git", cwd=repo
        )
    ensure_commit(repo, commit, 2)
    if vulnerable is not None:
        ensure_commit(repo, vulnerable, 1)
        parent = str(run("git", "rev-parse", vulnerable, cwd=repo)).strip()
    else:
        try:
            run("git", "rev-parse", "--verify", f"{commit}^", cwd=repo)
        except subprocess.CalledProcessError:
            # The commit may already exist as a shallow boundary from fetching a
            # different vulnerability in the same project. Refetch with parent.
            run(
                "git",
                "fetch",
                "--quiet",
                "--filter=blob:none",
                "--depth=2",
                "origin",
                commit,
                cwd=repo,
            )
        parent = str(run("git", "rev-parse", f"{commit}^", cwd=repo)).strip()
    return repo, parent


def changed_java_ranges(
    repo: Path, parent: str, fixing: str
) -> dict[str, list[list[int]]]:
    diff = str(
        run(
            "git",
            "diff",
            "--find-renames",
            "--unified=0",
            parent,
            fixing,
            "--",
            "*.java",
            cwd=repo,
        )
    )
    ranges: dict[str, list[list[int]]] = {}
    current: str | None = None
    for line in diff.splitlines():
        if DIFF_HEADER.match(line):
            current = None
            continue
        old_file = OLD_FILE.match(line)
        if old_file:
            value = old_file.group(1)
            current = None if value == "/dev/null" else value
            if current is not None:
                ranges.setdefault(current, [])
            continue
        hunk = HUNK.match(line)
        if hunk and current is not None:
            start = int(hunk.group(1))
            count = int(hunk.group(2) or "1")
            # A pure insertion has no deleted vulnerable line. Retain its old-file
            # anchor for a transparent, slightly more permissive secondary label.
            ranges[current].append([max(1, start), max(1, start + count - 1)])
    return {path: values for path, values in ranges.items() if values}


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dataset",
        type=Path,
        default=root / ".benchmarks" / "vul4j" / "dataset" / "vul4j_dataset.csv",
    )
    parser.add_argument(
        "--output", type=Path, default=root / ".benchmarks" / "vul4j-cases"
    )
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    output = args.output.resolve()
    cache = output.parent / "vul4j-repos"
    output.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)

    with args.dataset.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if args.limit is not None:
        rows = rows[: args.limit]

    cases = []
    for index, row in enumerate(rows, 1):
        case = {
            "vul_id": row["vul_id"],
            "cve_id": row["cve_id"],
            "cwe": row["cwe_id"] if row["cwe_id"].startswith("CWE-") else None,
            "cwe_name": row["cwe_name"],
            "repo": row["repo_slug"],
            "human_patch": row["human_patch"],
            "fixing_commit": None,
            "vulnerable_commit": None,
            "files": [],
        }
        try:
            slug, fixing, vulnerable = parse_patch_url(row["human_patch"])
            fixing = resolve_commit(slug, fixing)
            vulnerable = resolve_commit(slug, vulnerable) if vulnerable else None
            case["repo"] = slug
            print(f"[{index}/{len(rows)}] {row['vul_id']} {slug}", flush=True)
            repo, parent = ensure_repo(cache, slug, fixing, vulnerable)
            fixing = str(run("git", "rev-parse", fixing, cwd=repo)).strip()
            ranges = changed_java_ranges(repo, parent, fixing)
            case["fixing_commit"] = fixing
            case["vulnerable_commit"] = parent
        except (OSError, ValueError, subprocess.CalledProcessError) as exc:
            case["error"] = f"{type(exc).__name__}: {exc}"
            cases.append(case)
            print(f"  skipped: {case['error']}", flush=True)
            continue
        case_root = output / row["vul_id"] / "vulnerable"
        files = []
        for relative, line_ranges in ranges.items():
            try:
                content = run(
                    "git", "show", f"{parent}:{relative}", cwd=repo, text=False
                )
            except subprocess.CalledProcessError:
                continue
            destination = case_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(
                content if isinstance(content, bytes) else content.encode()
            )
            files.append({"path": relative, "ranges": line_ranges})
        case["files"] = files
        cases.append(case)

    manifest = {
        "vul4j_revision": VUL4J_REVISION,
        "cases_requested": len(rows),
        "cases_with_java_patch_ranges": sum(bool(case["files"]) for case in cases),
        "cases_with_fetch_errors": sum("error" in case for case in cases),
        "cases": cases,
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(output / "manifest.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
