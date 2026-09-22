from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .models import Candidate


class DiffError(RuntimeError):
    pass


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def changed_lines(paths: list[Path], base: str) -> dict[Path, list[tuple[int, int]]]:
    """Return added/modified line ranges since a git revision.

    Deleted-only hunks intentionally produce no range because there is no current
    source location to report. Untracked source files are treated as wholly new.
    """
    probe = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        raise DiffError("--changed-since requires running inside a Git repository")
    root = Path(probe.stdout.strip()).resolve()
    try:
        relative = [str(path.resolve().relative_to(root)) for path in paths]
    except ValueError as exc:
        raise DiffError(
            "all review paths must be inside the current Git repository"
        ) from exc

    command = ["git", "diff", "--unified=0", "--no-ext-diff", base, "--", *relative]
    process = subprocess.run(command, capture_output=True, text=True, check=False)
    if process.returncode != 0:
        raise DiffError(process.stderr.strip() or f"could not compare against {base!r}")

    ranges: dict[Path, list[tuple[int, int]]] = {}
    current: Path | None = None
    for line in process.stdout.splitlines():
        if line.startswith("+++ b/"):
            current = (root / line[6:]).resolve()
            ranges.setdefault(current, [])
            continue
        match = _HUNK.match(line)
        if current is not None and match:
            start = int(match.group(1))
            count = int(match.group(2) or "1")
            if count:
                ranges[current].append((start, start + count - 1))

    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "--", *relative],
        capture_output=True,
        text=True,
        check=False,
    )
    if untracked.returncode == 0:
        for name in untracked.stdout.splitlines():
            file_path = (root / name).resolve()
            if file_path.is_file():
                line_count = len(
                    file_path.read_text(encoding="utf-8", errors="replace").splitlines()
                )
                ranges[file_path] = [(1, max(1, line_count))]
    return ranges


def filter_changed(
    candidates: list[Candidate], ranges: dict[Path, list[tuple[int, int]]]
) -> list[Candidate]:
    return [
        candidate
        for candidate in candidates
        if any(
            candidate.start_line <= high and low <= candidate.end_line
            for low, high in ranges.get(candidate.path.resolve(), [])
        )
    ]
