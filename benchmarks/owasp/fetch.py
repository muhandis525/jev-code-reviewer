"""Fetch the exact OWASP Benchmark Java revision used by this evaluation."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

REPOSITORY = "https://github.com/OWASP-Benchmark/BenchmarkJava.git"
REVISION = "20cbf3d11123347e47ed89541e6942836def53f7"
DEFAULT_DESTINATION = (
    Path(__file__).resolve().parents[2] / ".benchmarks" / "BenchmarkJava"
)


def run(*command: str, cwd: Path | None = None) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    args = parser.parse_args()
    destination = args.destination.resolve()

    if destination.exists():
        if not (destination / ".git").is_dir():
            raise SystemExit(f"refusing to replace non-git path: {destination}")
        remote = run("git", "remote", "get-url", "origin", cwd=destination)
        if remote != REPOSITORY:
            raise SystemExit(f"unexpected origin for {destination}: {remote}")
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        run("git", "clone", "--no-checkout", REPOSITORY, str(destination))

    try:
        run("git", "cat-file", "-e", f"{REVISION}^{{commit}}", cwd=destination)
    except subprocess.CalledProcessError:
        run("git", "fetch", "--depth", "1", "origin", REVISION, cwd=destination)
    run("git", "checkout", "--detach", REVISION, cwd=destination)
    actual = run("git", "rev-parse", "HEAD", cwd=destination)
    if actual != REVISION:
        raise SystemExit(f"revision mismatch: expected {REVISION}, got {actual}")
    print(destination)
    print(actual)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
