# Jev Code Reviewer

[![tests](https://github.com/muhandis525/jev-code-reviewer/actions/workflows/test.yml/badge.svg)](https://github.com/muhandis525/jev-code-reviewer/actions/workflows/test.yml)
[![license: Apache--2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)](SECURITY.md)

An experimental, line-accurate code-review CLI that combines deterministic
local analysis with selective Jev decisions. It is designed to spend model
tokens on ambiguity—not on findings that syntax and data-flow rules can already
establish with high confidence.

## What is different

The default `smart` cascade:

1. finds candidate defects locally with Semgrep plus Python AST/regex checks;
2. deduplicates overlapping evidence and filters to changed lines when asked;
3. resolves high-confidence findings locally with zero API tokens;
4. sends only ambiguous, redacted five-line evidence windows to Jev;
5. caches typed decisions by a source-free content hash;
6. reports exact token usage and estimated Jev cost.

Reports include exact lines, category, severity, CWE, confidence, review method,
and a stable fingerprint. Output is available as text, JSON, or SARIF 2.1.0.

## Coverage

The bundled pack currently contains 48 rules covering Python, JavaScript,
TypeScript, Go, C/C++, PHP, Java, C#, Ruby, Rust, Kotlin, Swift, Dockerfiles,
Terraform, and generic configuration/source files. It prioritizes actionable
security, correctness, and reliability defects over formatting advice.

This remains an alpha tool. It does not replace a compiler, dependency scanner,
CodeQL/Semgrep product, security audit, or human review.

## Reality check

The benchmarks are committed with their limitations instead of being presented
as a single marketing score:

| Evaluation | Result | Meaning |
|---|---:|---|
| OWASP Java, 2,192 held-out cases | 72.2% precision, 76.4% recall | Good performance on synthetic, template-heavy servlet cases; 31.4% false-positive rate |
| Vul4J, 128 materialized real vulnerabilities | 0/65 strict CWE + patch-line hits | The bundled rules do not yet generalize to complex real vulnerabilities |
| Vul4J with Semgrep registry + bundled | 1/65 strict hits | Broader discovery helps slightly but remains inadequate |

Jev validates candidates; it cannot recover a vulnerability that local discovery
never proposes. This project is useful for experiments, narrow rules, diff
triage, and token-efficiency research—not as a standalone security guarantee.

## Install

Python 3.11 or newer is required.

```bash
./setup.sh
```

Alternatively:

```bash
python -m pip install -e .
```

From GitHub:

```bash
python -m pip install "git+https://github.com/muhandis525/jev-code-reviewer.git@v0.3.1"
```

Supply your own Jev key. Keys are never bundled or auto-discovered from private
machine paths.

```bash
export TYPESAFE_API_KEY="..."
jev-review src
```

## Token-efficient review

```bash
# Default: only ambiguous findings go to Jev
jev-review src --triage smart

# Review only lines added or modified since the base revision
jev-review . --changed-since origin/main

# Set a hard model-review budget; highest-severity candidates go first
jev-review src --max-jev-candidates 20

# Force Jev to assess every candidate for comparison/evaluation
jev-review src --triage all --no-cache

# Fully local: send no source externally
jev-review src --offline
```

The default `.jev-review-cache.json` contains only hashes and typed decisions,
not paths or source text. Delete it at any time or disable it with `--no-cache`.
Intentional matches can be suppressed on their source line with Semgrep's
`nosemgrep` comment or `jev-ignore`; suppressions should include a review reason.

## Reports and CI

```bash
jev-review src --format json --output reports/review.json --fail-on never
jev-review src --format sarif --output reports/review.sarif --fail-on high
```

Exit codes are `0` for a passing review, `1` when `--fail-on` is reached, and
`2` for configuration, scanner, diff, or API failures. The included GitHub
workflow performs an offline changed-line scan and uploads stable-fingerprint
SARIF without requiring secrets from pull requests.

## Privacy and cost

All discovery and line selection happen locally. Online mode sends the rule
claim, classification hint, and at most 1,200 characters of redacted context for
selected candidates. Common assignment secrets, bearer tokens, JWTs, AWS access
keys, token prefixes, and private-key blocks are redacted. Redaction is
best-effort; use `--offline` for code that must not leave the machine.

Each report records API calls, cache hits, input/output tokens, skipped budget,
and estimated input cost using the documented $42-per-billion-token Jev price.

Bundled and explicitly supplied Semgrep configs disable metrics.
`--semgrep-config auto` is opt-in, accesses the Semgrep Registry, and uses its
separate rule license and metrics behavior. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Verify

```bash
python -m unittest discover -s tests -v
semgrep scan --validate --config jev_code_reviewer/rules.yml
```

See [RESEARCH.md](RESEARCH.md) for design evidence and tradeoffs and
[benchmarks/README.md](benchmarks/README.md) for the benchmark methodology and
honest limitations.
