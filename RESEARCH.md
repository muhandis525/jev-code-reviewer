# Research and design record

Research was refreshed on 2026-09-22 using primary documentation and published
evaluation papers. The design conclusions below are deliberately narrower than
the usual “AI reviews your repository” claim.

## Why a selective cascade

Semgrep supports 30+ language/framework families and can perform semantic and
intra-file taint analysis. Its Community Edition does not provide the same
cross-file capabilities as the commercial engine. Jev accepts structured
questions and returns typed decisions plus input/output usage. These properties
fit a cascade: deterministic analysis supplies exact evidence; Jev decides only
cases whose local precision is not high enough.

This avoids asking a probabilistic model to invent file locations and reduces
source exposure, latency, and spend. The implementation also records the actual
token counts returned by Jev instead of estimating prompt size locally.

## Evidence-driven priorities

- The 2025 MITRE CWE Top 25 puts XSS, SQL injection, missing authorization,
  memory bounds errors, path traversal, command/code injection, unsafe
  deserialization, SSRF, and resource exhaustion among the most consequential
  weaknesses. The bundled pack prioritizes mechanically detectable members of
  those classes.
- GitHub warns that SARIF uploads without `partialFingerprints` can create
  duplicate alerts. Reports therefore include a stable project fingerprint.
- Semgrep documents `--baseline-commit`, but it can reject dirty worktrees.
  This project implements read-only Git hunk filtering that also includes
  untracked files, then sends only changed-line candidates to Jev.
- Published AI-review studies report useful suggestions alongside substantial
  rejection and false-positive rates. Jev is therefore a triage layer, not the
  sole source of findings and not an automatic authority.

## Token controls

The following mechanisms compound rather than duplicate each other:

1. exact local rules avoid whole-file/repository prompts;
2. overlapping detector matches deduplicate before model use;
3. `smart` mode locally accepts only evidence above a configurable confidence;
4. changed-line filtering removes unrelated legacy findings;
5. severity-first budgets cap the number of candidates sent;
6. batches share task criteria and hold at most eight candidates;
7. payload keys and instructions are compact, and context is capped;
8. content-addressed caching reuses decisions without storing source code.

`--triage all --no-cache` remains available for evaluation. It should not be the
default production mode because it spends tokens on deterministic findings.

## Limitations

- Bundled rules are intentionally small compared with mature SAST products.
- Community-edition data flow is mainly intra-file; architectural and
  cross-service bugs remain difficult.
- Local confidence values are engineering priors, not statistically calibrated
  probabilities. They need calibration on a much larger held-out corpus.
- A finding on a changed line can depend on unchanged code outside the reported
  hunk. Diff mode is a review-noise control, not a full-program proof.
- Redaction cannot guarantee removal of every proprietary value or credential.
- OWASP Benchmark is still synthetic and template-heavy. Its independently
  maintained labels and negative cases make it much stronger than the local
  regression set, but it is not evidence of accuracy on arbitrary production
  repositories.
- The 2,192-case held-out OWASP result has a 31.4% false-positive rate. The
  generic Java servlet taint rules therefore need triage and should not gate a
  build without a project-specific baseline.
- On 128 materialized Vul4J vulnerabilities, the bundled pack touched only 3
  human-patch locations and matched zero of 65 available CWE labels. The opt-in
  Semgrep community registry touched 6 patch locations and strictly matched one
  CWE. This is strong evidence that discovery breadth—not Jev token use—is the
  current bottleneck on real production defects.

## Primary references

- TypeSafe API schema: https://api.typesafe.ai/docs
- TypeSafe, “Introducing System One Models & Jev”:
  https://typesafe.ai/blog/introducing-system-one-models-and-jev
- Semgrep supported integrations/languages:
  https://semgrep.dev/products/integrations/
- Semgrep taint-analysis glossary:
  https://semgrep.dev/docs/writing-rules/glossary
- Semgrep CLI (`--baseline-commit`, metrics, limits):
  https://docs.semgrep.dev/cli-reference
- MITRE 2025 CWE Top 25:
  https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html
- GitHub SARIF support and fingerprints:
  https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support
- OASIS SARIF 2.1.0:
  https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
- OWASP Benchmark project and scoring corpus:
  https://owasp.org/www-project-benchmark/
- NIST Software Assurance Reference Dataset (SARD):
  https://www.nist.gov/itl/ssd/software-quality-group/software-assurance-reference-dataset-sard
- NIST Juliet 1.3 C/C++ and Java test suite:
  https://www.nist.gov/publications/juliet-13-cc-and-java-test-suite
- Vul4J real-world Java vulnerability dataset:
  https://github.com/tuhh-softsec/vul4j
- “Is Agentic Code Review Helpful?” (2026 preprint):
  https://arxiv.org/abs/2607.03316
- Industrial AI-assisted review study (2024 preprint):
  https://arxiv.org/abs/2412.18531
