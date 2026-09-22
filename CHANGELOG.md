# Changelog

## 0.3.1 - 2026-09-22

- Re-license the project from the MIT License to the Apache License 2.0.
- Align package metadata, documentation, notices, and release installation
  instructions with the new license and version.

## 0.3.0 - 2026-09-22

- Add 11 Java security rules for weak cryptography, weak randomness, insecure
  cookies, and servlet-to-command/SQL/XSS/path/LDAP/XPath/session data flow.
- Add a pinned, independently labelled OWASP Benchmark Java evaluator with a
  predeclared 80% held-out split, strict CWE matching, and confusion-matrix,
  MCC, per-CWE, and OWASP signal metrics.
- Publish the unfiltered result, including the 31.4% held-out false-positive
  rate, and document the separate Vul4J real-vulnerability evaluation track.
- Accept numeric and LOW/MEDIUM/HIGH confidence metadata from Semgrep registry
  rules instead of crashing during opt-in `auto` scans.

## 0.2.0 — 2026-09-22

- Expanded the bundled pack to 37 rules and added tested Java, C#, Ruby, Rust,
  Kotlin, Swift, Dockerfile, and Terraform coverage.
- Added smart local/Jev cascading, severity-first budgets, exact token/cost
  accounting, compact prompts, and a source-free decision cache.
- Added Git changed-line filtering, suppression comments, retry handling,
  stronger redaction, portable paths, and stable SARIF fingerprints.
- Added installable packaging, a lockfile, CI, an offline PR workflow, licensing,
  third-party notices, and a security policy.
- Added unsafe and safe polyglot regression cases and live smart-vs-all
  benchmark measurements.

## 0.1.0 — 2026-09-22

- Initial hybrid Semgrep/Python scanner and Jev typed triage.
- Text, JSON, and SARIF output with a four-language synthetic benchmark.
