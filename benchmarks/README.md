# Benchmarks

There are two deliberately separate evaluation tracks:

- `owasp/` scores against 2,740 externally maintained positive and negative
  cases with a predeclared 80% held-out split. Use this for the most defensible
  security detection score.
- `vul4j/` materializes vulnerable files and human-patch ranges for 129
  real-world Java vulnerabilities. It measures recall only because the corpus
  has no negative cases.
- `complex/` is the small, hand-authored regression set described below. It is
  useful for classifications and token use, but is not independent evidence.

## Complex benchmark

This benchmark measures the reviewer against 21 manually labeled issues across
Python/Flask, TypeScript, Go, and C. Labels are stored in `ground_truth.json`,
outside the source files, so neither Semgrep nor Jev sees the expected answers.

The corpus mixes:

- injection, XSS, unsafe deserialization, unsafe memory operations, and SSRF;
- error handling, resource lifetime, goroutine cancellation, and request timeouts;
- mutable defaults, off-by-one access, coercive equality, and missing `await`;
- safe lookalikes such as parameterized SQL, argument-array subprocess calls,
  `textContent`, `JSON.parse`, handled Go errors, and `snprintf`.

## Reproduce

```bash
./jev-review benchmarks/complex \
  --semgrep-config auto \
  --batch-size 8 \
  --format json \
  --output reports/complex-auto-live.json \
  --fail-on never

.venv/bin/python benchmarks/score_benchmark.py \
  reports/complex-auto-live.json \
  --output reports/complex-auto-score.json
```

`auto` downloads Semgrep registry rules and requires the network and Semgrep's
anonymous metrics. Omit `--semgrep-config auto` to test the deterministic bundled
rule set.

## Results (2026-09-22, v0.2)

| Mode | Findings | Precision | Recall | Exact severity | Input tokens | Score |
|---|---:|---:|---:|---:|---:|---:|
| Bundled offline | 12 | 100% | 57.1% | 91.7% | 0 | 80.7 / B |
| Jev on every candidate | 11 | 100% | 52.4% | 81.8% | 7,327 | 78.6 / C |
| Smart cascade, cold cache | 11 | 100% | 52.4% | 100% | 1,836 | 78.6 / C |
| Smart cascade, warm cache | 11 | 100% | 52.4% | 100% | 0 | 78.6 / C |

On this corpus, smart mode made one API call for three ambiguous candidates and
used 74.9% fewer input tokens than sending all 12 candidates. The warm-cache run
made zero API calls. Detection quality was unchanged relative to the all-Jev run.

The overall score weights precision 30%, recall 45%, category accuracy 15%, and
severity-within-one-level accuracy 10%. Smart mode's exact severity accuracy was
100% in this run; this small synthetic sample is not a calibration benchmark.

Jev rejected the low-severity coercive-equality candidate during triage. The
discovery layer did not propose the hardcoded token naming variant,
off-by-one condition, missing timeout, file leak, missing `await`, ignored body
read, goroutine cancellation issue, or undersized allocation.

These numbers are useful for regression testing, not marketing claims. The
corpus is small, synthetic, and was authored alongside the implementation. It
does not estimate performance on arbitrary repositories.
