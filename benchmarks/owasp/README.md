# OWASP Benchmark Java evaluation

This is the project's first external, independently labelled evaluation. It uses
OWASP Benchmark Java 1.2 at commit
`20cbf3d11123347e47ed89541e6942836def53f7`. The corpus is GPL-2.0 and is fetched
outside the package into the ignored `.benchmarks/` directory.

The split was declared before rule development:

- development: numeric test ID modulo 5 equals 0;
- held-out: every other test ID (80% of the corpus).

A prediction is credited only when a finding is assigned to the correct test
file **and** has the expected CWE. The evaluator reports confusion-matrix
metrics, per-CWE results, and OWASP's signal score (`recall - false positive
rate`). Wrong-CWE and unassigned findings receive no credit.

```bash
python benchmarks/owasp/fetch.py
jev-review .benchmarks/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode \
  --offline --engine semgrep --format json --fail-on never \
  --output .benchmarks/owasp-report.json
python benchmarks/owasp/score.py .benchmarks/owasp-report.json \
  --labels .benchmarks/BenchmarkJava/expectedresults-1.2.csv \
  --output .benchmarks/owasp-score.json
```

This suite is synthetic and template-heavy. It measures known web-security
source/sink patterns well, but it is not evidence that the tool finds the same
issues in arbitrary production projects. Real-vulnerability evaluation is a
separate benchmark track.

## Frozen result (2026-09-22)

The baseline 37-rule pack detected none of the 1,415 correctly classified
vulnerable cases. The expanded 48-rule pack produced this result without Jev:

| Partition | Cases | Precision | Recall | False-positive rate | OWASP score |
|---|---:|---:|---:|---:|---:|
| Development | 548 | 70.7% | 74.5% | 32.7% | 41.76% |
| Held-out | 2,192 | 72.2% | 76.4% | 31.4% | 44.99% |
| All | 2,740 | 71.9% | 76.0% | 31.7% | 44.34% |

The held-out confusion matrix is TP 866, FP 333, FN 267, TN 726. The result is
useful but not production-grade: nearly one in three negative cases is flagged.
See `results-2026-09-22.json` for the machine-readable summary.
