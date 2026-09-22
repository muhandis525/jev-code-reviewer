# Vul4J real-vulnerability evaluation

This track evaluates findings against human patches for 129 reproducible,
real-world Java vulnerabilities. It pins the Vul4J metadata repository at
`376411da11fa705019f731404de1d0679fe73537` and does not redistribute upstream
source code.

`prepare.py` fetches the fixing commit with partial Git clones, exports only the
changed Java files from its vulnerable parent, and records old-file patch ranges.
`score.py` reports file-hit recall, patch-line recall, and strict patch-line plus
CWE recall. Vul4J is positive-only, so this track cannot measure precision or a
false-positive rate; use OWASP Benchmark for those metrics.

```bash
python benchmarks/vul4j/prepare.py
python benchmarks/vul4j/run.py --output .benchmarks/vul4j-report.json
python benchmarks/vul4j/score.py .benchmarks/vul4j-report.json \
  --manifest .benchmarks/vul4j-cases/manifest.json \
  --output .benchmarks/vul4j-score.json
```

Use `--limit 10` for a transparent smoke run. A limited run is a pilot, not a
publishable score, and must always state its sample size.

## Frozen result (2026-09-22)

Of 129 cases, 128 were materialized into 305 changed Java files. VUL4J-23 was
excluded because its historical fixing commit is unavailable from the current
upstream Git remote.

| Discovery pack | File hits | Patch-line hits | Strict CWE + line hits |
|---|---:|---:|---:|
| Bundled rules | 29/128 (22.7%) | 3/128 (2.3%) | 0/65 (0%) |
| Semgrep `auto` + bundled | 45/128 (35.2%) | 6/128 (4.7%) | 1/65 (1.5%) |

These results are poor. File hits are reported only as a loose diagnostic; a
finding must touch the human patch and match its CWE to count as strict. Jev was
not run because it cannot recover a vulnerability for which discovery produced
no relevant candidate. See `results-2026-09-22.json`.
