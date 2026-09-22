# Contributing

Bug reports should include the smallest non-sensitive reproducer possible,
expected behavior, actual behavior, and the exact command used.

For a new rule:

1. prefer a syntax-aware Semgrep pattern over a broad regex;
2. assign category, severity, CWE where applicable, and a conservative local
   confidence string;
3. add one unsafe example and at least one safe lookalike to the unit tests;
4. run the full checks below;
5. explain false-positive boundaries in the pull request.

```bash
python -m unittest discover -s tests -v
semgrep scan --validate --config jev_code_reviewer/rules.yml
ruff check jev_code_reviewer tests benchmarks/owasp benchmarks/vul4j benchmarks/score_benchmark.py
ruff format --check jev_code_reviewer tests benchmarks/owasp benchmarks/vul4j benchmarks/score_benchmark.py
```

Never include API keys, proprietary source, production data, or Semgrep Registry
rules in a contribution. Benchmark improvements should preserve raw reports and
clearly identify synthetic, public, and independently labeled datasets.
