from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from benchmarks.owasp.score import read_labels, score


class OwaspBenchmarkScorerTests(unittest.TestCase):
    def test_requires_matching_test_and_cwe(self) -> None:
        labels = [
            {
                "name": "BenchmarkTest00001",
                "number": 1,
                "category": "sqli",
                "vulnerable": True,
                "cwe": 89,
            },
            {
                "name": "BenchmarkTest00005",
                "number": 5,
                "category": "sqli",
                "vulnerable": False,
                "cwe": 89,
            },
        ]
        report = {
            "findings": [
                {
                    "path": "src/BenchmarkTest00001.java",
                    "cwe": "CWE-89",
                    "rule_id": "right",
                },
                {
                    "path": "src/BenchmarkTest00005.java",
                    "cwe": "CWE-79",
                    "rule_id": "wrong-cwe",
                },
            ]
        }
        result = score(labels, report)
        self.assertEqual(result["all"]["true_positives"], 1)
        self.assertEqual(result["all"]["false_positives"], 0)
        self.assertEqual(result["report_summary"]["wrong_cwe_findings"], 1)
        self.assertEqual(result["held_out"]["true_positives"], 1)
        self.assertEqual(result["development"]["true_negatives"], 1)

    def test_false_positive_and_duplicate_are_counted_per_case(self) -> None:
        labels = [
            {
                "name": "BenchmarkTest00005",
                "number": 5,
                "category": "xss",
                "vulnerable": False,
                "cwe": 79,
            }
        ]
        finding = {
            "path": "BenchmarkTest00005.java",
            "cwe": "CWE-79",
            "rule_id": "xss",
        }
        result = score(labels, {"findings": [finding, finding]})
        self.assertEqual(result["all"]["false_positives"], 1)
        self.assertEqual(result["report_summary"]["duplicate_matching_findings"], 1)

    def test_label_reader_ignores_header_comment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "labels.csv"
            path.write_text(
                "# comment\nBenchmarkTest00001,pathtraver,true,22\n",
                encoding="utf-8",
            )
            labels = read_labels(path)
        self.assertEqual(labels[0]["cwe"], 22)
        self.assertTrue(labels[0]["vulnerable"])


if __name__ == "__main__":
    unittest.main()
