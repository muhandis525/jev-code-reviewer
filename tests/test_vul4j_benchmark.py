from __future__ import annotations

import unittest

from benchmarks.vul4j.score import score


class Vul4jBenchmarkScorerTests(unittest.TestCase):
    def test_patch_line_and_cwe_must_both_match_for_strict_credit(self) -> None:
        manifest = {
            "cases_requested": 2,
            "cases": [
                {
                    "vul_id": "VUL4J-1",
                    "cve_id": "CVE-1",
                    "cwe": "CWE-89",
                    "files": [{"path": "src/App.java", "ranges": [[10, 12]]}],
                },
                {
                    "vul_id": "VUL4J-2",
                    "cve_id": "CVE-2",
                    "cwe": "CWE-79",
                    "files": [{"path": "src/Web.java", "ranges": [[20, 20]]}],
                },
            ],
        }
        report = {
            "findings": [
                {
                    "path": "cases/VUL4J-1/vulnerable/src/App.java",
                    "start_line": 11,
                    "cwe": "CWE-89",
                },
                {
                    "path": "cases/VUL4J-2/vulnerable/src/Web.java",
                    "start_line": 20,
                    "cwe": "CWE-22",
                },
            ]
        }
        result = score(manifest, report)
        self.assertEqual(result["patch_line_hits"], 2)
        self.assertEqual(result["strict_cwe_patch_line_hits"], 1)
        self.assertEqual(result["strict_cwe_recall"], 0.5)

    def test_unmaterialized_cases_are_excluded_and_reported(self) -> None:
        manifest = {
            "cases_requested": 2,
            "cases": [
                {
                    "vul_id": "VUL4J-1",
                    "cve_id": "CVE-1",
                    "cwe": None,
                    "files": [{"path": "A.java", "ranges": [[1, 1]]}],
                },
                {"vul_id": "VUL4J-2", "cve_id": "CVE-2", "cwe": None, "files": []},
            ],
        }
        result = score(manifest, {"findings": []})
        self.assertEqual(result["cases_materialized"], 1)
        self.assertEqual(result["cases_excluded"], 1)


if __name__ == "__main__":
    unittest.main()
