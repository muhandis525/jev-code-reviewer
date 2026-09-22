from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from jev_code_reviewer.diff import changed_lines, filter_changed
from jev_code_reviewer.jev_client import (
    DecisionCache,
    cascade_review,
    local_review,
    parse_answers,
)
from jev_code_reviewer.models import Candidate, Finding, ReviewStats
from jev_code_reviewer.privacy import redact
from jev_code_reviewer.reporters import sarif_report
from jev_code_reviewer.scanner import (
    _normal_confidence,
    scan_builtin,
    scan_with_semgrep,
)


class ReviewerTests(unittest.TestCase):
    def test_semgrep_confidence_labels_are_normalized(self) -> None:
        self.assertEqual(_normal_confidence("HIGH"), 0.90)
        self.assertEqual(_normal_confidence("MEDIUM"), 0.75)
        self.assertEqual(_normal_confidence("LOW"), 0.60)
        self.assertEqual(_normal_confidence("not-a-number"), 0.82)
        self.assertEqual(_normal_confidence(2), 1.0)

    def test_builtin_scanner_reports_exact_lines(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.py"
            path.write_text(
                "def collect(value, values=[]):\n    values.append(value)\n",
                encoding="utf-8",
            )
            findings = scan_builtin([path])
        mutable = [
            item
            for item in findings
            if item.rule_id == "builtin.python.mutable-default"
        ]
        self.assertEqual(len(mutable), 1)
        self.assertEqual(mutable[0].start_line, 1)

    def test_secrets_are_redacted_before_api_use(self) -> None:
        value = 'api_key = "apikey_super_secret_value_123"'  # nosemgrep: test fixture
        redacted = redact(value)
        self.assertNotIn("super_secret", redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_bearer_jwt_and_aws_keys_are_redacted(self) -> None:
        value = (
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz.123456789012\n"
            "token = eyJabcdefghijk.abcdefghijkl.abcdefghijkl\n"
            "aws = AKIAABCDEFGHIJKLMNOP\n"
        )
        redacted = redact(value)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", redacted)
        self.assertNotIn("eyJabcdefghijk", redacted)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", redacted)

    def test_builtin_suppression_comment_is_respected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.py"
            path.write_text(
                'api_key = "definitely_not_real_123"  # jev-ignore\n', encoding="utf-8"
            )
            self.assertEqual(scan_builtin([path]), [])

    def test_semgrep_follows_request_data_to_sql_sink(self) -> None:
        source = (
            "from flask import request\n"
            "def lookup(cursor):\n"
            "    name = request.args.get('name')\n"
            "    return cursor.execute(f\"SELECT * FROM users WHERE name='{name}'\")\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "app.py"
            path.write_text(source, encoding="utf-8")
            candidates = scan_with_semgrep([path])
        self.assertTrue(
            any(item.cwe == "CWE-89" and item.start_line == 4 for item in candidates)
        )

    def test_typed_jev_answers_become_finding(self) -> None:
        candidate = Candidate(
            "rule",
            Path("sample.py"),
            7,
            7,
            1,
            "Issue",
            "Reason",
            "test",
            "security",
            "high",
            "CWE-78",
            "bad()",
            "    7 | bad()",
        )
        answers = {
            "c0_issue": {"type": "noul", "noul": 0.93},
            "c0_category": {"type": "choice", "choice": "security", "confidence": 0.88},
            "c0_severity": {"type": "choice", "choice": "high", "confidence": 0.81},
        }
        findings = parse_answers([candidate], answers, 0.55)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "security")

    def test_sarif_contains_physical_line(self) -> None:
        candidate = Candidate(
            "rule",
            Path("src/app.py"),
            7,
            8,
            1,
            "Issue",
            "Reason",
            "test",
            "correctness",
            "medium",
            None,
            "bad()",
            "    7 | bad()",
        )
        finding = Finding(candidate, "correctness", "medium", 0.9, 0.8, 0.8)
        payload = json.loads(sarif_report([finding]))
        region = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "region"
        ]
        self.assertEqual(region["startLine"], 7)
        self.assertEqual(payload["version"], "2.1.0")
        self.assertIn(
            "jevCodeReviewer/v1",
            payload["runs"][0]["results"][0]["partialFingerprints"],
        )

    def test_polyglot_rules_detect_language_specific_risks(self) -> None:
        examples = {
            "Bad.java": 'class Bad { void run(String x) throws Exception { Runtime.getRuntime().exec("ls " + x); } }',
            "Bad.cs": "class Bad { void Run(System.Threading.Tasks.Task<int> t) { var x = t.Result; } }",
            "bad.rb": "payload = Marshal.load(user_input)\n",
            "bad.rs": "fn cast(x: u32) -> f32 { unsafe { std::mem::transmute(x) } }\n",
            "Bad.kt": 'fun run(x: String) { Runtime.getRuntime().exec("ls " + x) }\n',
            "Bad.swift": "func load() { let x = try! risky() }\n",
            "bad.go": 'package main\nimport "crypto/tls"\nvar c = tls.Config{InsecureSkipVerify: true}\n',
            "Dockerfile": "FROM alpine:3\nUSER root\n",
            "main.tf": 'resource "x" "y" { ingress { cidr_blocks = ["0.0.0.0/0"] } }\n',
        }
        expected = {
            "jev.java.runtime-exec-concatenation",
            "jev.csharp.sync-over-async",
            "jev.ruby.marshal-load",
            "jev.rust.transmute",
            "jev.kotlin.runtime-exec-concatenation",
            "jev.swift.forced-try",
            "jev.go.insecure-tls",
            "jev.docker.root-user",
            "jev.terraform.public-ingress",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, source in examples.items():
                (root / name).write_text(source, encoding="utf-8")
            candidates = scan_with_semgrep([root])
        self.assertTrue(expected.issubset({item.rule_id for item in candidates}))

    def test_java_security_primitive_rules_distinguish_safe_alternatives(self) -> None:
        unsafe = """
class UnsafeCrypto {
  void run(javax.servlet.http.Cookie cookie) throws Exception {
    java.security.MessageDigest.getInstance("SHA-1");
    javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding");
    new java.util.Random().nextLong();
    cookie.setSecure(false);
  }
}
"""
        safe = """
class SafeCrypto {
  void run(javax.servlet.http.Cookie cookie) throws Exception {
    java.security.MessageDigest.getInstance("SHA-256");
    javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
    new java.security.SecureRandom().nextLong();
    cookie.setSecure(true);
  }
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsafe_path = root / "UnsafeCrypto.java"
            safe_path = root / "SafeCrypto.java"
            unsafe_path.write_text(unsafe, encoding="utf-8")
            safe_path.write_text(safe, encoding="utf-8")
            candidates = scan_with_semgrep([root])
        ids = {
            item.rule_id for item in candidates if item.path == unsafe_path.resolve()
        }
        self.assertTrue(
            {
                "jev.java.weak-message-digest",
                "jev.java.weak-cipher",
                "jev.java.weak-security-random",
                "jev.java.insecure-cookie-flag",
            }.issubset(ids)
        )
        self.assertFalse(any(item.path == safe_path.resolve() for item in candidates))

    def test_decision_cache_stores_no_source_code(self) -> None:
        candidate = Candidate(
            "rule",
            Path("sample.py"),
            1,
            1,
            1,
            "Issue",
            "Reason",
            "test",
            "security",
            "high",
            "CWE-78",
            "danger(secret)",
            "1 | danger(secret)",
        )
        decision = {
            "probability": 0.9,
            "category": "security",
            "severity": "high",
            "category_confidence": 0.8,
            "severity_confidence": 0.8,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cache.json"
            cache = DecisionCache(path)
            cache.put(candidate, "jev-latest", decision)
            cache.save()
            raw = path.read_text(encoding="utf-8")
            self.assertNotIn("danger(secret)", raw)
            self.assertEqual(DecisionCache(path).get(candidate, "jev-latest"), decision)

    def test_polyglot_safe_lookalikes_do_not_trigger_new_rules(self) -> None:
        examples = {
            "Safe.java": 'class Safe { void run(String x) throws Exception { new ProcessBuilder("ls", x).start(); } }',
            "Safe.cs": "class Safe { async System.Threading.Tasks.Task<int> Run() { return await Work(); } }",
            "safe.rb": "payload = JSON.parse(user_input)\n",
            "safe.rs": "fn cast(x: u32) -> f64 { x as f64 }\n",
            "Safe.kt": 'fun run(x: String) { ProcessBuilder("ls", x).start() }\n',
            "Safe.swift": "func load() throws { let x = try risky() }\n",
            "safe.go": 'package main\nimport "crypto/tls"\nvar c = tls.Config{MinVersion: tls.VersionTLS12}\n',
            "Dockerfile": "FROM alpine:3\nUSER 10001\n",
            "main.tf": 'resource "x" "y" { ingress { cidr_blocks = ["10.0.0.0/8"] } }\n',
        }
        prefixes = (
            "jev.java.",
            "jev.csharp.",
            "jev.ruby.",
            "jev.rust.",
            "jev.kotlin.",
            "jev.swift.",
            "jev.go.insecure-tls",
            "jev.docker.",
            "jev.terraform.",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, source in examples.items():
                (root / name).write_text(source, encoding="utf-8")
            candidates = scan_with_semgrep([root])
        triggered = [
            item.rule_id for item in candidates if item.rule_id.startswith(prefixes)
        ]
        self.assertEqual(triggered, [])

    def test_smart_cascade_only_sends_ambiguous_candidates(self) -> None:
        def make(line: int, confidence: float) -> Candidate:
            return Candidate(
                f"rule-{line}",
                Path("sample.py"),
                line,
                line,
                1,
                "Issue",
                "Reason",
                "test",
                "correctness",
                "medium",
                None,
                "bad()",
                f"{line} | bad()",
                "python",
                confidence,
            )

        class FakeClient:
            def __init__(self) -> None:
                self.stats = ReviewStats()
                self.received: list[Candidate] = []

            def review(
                self, candidates: list[Candidate], threshold: float
            ) -> list[Finding]:
                self.received = candidates
                self.stats.jev_reviewed = len(candidates)
                return local_review(candidates)

        client = FakeClient()
        findings, stats = cascade_review([make(1, 0.98), make(2, 0.65)], client, 0.55)  # type: ignore[arg-type]
        self.assertEqual([item.start_line for item in client.received], [2])
        self.assertEqual(len(findings), 2)
        self.assertEqual(stats.locally_decided, 1)

    def test_changed_line_filter_excludes_old_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(
                ["git", "config", "user.email", "test@example.com"],
                cwd=root,
                check=True,
            )
            subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
            path = root / "app.py"
            path.write_text("old()\nkeep()\n", encoding="utf-8")
            subprocess.run(["git", "add", "app.py"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
            path.write_text("old()\nchanged()\n", encoding="utf-8")
            candidate_old = Candidate(
                "old",
                path,
                1,
                1,
                1,
                "Old",
                "",
                "test",
                "correctness",
                "low",
                None,
                "",
                "",
            )
            candidate_new = Candidate(
                "new",
                path,
                2,
                2,
                1,
                "New",
                "",
                "test",
                "correctness",
                "low",
                None,
                "",
                "",
            )
            previous = Path.cwd()
            try:
                import os

                os.chdir(root)
                filtered = filter_changed(
                    [candidate_old, candidate_new], changed_lines([root], "HEAD")
                )
            finally:
                os.chdir(previous)
        self.assertEqual([item.rule_id for item in filtered], ["new"])


if __name__ == "__main__":
    unittest.main()
