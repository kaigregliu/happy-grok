import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import happy_grok


class HappyGrokTests(unittest.TestCase):
    def test_redacts_matches_by_default(self):
        value = "zgQ9" + "LmN4" + "Rx72" + "PvA8"
        text = "API_" + "KEY=" + value
        findings = happy_grok.scan_text(text, "config.env", 1, show=False)

        self.assertTrue(findings)
        self.assertEqual(findings[0].match, "zgQ9...PvA8")

    def test_filters_obvious_placeholders(self):
        text = "API_KEY=example-placeholder-token"
        findings = happy_grok.scan_text(text, "example.env", 1, show=False)

        self.assertEqual(findings, [])

    def test_detects_sensitive_file_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text("HELLO=world\n", encoding="utf-8")

            evidence = happy_grok.sensitive_path_evidence(root)

        self.assertTrue(any(item.kind == "sensitive-file-present" for item in evidence))

    def test_scan_files_skips_binary_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "binary.dat").write_bytes(b"\0API_KEY=" + (b"a" * 24))

            findings = happy_grok.scan_files(root, max_file_mb=1, show=False)

        self.assertEqual(findings, [])

    def test_json_report_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "report.json"
            finding = happy_grok.Finding(
                kind="secret",
                severity="high",
                rule_id="test-rule",
                location="file.txt",
                line=1,
                match="abcd...wxyz",
                recommendation="Rotate it.",
            )

            happy_grok.write_json(report, root, [finding], [], git_enabled=False)
            payload = json.loads(report.read_text(encoding="utf-8"))

        self.assertEqual(payload["tool"], "happy-grok")
        self.assertEqual(payload["summary"]["high"], 1)
        self.assertIn("findings", payload)
        self.assertIn("evidence", payload)

    def test_cli_missing_path_returns_usage_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing"
            proc = subprocess.run(
                [sys.executable, str(ROOT / "happy_grok.py"), str(missing)],
                text=True,
                capture_output=True,
            )

        self.assertEqual(proc.returncode, 2)
        self.assertIn("path does not exist", proc.stderr)

    def test_cli_returns_one_for_high_or_critical_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_url = "postgres://user:" + "p" * 18 + "@localhost:5432/app"
            (root / "settings.txt").write_text("DATABASE_URL=" + db_url + "\n", encoding="utf-8")

            proc = subprocess.run(
                [sys.executable, str(ROOT / "happy_grok.py"), str(root), "--no-history"],
                text=True,
                capture_output=True,
            )

        self.assertEqual(proc.returncode, 1)
        self.assertIn("database-url", proc.stdout)
        self.assertNotIn("p" * 18, proc.stdout)

    def test_git_history_scan_detects_removed_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._git(root, "init")
            self._git(root, "config", "user.email", "test@example.com")
            self._git(root, "config", "user.name", "Test User")
            value = "zgQ9" + "LmN4" + "Rx72" + "PvA8"
            token = "API_" + "KEY=" + value + "\n"
            secret_file = root / "config.txt"
            secret_file.write_text(token, encoding="utf-8")
            self._git(root, "add", "config.txt")
            self._git(root, "commit", "-m", "add config")
            secret_file.write_text("API_KEY=example-placeholder-token\n", encoding="utf-8")
            self._git(root, "commit", "-am", "remove secret")

            findings = happy_grok.scan_git_history(root, show=False, max_findings=20)

        self.assertTrue(any(item.rule_id == "generic-assignment" for item in findings))

    def test_git_tracked_sensitive_file_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._git(root, "init")
            self._git(root, "config", "user.email", "test@example.com")
            self._git(root, "config", "user.name", "Test User")
            (root / ".env").write_text("HELLO=world\n", encoding="utf-8")
            self._git(root, "add", ".env")
            self._git(root, "commit", "-m", "track env")

            evidence = happy_grok.git_tracked_sensitive_files(root)

        self.assertTrue(any(item.kind == "sensitive-file-tracked" for item in evidence))

    def _git(self, cwd, *args):
        env = os.environ.copy()
        env["GIT_AUTHOR_DATE"] = "2026-01-01T00:00:00Z"
        env["GIT_COMMITTER_DATE"] = "2026-01-01T00:00:00Z"
        proc = subprocess.run(["git", *args], cwd=cwd, text=True, capture_output=True, env=env)
        if proc.returncode != 0:
            self.fail(f"git {' '.join(args)} failed:\n{proc.stdout}\n{proc.stderr}")


if __name__ == "__main__":
    unittest.main()
