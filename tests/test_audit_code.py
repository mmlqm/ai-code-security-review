import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import audit_code


class AuditCodeTests(unittest.TestCase):
    def write(self, root: Path, rel: str, text: str) -> None:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_detects_and_redacts_release_blockers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(
                root,
                "app/auth.py",
                'API_KEY = "ReviewFixture7f3A9q2Lx8Zp"\n'
                "\n"
                "def is_admin(user):\n"
                "    return True  # auth temporary bypass\n",
            )

            report = audit_code.scan_project(root)
            rule_ids = {finding.rule_id for finding in report.findings}

            self.assertIn("secret-generic-hardcoded", rule_ids)
            self.assertIn("auth-placeholder", rule_ids)
            self.assertTrue(audit_code.should_fail(report, "HIGH"))
            rendered = audit_code.render_report(report, "markdown")
            self.assertIn("***redacted***", rendered)
            self.assertNotIn("ReviewFixture7f3A9q2Lx8Zp", rendered)

    def test_cli_returns_failure_for_high_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "auth.py", "def allowed(user):\n    return True  # auth bypass\n")

            stream = io.StringIO()
            with redirect_stdout(stream):
                exit_code = audit_code.main([str(root), "--format", "json", "--fail-on", "HIGH"])

            self.assertEqual(exit_code, 1)
            payload = json.loads(stream.getvalue())
            self.assertEqual(payload["summary"]["status"], "fail")

    def test_sarif_output_is_structured(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "Dockerfile", "FROM python:latest\nUSER root\n")

            report = audit_code.scan_project(root)
            sarif = json.loads(audit_code.render_report(report, "sarif"))

            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(len(sarif["runs"]), 1)
            self.assertIn("tool", sarif["runs"][0])


if __name__ == "__main__":
    unittest.main()
