import json
import tempfile
import unittest
from pathlib import Path

import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import ai_report
import audit_code


class AiReportTests(unittest.TestCase):
    def write(self, root: Path, rel: str, text: str) -> Path:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_merges_scanner_and_ai_findings_into_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "auth.py", "def allowed(user):\n    return True  # auth bypass\n")
            scanner_report = audit_code.scan_project(root).to_dict()
            scanner_path = root / "scanner.json"
            scanner_path.write_text(json.dumps(scanner_report), encoding="utf-8")
            ai_path = root / "ai.json"
            ai_path.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "dimension": "business-logic",
                                "title": "Payment replay lacks idempotency",
                                "severity": "HIGH",
                                "confidence": "medium",
                                "location": "payments.py:42",
                                "description": "A repeated callback can process the same payment twice.",
                                "risk_path": "Callback handler lacks an idempotency key check before fulfillment.",
                                "remediation": "Store and enforce an idempotency key.",
                                "test_recommendation": "Replay the same callback and assert one fulfillment.",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            scanner, items = ai_report.build_report(root, scanner_report_path=str(scanner_path), ai_finding_paths=[str(ai_path)])
            markdown = ai_report.render_markdown(scanner, items)

            self.assertIn("Payment replay lacks idempotency", markdown)
            self.assertIn("auth-placeholder", markdown)
            self.assertIn("Release Blockers", markdown)

    def test_cli_writes_pr_comment_and_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scanner_path = root / "scanner.json"
            scanner_path.write_text(
                json.dumps({"summary": {"root": str(root), "status": "pass", "score": 100}, "findings": []}),
                encoding="utf-8",
            )
            ai_path = root / "ai.json"
            ai_path.write_text(
                json.dumps(
                    {
                        "chains": [
                            {
                                "title": "Info leak plus SSRF exposes internal data",
                                "severity": "CRITICAL",
                                "confidence": "high",
                                "location": "api.py:9",
                                "linked_findings": ["info-leak", "ssrf-request-url"],
                                "description": "Two findings combine into internal data exposure.",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            report_path = root / "report.md"
            comment_path = root / "comment.md"
            json_path = root / "combined.json"

            exit_code = ai_report.main(
                [
                    str(root),
                    "--scanner-report",
                    str(scanner_path),
                    "--ai-findings",
                    str(ai_path),
                    "--output",
                    str(report_path),
                    "--pr-comment-output",
                    str(comment_path),
                    "--json-output",
                    str(json_path),
                    "--fail-on",
                    "CRITICAL",
                ]
            )

            self.assertEqual(exit_code, 1)
            self.assertIn("Info leak plus SSRF", report_path.read_text(encoding="utf-8"))
            self.assertIn("Release Blockers", comment_path.read_text(encoding="utf-8"))
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["counts"]["CRITICAL"], 1)


if __name__ == "__main__":
    unittest.main()
