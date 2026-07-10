import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import audit_code


class EngineFeatureTests(unittest.TestCase):
    def write(self, root: Path, rel: str, text: str) -> None:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_auditignore_excludes_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, ".auditignore", "ignored/**\n")
            self.write(root, "ignored/auth.py", "def allowed(user):\n    return True  # auth bypass\n")
            self.write(root, "app.py", "print('ok')\n")

            report = audit_code.scan_project(root)

            self.assertNotIn("ignored/auth.py", {finding.path for finding in report.findings})
            self.assertGreaterEqual(report.summary.skipped_files, 1)

    def test_changed_paths_scan_only_selected_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "safe.py", "print('ok')\n")
            self.write(root, "unsafe.py", "def allowed(user):\n    return True  # auth bypass\n")

            safe_report = audit_code.scan_project(root, changed_paths=["safe.py"])
            unsafe_report = audit_code.scan_project(root, changed_paths=["unsafe.py"])

            self.assertNotIn("auth-placeholder", {finding.rule_id for finding in safe_report.findings})
            self.assertIn("auth-placeholder", {finding.rule_id for finding in unsafe_report.findings})

    def test_changed_files_from_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            changed = root / "changed.txt"
            self.write(root, "safe.py", "print('ok')\n")
            self.write(root, "unsafe.py", "def allowed(user):\n    return True  # auth bypass\n")
            changed.write_text("unsafe.py\n", encoding="utf-8")

            stream = io.StringIO()
            with redirect_stdout(stream):
                exit_code = audit_code.main([str(root), "--changed-files-from", str(changed), "--format", "json"])

            self.assertEqual(exit_code, 1)
            self.assertIn("auth-placeholder", stream.getvalue())

    def test_color_output_can_be_forced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "auth.py", "def allowed(user):\n    return True  # auth bypass\n")

            stream = io.StringIO()
            with redirect_stdout(stream):
                audit_code.main([str(root), "--color", "always", "--fail-on", "none"])

            self.assertIn("\033[", stream.getvalue())

    @unittest.skipIf(sys.version_info < (3, 11), "tomllib requires Python 3.11+")
    def test_sliding_window_custom_rule_matches_across_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(
                root,
                ".audit-code.toml",
                """
[[rules]]
id = "policy-cross-line-secret"
title = "Cross-line unsafe pattern"
severity = "HIGH"
category = "policy"
pattern = "BEGIN_UNSAFE\\\\s+END_UNSAFE"
remediation = "Remove the cross-line unsafe pattern."
scan_mode = "sliding_window"
window_lines = 2
""",
            )
            self.write(root, "sample.py", "BEGIN_UNSAFE\nEND_UNSAFE\n")

            report = audit_code.scan_project(root)

            self.assertIn("policy-cross-line-secret", {finding.rule_id for finding in report.findings})

    @unittest.skipIf(sys.version_info < (3, 11), "tomllib requires Python 3.11+")
    def test_deprecated_multiline_maps_to_anchors_cross_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(
                root,
                ".audit-code.toml",
                """
[[rules]]
id = "policy-anchor-second-line"
title = "Anchor second line"
severity = "LOW"
category = "policy"
pattern = "^SECOND_LINE"
remediation = "Review the second line."
scan_mode = "file"
multiline = true
""",
            )
            self.write(root, "sample.py", "FIRST_LINE\nSECOND_LINE\n")

            report = audit_code.scan_project(root)

            self.assertIn("policy-anchor-second-line", {finding.rule_id for finding in report.findings})

    def test_requirements_inline_comments_are_ignored_for_pin_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "requirements.txt", "flask==3.0.0  # pinned\nrequests  # not pinned\n")

            report = audit_code.scan_project(root)
            findings = [finding for finding in report.findings if finding.rule_id == "python-unpinned-dependency"]

            self.assertEqual(len(findings), 1)
            self.assertIn("requests", findings[0].snippet)

    def test_long_lines_are_reported_as_scan_limitation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "bundle.js", "x" * 5001 + "\n")

            report = audit_code.scan_project(root)

            self.assertEqual(report.summary.long_lines_skipped, 1)
            self.assertIn("scan-long-lines-skipped", {finding.rule_id for finding in report.findings})

    def test_python_sql_variable_tracking_finds_cross_line_execute(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(
                root,
                "app.py",
                "def load_user(user_id, cursor):\n"
                "    sql = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
                "    return cursor.execute(sql)\n",
            )

            report = audit_code.scan_project(root)

            self.assertIn("sql-python-variable-track", {finding.rule_id for finding in report.findings})

    def test_python_shell_variable_tracking_finds_cross_line_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(
                root,
                "tasks.py",
                "def archive(name):\n"
                "    cmd = f\"tar czf /tmp/{name}.tgz {name}\"\n"
                "    return subprocess.run(cmd, shell=True)\n",
            )

            report = audit_code.scan_project(root)

            self.assertIn("shell-python-variable-track", {finding.rule_id for finding in report.findings})

    def test_tracked_variable_reassignment_clears_previous_risk(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(
                root,
                "app.py",
                "def load_user(user_id, cursor):\n"
                "    sql = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
                "    sql = \"SELECT * FROM users WHERE id = ?\"\n"
                "    return cursor.execute(sql, [user_id])\n",
            )

            report = audit_code.scan_project(root)

            self.assertNotIn("sql-python-variable-track", {finding.rule_id for finding in report.findings})


if __name__ == "__main__":
    unittest.main()
