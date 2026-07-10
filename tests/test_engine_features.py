import io
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


if __name__ == "__main__":
    unittest.main()
