"""Tests for auditor modules: variable tracker, regex sandbox, tool bridge."""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from auditors.variable_tracker import scan_file_for_tracked_variables, TRACK_RULES
from auditors.regex_sandbox import (
    classify_redos_risk,
    safe_compile,
    estimate_complexity,
    safe_compile_custom_rule,
)
from auditors.tool_bridge import check_availability, TOOL_REGISTRY


class VariableTrackerTests(unittest.TestCase):
    def test_detects_sql_fstring_variable(self):
        path = Path("app.py")
        text = (
            'sql = f"SELECT * FROM users WHERE id = {user_id}"\n'
            "cursor.execute(sql)\n"
        )
        findings = scan_file_for_tracked_variables(path, text, TRACK_RULES)
        sql_ids = {f["rule_id"] for f in findings}
        self.assertIn("track-sql-fstring", sql_ids)

    def test_no_false_positive_on_safe_execute(self):
        path = Path("app.py")
        text = (
            'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n'
        )
        findings = scan_file_for_tracked_variables(path, text, TRACK_RULES)
        self.assertEqual(len(findings), 0)

    def test_detects_shell_variable(self):
        path = Path("deploy.py")
        text = (
            'cmd = f"rm -rf {user_path}"\n'
            "subprocess.run(cmd, shell=True)\n"
        )
        findings = scan_file_for_tracked_variables(path, text, TRACK_RULES)
        shell_ids = {f["rule_id"] for f in findings}
        self.assertIn("track-shell-command", shell_ids)

    def test_detects_path_traversal_variable(self):
        path = Path("views.py")
        text = (
            'filepath = os.path.join("/var/data", request.args.get("file"))\n'
            "return send_file(filepath)\n"
        )
        findings = scan_file_for_tracked_variables(path, text, TRACK_RULES)
        path_ids = {f["rule_id"] for f in findings}
        self.assertIn("track-path-traversal", path_ids)

    def test_detects_ssrf_variable(self):
        path = Path("api.py")
        text = (
            'target_url = request.args.get("url")\n'
            "requests.get(target_url)\n"
        )
        findings = scan_file_for_tracked_variables(path, text, TRACK_RULES)
        ssrf_ids = {f["rule_id"] for f in findings}
        self.assertIn("track-ssrf", ssrf_ids)

    def test_respects_extension_filter(self):
        path = Path("script.sh")
        text = (
            'sql = f"SELECT * FROM users WHERE id = {uid}"\n'
            "cursor.execute(sql)\n"
        )
        findings = scan_file_for_tracked_variables(path, text, TRACK_RULES)
        # SQL tracking rules require .py extension
        sql_findings = [f for f in findings if f["rule_id"].startswith("track-sql")]
        self.assertEqual(len(sql_findings), 0)


class RegexSandboxTests(unittest.TestCase):
    def test_detects_nested_quantifier_redos(self):
        warnings = classify_redos_risk(r"(a+)+b")
        self.assertGreater(len(warnings), 0)
        self.assertIn("nested quantifier", warnings[0])

    def test_detects_alternation_redos(self):
        warnings = classify_redos_risk(r"(a|aa|aaa)+c")
        self.assertGreater(len(warnings), 0)

    def test_detects_overlapping_dot_star(self):
        warnings = classify_redos_risk(r".*.*b")
        self.assertGreater(len(warnings), 0)

    def test_safe_pattern_passes(self):
        warnings = classify_redos_risk(r"SELECT.*FROM.*WHERE")
        self.assertEqual(len(warnings), 0)

    def test_safe_compile_strict_raises(self):
        with self.assertRaises(ValueError):
            safe_compile(r"(a+)+b", strict=True)

    def test_safe_compile_non_strict_warns(self):
        # Should compile with warning but not raise
        pattern = safe_compile(r"(a+)+b", strict=False)
        self.assertIsNotNone(pattern)

    def test_estimate_complexity_simple(self):
        score = estimate_complexity(r"hello")
        self.assertEqual(score, 0)

    def test_estimate_complexity_complex(self):
        score = estimate_complexity(r"(a+)+b|c*d|e{1,5}")
        self.assertGreater(score, 10)

    def test_safe_compile_custom_rule_blocks_complex(self):
        with self.assertRaises(ValueError):
            safe_compile_custom_rule(
                r"(a+)+b|c*d|e{1,5}|f*g|h+i|j{2,10}|k{1,5}l|m*n|o+p|q{3}r",
                rule_id="test",
                max_complexity=10,
            )

    def test_safe_compile_custom_rule_allows_simple(self):
        pattern = safe_compile_custom_rule(
            r"SELECT.*FROM.*WHERE",
            rule_id="test",
            max_complexity=30,
        )
        self.assertIsNotNone(pattern)

    def test_invalid_regex_raises(self):
        with self.assertRaises(ValueError):
            safe_compile(r"[unclosed", strict=False)


class ToolBridgeTests(unittest.TestCase):
    def test_registry_has_expected_tools(self):
        self.assertIn("semgrep", TOOL_REGISTRY)
        self.assertIn("gitleaks", TOOL_REGISTRY)
        self.assertIn("hadolint", TOOL_REGISTRY)
        self.assertIn("bandit", TOOL_REGISTRY)

    def test_check_availability_returns_dict(self):
        available = check_availability()
        self.assertIsInstance(available, dict)
        self.assertIn("semgrep", available)

    def test_tool_registry_has_install_hints(self):
        for name, info in TOOL_REGISTRY.items():
            self.assertIn("install_hint", info, f"{name} missing install_hint")
            self.assertIn("binary", info, f"{name} missing binary")
            self.assertIn("description", info, f"{name} missing description")


if __name__ == "__main__":
    unittest.main()
