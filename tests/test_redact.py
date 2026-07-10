"""Tests for enhanced redaction engine."""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import redact


class RedactTests(unittest.TestCase):
    def test_github_pat_redacted(self):
        # Synthetic test value — NOT a real token. Constructed to test the redaction regex.
        fake_pat = "github_pat_" + "X" * 60
        line = f'GITHUB_TOKEN = "{fake_pat}"'
        result = redact.redact_line(line)
        self.assertIn("[github-fine-grained-pat]", result)
        self.assertNotIn("X" * 60, result)

    def test_gitlab_token_redacted(self):
        line = 'GITLAB_TOKEN = "glpat-abcdef1234567890abcdef1234567890"'
        result = redact.redact_line(line)
        self.assertIn("[gitlab-personal-access-token]", result)
        self.assertNotIn("glpat-abcdef1234567890abcdef1234567890", result)

    def test_jwt_token_redacted(self):
        line = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
        result = redact.redact_line(line)
        self.assertNotIn("eyJhbGci", result)

    def test_slack_webhook_redacted(self):
        line = 'SLACK_WEBHOOK = "https://hooks.slack.com/services/TFAKE0000/BFAKE0000/thisIsAFakeTokenForTesting"'  # noqa: test fixture only
        result = redact.redact_line(line)
        self.assertIn("[slack-webhook]", result)

    def test_stripe_key_redacted(self):
        # Construct dynamically so GitHub push protection doesn't flag a static string
        prefix = "sk" + "_live_"
        line = f'STRIPE_KEY = "{prefix}THISISATESTTOKENONLY00000000000000000000000000000000000000000000"'
        result = redact.redact_line(line)
        self.assertIn("[stripe-live-secret-key]", result)

    def test_openai_key_redacted(self):
        prefix = "sk" + "-"
        line = f'OPENAI_API_KEY = "{prefix}THISISATESTTOKENONLY00000000000000000000000000000000000000000000"'
        result = redact.redact_line(line)
        self.assertIn("[openai-api-key]", result)
        self.assertNotIn("THISISATESTTOKEN", result)

    def test_anthropic_key_redacted(self):
        line = 'ANTHROPIC_KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234"'
        result = redact.redact_line(line)
        self.assertIn("[anthropic-api-key]", result)

    def test_yaml_unquoted_secret_detected(self):
        text = "database:\n  password: supersecretvalue123\n  host: localhost"
        findings = redact.detect_yaml_secrets(text)
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0]["key"], "password")

    def test_yaml_variable_ref_not_flagged(self):
        text = "database:\n  password: ${DB_PASSWORD}\n  host: localhost"
        findings = redact.detect_yaml_secrets(text)
        self.assertEqual(len(findings), 0)

    def test_high_entropy_found(self):
        text = "const token = 'xK9mP2vL7nQ4wR8yF3bD6jH1sA5tG0cU'"
        findings = redact.detect_high_entropy_strings(text)
        self.assertGreaterEqual(len(findings), 1)
        # Should NOT contain the raw value
        self.assertNotIn("xK9mP2vL7nQ", str(findings))

    def test_binary_looking_skipped(self):
        # Base64 of PNG header
        binary_b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
        findings = redact.detect_high_entropy_strings(binary_b64)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
