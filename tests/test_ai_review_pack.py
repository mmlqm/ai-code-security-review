import tempfile
import unittest
from pathlib import Path

import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import ai_review_pack


class AiReviewPackTests(unittest.TestCase):
    def write(self, root: Path, rel: str, text: str) -> None:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_builds_codex_review_pack_with_scanner_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "app/auth.py", "def allowed(user):\n    return True  # auth bypass\n")

            pack = ai_review_pack.build_pack(root, agent="codex", depth="deep")

            self.assertIn("AI-Assisted Code Security Review Pack", pack)
            self.assertIn("Use $ai-code-security-review", pack)
            self.assertIn("Adaptive Review Scope", pack)
            self.assertIn("Estimated tokens", pack)
            self.assertIn("auth-placeholder", pack)
            self.assertIn("app/auth.py", pack)

    def test_cli_writes_claude_pack(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "src/session.py", "API_KEY = 'ReviewFixture7f3A9q2Lx8Zp'\n")
            output = root / "pack.md"

            exit_code = ai_review_pack.main([str(root), "--agent", "claude", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            text = output.read_text(encoding="utf-8")
            self.assertIn("Agent: claude", text)
            self.assertIn("ai-code-security-review skill", text)
            self.assertIn("***redacted***", text)


if __name__ == "__main__":
    unittest.main()
