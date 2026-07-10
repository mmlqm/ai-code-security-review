import tempfile
import unittest
from pathlib import Path

import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import audit_code


class BuiltinRuleTests(unittest.TestCase):
    def write(self, root: Path, rel: str, text: str) -> None:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_builtin_catalog_has_expanded_coverage(self):
        rules = audit_code._rules()
        ids = {rule.id for rule in rules}

        self.assertGreaterEqual(len(ids), 47)
        self.assertIn("jwt-none-algorithm", ids)
        self.assertIn("mongo-query-from-request", ids)
        self.assertIn("mass-assignment-js", ids)
        self.assertIn("ssti-render-template-string", ids)

    def test_high_value_ai_failure_rules_match(self):
        cases = [
            ("jwt-none-algorithm", "auth.py", 'jwt.decode(token, algorithms=["none"])\n'),
            ("express-default-session-secret", "server.js", 'app.use(session({ secret: "keyboard cat" }))\n'),
            ("django-allowed-hosts-wildcard", "settings.py", 'ALLOWED_HOSTS = ["*"]\n'),
            ("mongo-query-from-request", "api.js", "db.users.find(req.body)\n"),
            ("mongo-dollar-operator-input", "api.js", 'db.users.find({"$ne": req.query.role})\n'),
            ("mass-assignment-js", "users.js", "User.create(req.body)\n"),
            ("mass-assignment-python", "views.py", "User.objects.create(**request.POST)\n"),
            ("ssti-render-template-string", "views.py", 'render_template_string(request.args.get("tpl"))\n'),
            ("open-redirect-request", "views.py", 'return redirect(request.args.get("next"))\n'),
            ("xss-dangerously-set-inner-html", "App.jsx", "return <div dangerouslySetInnerHTML={{__html: userHtml}} />\n"),
            ("xss-innerhtml-location", "app.js", "element.innerHTML = location.search\n"),
            ("cors-wildcard-with-credentials", "server.js", 'app.use(cors({ origin: "*", credentials: true }))\n'),
            ("bcrypt-low-rounds", "auth.js", "bcrypt.hash(password, 4)\n"),
            ("terraform-public-s3", "bucket.tf", 'acl = "public-read"\n'),
        ]

        for rule_id, rel, source in cases:
            with self.subTest(rule_id=rule_id):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    self.write(root, rel, source)

                    report = audit_code.scan_project(root)
                    ids = {finding.rule_id for finding in report.findings}

                    self.assertIn(rule_id, ids)


if __name__ == "__main__":
    unittest.main()
