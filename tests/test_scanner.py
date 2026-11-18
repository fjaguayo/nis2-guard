import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "nis2-guard" / "scripts"))
import nis2_scan  # noqa: E402


def rules_found(files: dict[str, str]) -> set[str]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name, content in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        findings, _ = nis2_scan.scan(root)
        return {f["rule"] for f in findings}


class ScannerTests(unittest.TestCase):
    def test_detects_core_issues(self):
        code = "\n".join([
            "import hashlib, requests",
            'password = "' + "hunter2" + 'Zk9!xQ"',
            "requests.get(url, verify=False)",
            'h = hashlib.md5(b"x")',
            'cur.execute(f"SELECT * FROM t WHERE id={uid}")',
            "DEBUG = True",
        ])
        found = rules_found({"app.py": code})
        for rid in ("SECRET-HARDCODED", "TLS-VERIFY-OFF", "CRYPTO-WEAK-HASH",
                    "INJECTION-SQL", "DEBUG-ENABLED"):
            self.assertIn(rid, found)

    def test_placeholders_are_ignored(self):
        found = rules_found({"app.py": 'api_key = "your_api_key_here"\n'})
        self.assertNotIn("SECRET-HARDCODED", found)

    def test_ignore_comment(self):
        found = rules_found({"app.py": "requests.get(u, verify=False)  # nis2-ignore\n"})
        self.assertNotIn("TLS-VERIFY-OFF", found)

    def test_env_not_ignored(self):
        found = rules_found({".env": "DB_PASSWORD=supersecretvalue123\n"})
        self.assertIn("PROJECT-ENV-NOT-IGNORED", found)
        self.assertIn("SECRET-HARDCODED", found)

    def test_env_ignored_is_ok(self):
        found = rules_found({".env": "A=1\n", ".gitignore": ".env\n"})
        self.assertNotIn("PROJECT-ENV-NOT-IGNORED", found)

    def test_dockerfile_checks(self):
        found = rules_found({"Dockerfile": "FROM python:latest\nRUN curl https://x.sh | sh\n"})
        self.assertIn("DOCKER-ROOT", found)
        self.assertIn("DOCKER-UNPINNED-IMAGE", found)
        self.assertIn("DOCKER-CURL-PIPE", found)

    def test_dockerfile_clean(self):
        found = rules_found({"Dockerfile": "FROM python:3.12-slim\nUSER app\n"})
        self.assertNotIn("DOCKER-ROOT", found)
        self.assertNotIn("DOCKER-UNPINNED-IMAGE", found)

    def test_missing_lockfile(self):
        found = rules_found({"package.json": "{}"})
        self.assertIn("PROJECT-NO-LOCKFILE", found)

    def test_project_docs_detected(self):
        found = rules_found({"SECURITY.md": "x", "docs/incident-response.md": "x"})
        self.assertNotIn("PROJECT-NO-SECURITY-POLICY", found)
        self.assertNotIn("PROJECT-NO-INCIDENT-PLAN", found)

    def test_report_never_contains_secret_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.py").write_text('token = "abcdefgh12345678"\n', encoding="utf-8")
            findings, n = nis2_scan.scan(root)
            report = nis2_scan.render_md(root, findings, n)
            self.assertNotIn("abcdefgh12345678", report)


if __name__ == "__main__":
    unittest.main()
