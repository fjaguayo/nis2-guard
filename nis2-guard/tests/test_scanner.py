import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import nis2_scan  # noqa: E402

ALL = list(nis2_scan.FRAMEWORKS)


def scan_files(files: dict[str, str], frameworks=None):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name, content in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        findings, n = nis2_scan.scan(root, frameworks=frameworks)
        report = nis2_scan.render_md(root, findings, n, frameworks)
        return findings, report


def rules_found(files: dict[str, str], frameworks=None) -> set[str]:
    return {f["rule"] for f in scan_files(files, frameworks)[0]}


AI_PY = "from openai import OpenAI\nclient = OpenAI()\n"


class NIS2Tests(unittest.TestCase):
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
        found = rules_found({"app.py": "requests.get(u, verify=False)  # nis2-ignore\n"}, ALL)
        self.assertNotIn("TLS-VERIFY-OFF", found)
        self.assertNotIn("DORA-HTTP-NO-TIMEOUT", found)

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
        _, report = scan_files({"a.py": 'token = "abcdefgh12345678"\n'}, ALL)
        self.assertNotIn("abcdefgh12345678", report)


class FrameworkSelectionTests(unittest.TestCase):
    def test_default_runs_only_nis2_rules(self):
        files = {
            "app.py": AI_PY + 'logger.info(f"login {user.email}")\nrequests.get(u)\n',
            "schema.sql": "CREATE TABLE users (id int, dni varchar(9));\n",
        }
        found = rules_found(files)
        self.assertFalse([r for r in found if r.startswith(("GDPR-", "AIACT-", "DORA-"))])

    def test_shared_rule_counted_once_with_all_refs(self):
        findings, _ = scan_files({"a.py": 'secret = "Zx81kq0Pl2mW"\n'}, ALL)
        hits = [f for f in findings if f["rule"] == "SECRET-HARDCODED"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(set(hits[0]["refs"]), {"nis2", "gdpr", "dora"})

    def test_refs_limited_to_selected(self):
        findings, report = scan_files({"a.py": 'secret = "Zx81kq0Pl2mW"\n'}, ["gdpr"])
        hit = [f for f in findings if f["rule"] == "SECRET-HARDCODED"][0]
        self.assertEqual(set(hit["refs"]), {"gdpr"})
        self.assertEqual(hit["art"], "")
        self.assertIn("GDPR Art. 32", report)
        self.assertNotIn("PROJECT-NO-SECURITY-POLICY", {f["rule"] for f in findings})

    def test_parse_frameworks(self):
        self.assertEqual(nis2_scan.parse_frameworks([]), ["nis2"])
        self.assertEqual(nis2_scan.parse_frameworks(["all"]), ALL)
        self.assertEqual(nis2_scan.parse_frameworks(["dora,gdpr"]), ["gdpr", "dora"])
        with self.assertRaises(SystemExit):
            nis2_scan.parse_frameworks(["hipaa"])

    def test_json_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "r.json"
            (Path(tmp) / "a.py").write_text("x = 1\n", encoding="utf-8")
            nis2_scan.main([tmp, "--framework", "all", "--format", "json", "--output", str(out)])
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["frameworks"], ALL)
            self.assertEqual({m["framework"] for m in data["manual_review"]}, set(ALL))

    def test_manual_blocks_per_framework(self):
        _, report = scan_files({"a.py": "x = 1\n"}, ["gdpr", "dora"])
        self.assertIn("### GDPR", report)
        self.assertIn("### DORA", report)
        self.assertNotIn("### AI Act", report)


class GDPRTests(unittest.TestCase):
    def test_pii_in_logs(self):
        found = rules_found({"a.py": 'logger.info(f"login ok for {user.email}")\n'}, ["gdpr"])
        self.assertIn("GDPR-PII-IN-LOGS", found)
        found = rules_found({"a.py": 'logger.info("login ok", extra={"user_id": uid})\n'}, ["gdpr"])
        self.assertNotIn("GDPR-PII-IN-LOGS", found)

    def test_password_fast_hash(self):
        found = rules_found({"a.py": "h = hashlib.sha256(password.encode()).hexdigest()\n"}, ["gdpr"])
        self.assertIn("GDPR-PASSWORD-FAST-HASH", found)
        found = rules_found({"a.py": "digest = hashlib.sha256(file_bytes).hexdigest()\n"}, ["gdpr"])
        self.assertNotIn("GDPR-PASSWORD-FAST-HASH", found)

    def test_sensitive_plaintext_column(self):
        found = rules_found({"schema.sql": "CREATE TABLE p (\n  id int,\n  dni varchar(9)\n);\n"}, ["gdpr"])
        self.assertIn("GDPR-SENSITIVE-PLAINTEXT-COLUMN", found)
        found = rules_found({"models.py": "dni_enc = Column(String(255))\nnickname = Column(String)\n"}, ["gdpr"])
        self.assertNotIn("GDPR-SENSITIVE-PLAINTEXT-COLUMN", found)

    def test_no_sensitive_false_positive_on_words(self):
        found = rules_found({"schema.sql": "  unified text,\n  spaniel text\n"}, ["gdpr"])
        self.assertNotIn("GDPR-SENSITIVE-PLAINTEXT-COLUMN", found)

    def test_no_erasure_path(self):
        found = rules_found({"schema.sql": "CREATE TABLE users (id int primary key, email text);\n"}, ["gdpr"])
        self.assertIn("GDPR-NO-ERASURE-PATH", found)
        found = rules_found({
            "schema.sql": "CREATE TABLE users (id int primary key);\n",
            "jobs.py": "def anonymize_inactive_users():\n    pass\n",
        }, ["gdpr"])
        self.assertNotIn("GDPR-NO-ERASURE-PATH", found)

    def test_tracker_without_consent(self):
        page = "<script src='https://www.googletagmanager.com/gtag/js'></script>\n"
        self.assertIn("GDPR-TRACKER-NO-CONSENT", rules_found({"index.html": page}, ["gdpr"]))
        found = rules_found({"index.html": page, "cmp.js": "initCookieConsent();\n"}, ["gdpr"])
        self.assertNotIn("GDPR-TRACKER-NO-CONSENT", found)

    def test_pii_to_llm(self):
        code = AI_PY + 'messages = [{"role": "user", "content": f"Write to {customer.email}"}]\n'
        self.assertIn("GDPR-PII-TO-LLM", rules_found({"a.py": code}, ["gdpr"]))
        code = 'messages = [{"role": "user", "content": f"Write to {customer.email}"}]\n'
        self.assertNotIn("GDPR-PII-TO-LLM", rules_found({"a.py": code}, ["gdpr"]))

    def test_report_never_contains_personal_data(self):
        code = 'logger.info("user 12345678Z ana@example.org logged in", user.email)\n'
        _, report = scan_files({"a.py": code}, ["gdpr"])
        self.assertNotIn("12345678Z", report)
        self.assertNotIn("ana@example.org", report)


class AIActTests(unittest.TestCase):
    def test_no_ai_rules_without_sdk(self):
        code = 'system = f"You help {user_name}"\neval(response.content)\n'
        found = rules_found({"a.py": code}, ["ai-act"])
        self.assertFalse([r for r in found if r.startswith("AIACT-")])

    def test_llm_output_exec(self):
        code = AI_PY + "eval(resp.choices[0].message.content)\n"
        self.assertIn("AIACT-LLM-OUTPUT-EXEC", rules_found({"a.py": code}, ["ai-act"]))
        code = AI_PY + "data = json.loads(resp.choices[0].message.content)\n"
        self.assertNotIn("AIACT-LLM-OUTPUT-EXEC", rules_found({"a.py": code}, ["ai-act"]))

    def test_prompt_injection(self):
        code = AI_PY + 'msgs = [{"role": "system", "content": f"Rules for {user_input}"}]\n'
        self.assertIn("AIACT-PROMPT-INJECTION-RISK", rules_found({"a.py": code}, ["ai-act"]))
        code = AI_PY + 'msgs = [{"role": "system", "content": SYSTEM_PROMPT}]\n'
        self.assertNotIn("AIACT-PROMPT-INJECTION-RISK", rules_found({"a.py": code}, ["ai-act"]))

    def test_js_sdk_detected(self):
        code = "import Anthropic from '@anthropic-ai/sdk';\nconst system = `Act as ${req.body.role}`;\n" \
               "client.messages.create({ system: `Act as ${req.body.role}` });\n"
        self.assertIn("AIACT-PROMPT-INJECTION-RISK", rules_found({"a.ts": code}, ["ai-act"]))

    def test_disclosure_and_audit(self):
        found = rules_found({"a.py": AI_PY}, ["ai-act"])
        self.assertIn("AIACT-NO-DISCLOSURE", found)
        self.assertIn("AIACT-NO-AI-AUDIT-LOG", found)
        found = rules_found({
            "a.py": AI_PY + 'audit.log(model_version=m, prompt_hash=h)\n',
            "ui.html": "<p>This answer is AI-generated.</p>\n",
        }, ["ai-act"])
        self.assertNotIn("AIACT-NO-DISCLOSURE", found)
        self.assertNotIn("AIACT-NO-AI-AUDIT-LOG", found)

    def test_sdk_in_manifest_only(self):
        found = rules_found({"requirements.txt": "anthropic==0.40.0\n"}, ["ai-act"])
        self.assertIn("AIACT-NO-DISCLOSURE", found)

    def test_high_risk_indicator(self):
        code = AI_PY + "def rank_candidate(cv):\n    return client.responses.create(input=cv)\n"
        self.assertIn("AIACT-HIGH-RISK-INDICATOR", rules_found({"a.py": code}, ["ai-act"]))
        code += "def finalize(c):\n    require_approval(c)\n"
        self.assertNotIn("AIACT-HIGH-RISK-INDICATOR", rules_found({"a.py": code}, ["ai-act"]))


class DORATests(unittest.TestCase):
    def test_weak_tls(self):
        self.assertIn("DORA-WEAK-TLS-VERSION",
                      rules_found({"nginx.conf": "ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n"}, ["dora"]))
        self.assertNotIn("DORA-WEAK-TLS-VERSION",
                         rules_found({"nginx.conf": "ssl_protocols TLSv1.2 TLSv1.3;\n"}, ["dora"]))
        self.assertIn("DORA-WEAK-TLS-VERSION",
                      rules_found({"a.py": "ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n"}, ["dora"]))
        self.assertNotIn("DORA-WEAK-TLS-VERSION",
                         rules_found({"a.py": "ctx.minimum_version = ssl.TLSVersion.TLSv1_2\n"}, ["dora"]))

    def test_http_no_timeout(self):
        self.assertIn("DORA-HTTP-NO-TIMEOUT", rules_found({"a.py": "r = requests.get(url)\n"}, ["dora"]))
        self.assertNotIn("DORA-HTTP-NO-TIMEOUT",
                         rules_found({"a.py": "r = requests.get(url, timeout=5)\n"}, ["dora"]))
        multi = "r = requests.post(\n    url,\n    timeout=5,\n)\n"
        self.assertNotIn("DORA-HTTP-NO-TIMEOUT", rules_found({"a.py": multi}, ["dora"]))

    def test_resilience_lib(self):
        self.assertIn("DORA-NO-RESILIENCE-LIB", rules_found({"requirements.txt": "stripe==9.0.0\n"}, ["dora"]))
        found = rules_found({"requirements.txt": "stripe==9.0.0\ntenacity==8.2.3\n"}, ["dora"])
        self.assertNotIn("DORA-NO-RESILIENCE-LIB", found)

    def test_healthcheck(self):
        self.assertIn("DORA-NO-HEALTHCHECK", rules_found({"requirements.txt": "fastapi==0.110.0\n"}, ["dora"]))
        found = rules_found({"requirements.txt": "fastapi==0.110.0\n",
                             "main.py": '@app.get("/health")\ndef health():\n    return {}\n'}, ["dora"])
        self.assertNotIn("DORA-NO-HEALTHCHECK", found)

    def test_unpinned_action(self):
        wf = "steps:\n  - uses: actions/checkout@v4\n  - uses: ./local-action\n"
        findings, _ = scan_files({".github/workflows/ci.yml": wf})
        hits = [f for f in findings if f["rule"] == "DORA-UNPINNED-ACTION"]
        self.assertEqual([h["detail"] for h in hits], ["actions/checkout@v4"])
        pinned = "steps:\n  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2\n"
        self.assertNotIn("DORA-UNPINNED-ACTION", rules_found({".github/workflows/ci.yml": pinned}))


if __name__ == "__main__":
    unittest.main()
