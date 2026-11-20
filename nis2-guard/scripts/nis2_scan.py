#!/usr/bin/env python3
"""nis2-guard: static scanner that helps align a codebase with the technical side of
four EU frameworks: NIS2, GDPR, the AI Act and DORA.

Standard library only. It looks for technical signals in code and repository layout
that relate to:
  - NIS2   Directive (EU) 2022/2555, Art. 21 and 23
  - GDPR   Regulation (EU) 2016/679, Art. 5, 9, 17, 25, 32, 33, 44+
  - AI Act Regulation (EU) 2024/1689, Art. 12, 14, 15, 50
  - DORA   Regulation (EU) 2022/2554, Art. 9, 11, 17, 19, 24-28
It certifies nothing: it is a helper for catching the obvious problems.

Usage:
    python nis2_scan.py PATH [--framework nis2|gdpr|ai-act|dora|all ...]
                             [--format md|json] [--output FILE]
                             [--fail-on high|medium|low|none] [--exclude GLOB ...]

Without --framework only the NIS2 rules run. To silence a single line, add
"nis2-ignore" in a comment on that line (works for every framework).
Line-based rules look at one line at a time: calls split over several lines can be
missed (false negatives) and are reported as such in the manual checks.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

FRAMEWORKS = ("nis2", "gdpr", "ai-act", "dora")
FW_LABEL = {"nis2": "NIS2", "gdpr": "GDPR", "ai-act": "AI Act", "dora": "DORA"}

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist",
    "build", ".next", "target", "vendor", ".tox", ".mypy_cache", ".idea",
}
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock",
    "cargo.lock", "go.sum", "pipfile.lock", "composer.lock",
}
CODE_EXT = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".cs",
    ".rs", ".kt", ".swift", ".sh",
}
CONFIG_EXT = {
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".tf",
    ".properties", ".xml", ".env",
}
# Extra extensions: only the rules that opt in with "exts" look at them.
EXTRA_EXT = {".sql", ".prisma", ".html", ".htm", ".vue", ".svelte"}
SCAN_EXT = CODE_EXT | CONFIG_EXT
MAX_BYTES = 1_000_000
SEV_ORDER = {"high": 3, "medium": 2, "low": 1}
LABEL = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
MANIFESTS = {
    "package.json", "requirements.txt", "pyproject.toml", "pipfile", "setup.py",
    "setup.cfg", "go.mod", "pom.xml", "build.gradle", "build.gradle.kts", "gemfile",
    "composer.json", "cargo.toml",
}

PLACEHOLDER = re.compile(
    r"(?i)example|changeme|change_me|your[_-]|xxx|<[^>]+>|\$\{|%\(|environ|"
    r"getenv|process\.env|\*{3,}|dummy|sample|placeholder|todo|fake"
)
ENV_SECRET = re.compile(
    r"(?i)^\s*(?:export\s+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)"
    r"[A-Z0-9_]*\s*=\s*[^\s'\"#$][^\s#]{7,}"
)

# Personal data field names (GDPR rules).
PII = (r"(?:e[-_]?mail|ip_?address|remote_addr|\bip\b|phone|tel[eé]fono|\bdni\b|\bnie\b|"
       r"\bnif\b|\bssn\b|iban|birth|fecha_?nacimiento|\bdob\b|\baddress\b|direcci[oó]n|"
       r"full_?name|first_?name|last_?name|apellidos?)")
SENSITIVE_PARTS = {"dni", "nie", "nif", "ssn", "iban", "diagnosis", "diagnostico",
                   "health", "medical", "salud", "nss"}
ENC_MARK = re.compile(r"(?i)encrypt|pgp_sym|_enc\b|hash|cipher|vault|kms")

AI_IMPORT = re.compile(
    r"(?m)^\s*(?:from|import)\s+(?:openai|anthropic|langchain\w*|llama_index|"
    r"google\.generativeai|google\.genai|mistralai|cohere|ollama|transformers|litellm)\b"
    r"|(?:require\(\s*|from\s+)['\"](?:openai|@anthropic-ai/sdk|langchain|@langchain/[\w-]+|"
    r"llamaindex|@google/genai|@google/generative-ai|@mistralai/mistralai|cohere-ai|ollama|ai)['\"]"
)
AI_MANIFEST = re.compile(
    r"(?im)^\s*['\"]?(?:openai|anthropic|@anthropic-ai/sdk|langchain[\w-]*|@langchain/[\w-]+|"
    r"llama[-_]index|llamaindex|google-generativeai|google-genai|@google/genai|mistralai|"
    r"@mistralai/mistralai|cohere|cohere-ai|ollama|transformers|litellm)['\"]?\s*(?:[=<>~!:@,\]]|$)"
)


def _balanced_from(m: re.Match) -> bool:
    """True when the call that starts at the match closes on the same line."""
    rest = m.string[m.start():]
    return rest.count("(") <= rest.count(")")


def _sensitive_column(m: re.Match) -> bool:
    col = m.group("col").lower()
    if ENC_MARK.search(m.string):
        return False
    parts = set(re.split(r"_+", col))
    return bool(parts & SENSITIVE_PARTS) or "card_number" in col or "cardnumber" in col \
        or "credit_card" in col


RULES = [
    # ---------------- Shared rules (NIS2, with cross-mappings) ----------------
    {
        "id": "SECRET-HARDCODED", "sev": "high",
        "refs": {"nis2": "21(2)(h), 21(2)(i)", "gdpr": "32", "dora": "9"},
        "placeholder_check": True,
        "pats": [
            r"AKIA[0-9A-Z]{16}",
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            r"gh[pousr]_[A-Za-z0-9]{36,}",
            r"sk-ant-[A-Za-z0-9_\-]{20,}",
            r"sk_live_[A-Za-z0-9]{20,}",
            r"xox[baprs]-[A-Za-z0-9-]{10,}",
            r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b"
            r"\s*[:=]\s*['\"][^'\"\s]{8,}['\"]",
        ],
        "msg": "Possible credential written in code or in a configuration file.",
        "fix": "Remove it from the repository, rotate the credential (treat it as exposed) and read it from an environment variable or a secrets manager.",
    },
    {
        "id": "TLS-VERIFY-OFF", "sev": "high",
        "refs": {"nis2": "21(2)(h)", "gdpr": "32", "dora": "9"},
        "pats": [
            r"verify\s*=\s*False",
            r"rejectUnauthorized\s*:\s*false",
            r"InsecureSkipVerify\s*:\s*true",
            r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0",
            r"CURLOPT_SSL_VERIFYPEER\W+(?:false|0)",
            r"ssl\._create_unverified_context",
        ],
        "msg": "TLS certificate verification is disabled.",
        "fix": "Remove the override. If the problem is an internal CA, add that CA to the trust store instead of skipping verification.",
    },
    {
        "id": "AUTH-JWT-UNSAFE", "sev": "high",
        "refs": {"nis2": "21(2)(i), 21(2)(j)", "gdpr": "32", "dora": "9"},
        "code_only": True,
        "pats": [
            r"algorithms\s*=\s*\[\s*['\"]none['\"]",
            r"verify_signature['\"]?\s*:\s*False",
        ],
        "msg": "JWT tokens are accepted without verifying the signature.",
        "fix": "Always verify the signature and pin the list of allowed algorithms (for example RS256 or ES256).",
    },
    {
        "id": "INJECTION-SQL", "sev": "high",
        "refs": {"nis2": "21(2)(e)", "gdpr": "32"}, "code_only": True,
        "pats": [
            r"\.(?:execute|executemany|query|raw)\(\s*(?:f['\"]|['\"][^'\"]*['\"]\s*(?:%|\+|\.format\())",
            r"\.query\(\s*`[^`]*\$\{",
        ],
        "msg": "SQL query built by concatenating or interpolating strings: injection risk.",
        "fix": "Use parameterized queries (placeholders with parameters passed separately) or the ORM.",
    },
    {
        "id": "CRYPTO-WEAK-CIPHER", "sev": "high",
        "refs": {"nis2": "21(2)(h)", "gdpr": "32", "dora": "9"}, "code_only": True,
        "pats": [r"MODE_ECB|AES/ECB|\bRC4\b|\b3DES\b|DES/|DESede|createCipher\("],
        "msg": "Obsolete cipher or insecure mode (ECB, DES, RC4).",
        "fix": "Switch to AES-256-GCM or ChaCha20-Poly1305, with keys and nonces handled by a high-level library.",
    },
    {
        "id": "CRYPTO-WEAK-HASH", "sev": "medium",
        "refs": {"nis2": "21(2)(h)", "gdpr": "32", "dora": "9"}, "code_only": True,
        "pats": [
            r"hashlib\.(?:md5|sha1)\(",
            r"getInstance\(\s*['\"](?:MD5|SHA-?1)['\"]",
            r"createHash\(\s*['\"](?:md5|sha1)['\"]",
            r"\b(?:MD5|SHA1)\.Create\(",
        ],
        "msg": "MD5 or SHA-1 in use; neither is suitable for security purposes.",
        "fix": "Use SHA-256 or stronger for integrity, and argon2id, scrypt or bcrypt for passwords.",
    },
    {
        "id": "EXEC-DANGEROUS", "sev": "medium",
        "refs": {"nis2": "21(2)(e)", "ai-act": "15"}, "code_only": True,
        "pats": [
            r"\beval\(", r"\bos\.system\(", r"shell\s*=\s*True",
            r"child_process\.exec\(", r"\bpickle\.loads?\(", r"yaml\.load\((?![^)]*Loader)",
        ],
        "msg": "Dynamic code execution or unsafe deserialization.",
        "fix": "Avoid eval and shell=True, pass arguments as a list, use yaml.safe_load and data formats that cannot execute code.",
    },
    {
        "id": "DEBUG-ENABLED", "sev": "medium",
        "refs": {"nis2": "21(2)(e)", "gdpr": "32"}, "code_only": True,
        "pats": [r"\bDEBUG\s*=\s*True\b", r"\bdebug\s*=\s*True\b"],
        "msg": "Debug mode enabled in code: it can leak stack traces and internal data.",
        "fix": "Read it from configuration and keep it off by default in production.",
    },
    {
        "id": "CORS-WILDCARD", "sev": "medium",
        "refs": {"nis2": "21(2)(e), 21(2)(i)", "gdpr": "32"},
        "pats": [
            r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]?\*",
            r"allow_origins\s*=\s*\[\s*['\"]\*['\"]",
            r"origin\s*:\s*['\"]\*['\"]",
            r"CORS_ALLOW_ALL_ORIGINS\s*=\s*True",
        ],
        "msg": "CORS is open to any origin.",
        "fix": "List the allowed origins explicitly.",
    },
    {
        "id": "LOG-SENSITIVE", "sev": "medium",
        "refs": {"nis2": "21(2)(i)", "gdpr": "32", "dora": "9"}, "code_only": True,
        "pats": [
            r"(?i)(?:log(?:ger)?\.\w+|print|console\.\w+|logging\.\w+)\(.*"
            r"\b(?:password|passwd|token|secret|api[_-]?key|authorization)\b"
        ],
        "msg": "A log statement may be writing sensitive data (check whether it logs the value or only the name).",
        "fix": "Never log passwords, tokens or authorization headers; mask or drop the value.",
    },
    {
        "id": "HTTP-PLAINTEXT", "sev": "low",
        "refs": {"nis2": "21(2)(h)", "gdpr": "32"}, "code_only": True,
        "pats": [r"['\"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|www\.w3\.org|schemas\.|example\.)"],
        "msg": "URL using unencrypted HTTP.",
        "fix": "Use HTTPS unless the traffic is strictly local.",
    },
    {
        "id": "DORA-UNPINNED-ACTION", "sev": "low",
        "refs": {"nis2": "21(2)(d)", "dora": "28"},
        "path_glob": ".github/workflows/*",
        "pats": [r"^\s*-?\s*uses:\s*['\"]?(?P<ref>[^\s'\"#]+)"],
        "post": lambda m: not m.group("ref").startswith(("./", "docker://"))
        and not re.search(r"@[0-9a-f]{40}$", m.group("ref")),
        "detail": lambda m: m.group("ref"),
        "msg": "GitHub Action referenced by tag or branch: whoever controls that tag controls your pipeline.",
        "fix": "Pin the action to a full commit SHA and keep the tag in a comment (Dependabot can still update it).",
    },
    # ---------------- GDPR ----------------
    {
        "id": "GDPR-PII-IN-LOGS", "sev": "medium",
        "refs": {"gdpr": "5(1)(f), 32"}, "code_only": True,
        "pats": [
            r"(?i)(?:log(?:ger)?\.\w+|print|console\.\w+|logging\.\w+|capture_?message|"
            r"captureMessage|captureException|set_?user|setUser)\(.*" + PII
        ],
        "msg": "A log or error-tracker call may include personal data (email, IP, phone, ID number, IBAN, name or address).",
        "fix": "Log a pseudonymous identifier (internal user id or a salted hash) instead of the personal data, or mask it before logging.",
    },
    {
        "id": "GDPR-PASSWORD-FAST-HASH", "sev": "high",
        "refs": {"gdpr": "32"}, "code_only": True,
        "pats": [
            r"(?i)hashlib\.(?:md5|sha1|sha224|sha256|sha384|sha512)\([^)]*(?:password|passwd|pwd|contrase)",
            r"(?i)(?:password|passwd|pwd)\w*\s*=\s*hashlib\.(?:md5|sha1|sha224|sha256|sha384|sha512)\(",
            r"(?i)createHash\(\s*['\"](?:md5|sha1|sha256|sha512)['\"]\s*\)\s*\.update\([^)]*(?:password|passwd|pwd)",
            r"(?i)DigestUtils\.(?:md5|sha1|sha256|sha512)\w*\([^)]*(?:password|passwd|pwd)",
        ],
        "msg": "Password hashed with a fast general-purpose hash: it can be brute-forced at scale if the database leaks.",
        "fix": "Use argon2id (preferred), scrypt or bcrypt through a maintained library (argon2-cffi, passlib, bcrypt).",
    },
    {
        "id": "GDPR-SENSITIVE-PLAINTEXT-COLUMN", "sev": "medium",
        "refs": {"gdpr": "9, 32"}, "exts": {".sql", ".prisma", ".py"},
        "pats": [
            r"(?i)^\s*[`\"\[]?(?P<col>\w+)[`\"\]]?\s+(?:n?varchar|n?char|text|string|clob)\b",
            r"^\s*(?P<col>\w+)\s+String\b",
            r"(?P<col>\w+)\s*(?::\s*Mapped\[[^\]]*\])?\s*=\s*(?:db\.|sa\.)?(?:Column|mapped_column)\(\s*(?:db\.|sa\.)?(?:String|Text|Unicode)",
            r"(?P<col>\w+)\s*=\s*models\.(?:Char|Text)Field",
        ],
        "post": _sensitive_column,
        "detail": lambda m: m.group("col"),
        "msg": "Column for national IDs, bank/card numbers or health data stored as plain text.",
        "fix": "Encrypt the column at the application level (AES-GCM with keys in a KMS) or with the database's encryption features, and restrict who can read it.",
    },
    {
        "id": "GDPR-TRACKER-NO-CONSENT", "sev": "low",
        "refs": {"gdpr": "6, 7 (+ ePrivacy)"}, "exts": {".html", ".htm", ".vue", ".svelte"},
        "code_too": True,
        "pats": [r"\bgtag\(|\bfbq\(|googletagmanager\.com|static\.hotjar\.com|\bhj\(|"
                 r"mixpanel\.init\(|analytics\.load\(|clarity\.ms|_hsq\.push|connect\.facebook\.net"],
        "msg": "Analytics or advertising tracker loaded and no consent management detected in the project.",
        "fix": "Load trackers only after explicit consent (a consent manager or your own banner) and record that consent.",
    },
    {
        "id": "GDPR-PII-TO-LLM", "sev": "medium",
        "refs": {"gdpr": "28, 44+"}, "code_only": True, "ai_file": True,
        "pats": [
            r"(?i)\b(?:content|prompt|messages?|input|system|query|text)\b.*"
            r"(?:f['\"][^'\"]*\{[^}]*" + PII + r"[^}]*\}|\$\{[^}]*" + PII + r"[^}]*\}|"
            r"\.format\([^)]*" + PII + r"|\+\s*[\w.\[\]'\"]*" + PII + r")"
        ],
        "msg": "Personal data appears to be interpolated into a prompt sent to an external AI provider.",
        "fix": "Send only what the task needs: pseudonymize or strip personal data before the call, and check there is a DPA and a valid transfer mechanism with the provider.",
    },
    # ---------------- AI Act ----------------
    {
        "id": "AIACT-LLM-OUTPUT-EXEC", "sev": "high",
        "refs": {"ai-act": "15"}, "code_only": True, "ai_file": True,
        "pats": [
            r"(?i)(?:\beval|\bexec|subprocess\.\w+|os\.system|\.execute|\.executescript|"
            r"child_process\.exec\w*|\bexecSync)\(.*(?:completion|choices|\.content\b|output_text|"
            r"response\.text|generated_text|llm_output|model_output|\.invoke\()"
        ],
        "msg": "Model output is executed as code, a shell command or SQL.",
        "fix": "Never execute model output directly. Parse it into a strict schema, validate it against an allow-list and run only predefined actions.",
    },
    {
        "id": "AIACT-PROMPT-INJECTION-RISK", "sev": "medium",
        "refs": {"ai-act": "15"}, "code_only": True, "ai_file": True,
        "pats": [
            r"['\"]?role['\"]?\s*:\s*['\"]system['\"].*['\"]?content['\"]?\s*:\s*"
            r"(?:f['\"]|`[^`]*\$\{|[^,}]*\+\s*\w|[^,}]*\.format\()",
            r"\bsystem\s*=\s*(?:f['\"]|[^,)]*\.format\(|[^,)'\"]*\+\s*\w)",
            r"\bsystem\s*:\s*`[^`]*\$\{",
            r"SystemMessage\(\s*(?:content\s*=\s*)?f['\"]",
        ],
        "msg": "Dynamic data is interpolated into the system prompt: user-controlled text there can override your instructions.",
        "fix": "Keep the system prompt static. Pass user input in the user turn, clearly delimited, and validate the model's output before acting on it.",
    },
    # ---------------- DORA ----------------
    {
        "id": "DORA-WEAK-TLS-VERSION", "sev": "high",
        "refs": {"dora": "9", "nis2": "21(2)(h)"}, "fw_only": "dora",
        "pats": [
            r"PROTOCOL_TLSv1(?:_1)?\b|PROTOCOL_SSLv[23]\b|\bTLSv1_(?:1_)?method\b|\bSSLv3_method\b",
            r"TLSVersion\.(?:TLSv1(?:_1)?|SSLv3)\b",
            r"minVersion\s*:\s*['\"]TLSv1(?:\.1)?['\"]",
            r"secureProtocol\s*:\s*['\"](?:TLSv1|TLSv1_1|SSLv3)_method['\"]",
            r"MinVersion\s*:\s*tls\.VersionTLS1[01]\b",
            r"ssl_protocols[^;\n]*(?:\bSSLv3\b|\bTLSv1(?:\.1)?(?![.\d]))",
        ],
        "msg": "A legacy protocol (SSLv3, TLS 1.0 or TLS 1.1) is explicitly allowed.",
        "fix": "Require TLS 1.2 as the minimum, TLS 1.3 where possible, and remove legacy protocols from server and client configuration.",
    },
    {
        "id": "DORA-HTTP-NO-TIMEOUT", "sev": "medium",
        "refs": {"dora": "9, 11"}, "code_only": True,
        "pats": [
            r"\brequests\.(?:get|post|put|patch|delete|head|request)\((?!.*\btimeout\s*=)",
            r"\bhttp\.(?:Get|Post|PostForm|Head)\(",
        ],
        "post": _balanced_from,
        "msg": "Outbound HTTP call with no timeout: a slow provider can hang your service.",
        "fix": "Always set a connect and read timeout, and wrap external calls with retries with backoff and a circuit breaker.",
    },
]
RULE_BY_ID = {r["id"]: r for r in RULES}
for _r in RULES:
    _r["rx"] = [re.compile(p) for p in _r["pats"]]

# Project-level rule metadata (used for refs and filtering).
PROJECT_RULES = {
    "PROJECT-NO-SECURITY-POLICY": {"nis2": "21(2)(e)"},
    "PROJECT-NO-INCIDENT-PLAN": {"nis2": "21(2)(b), 23", "gdpr": "33", "dora": "17, 19"},
    "PROJECT-NO-CI": {"nis2": "21(2)(e), 21(2)(f)", "dora": "24, 25"},
    "PROJECT-NO-DEP-SCANNING": {"nis2": "21(2)(d), 21(2)(e)", "dora": "28"},
    "PROJECT-NO-SBOM": {"nis2": "21(2)(d)", "dora": "28"},
    "PROJECT-NO-LOCKFILE": {"nis2": "21(2)(d)", "dora": "28"},
    "PROJECT-UNPINNED-DEPS": {"nis2": "21(2)(d)", "dora": "28"},
    "PROJECT-ENV-NOT-IGNORED": {"nis2": "21(2)(h), 21(2)(i)"},
    "DOCKER-ROOT": {"nis2": "21(2)(i)", "dora": "28"},
    "DOCKER-UNPINNED-IMAGE": {"nis2": "21(2)(d)", "dora": "28"},
    "DOCKER-CURL-PIPE": {"nis2": "21(2)(d)", "dora": "28"},
    "GDPR-NO-ERASURE-PATH": {"gdpr": "5(1)(e), 17"},
    "AIACT-NO-DISCLOSURE": {"ai-act": "50"},
    "AIACT-NO-AI-AUDIT-LOG": {"ai-act": "12"},
    "AIACT-HIGH-RISK-INDICATOR": {"ai-act": "6, 14, Annex III"},
    "DORA-NO-RESILIENCE-LIB": {"dora": "11"},
    "DORA-NO-HEALTHCHECK": {"dora": "11, 24"},
}

MANUAL = {
    "nis2": [
        ("20", "Management bodies approve and oversee the cybersecurity measures and receive training."),
        ("21(2)(a)", "Documented and approved policies on risk analysis and information system security."),
        ("21(2)(b), 23", "Incident handling able to deliver an early warning within 24 h, a notification within 72 h and a final report within one month."),
        ("21(2)(c)", "Tested backups, business continuity and crisis management."),
        ("21(2)(d)", "Assessment of critical suppliers and security clauses in contracts."),
        ("21(2)(f)", "Periodic testing or audits that measure whether the measures work."),
        ("21(2)(g)", "Cyber hygiene practices and staff training."),
        ("21(2)(i)", "Access control, joiner/leaver processes and asset inventory."),
        ("21(2)(j)", "MFA enabled for administration, email and remote access; secured emergency communications."),
    ],
    "gdpr": [
        ("6, 7", "Legal basis for each processing and records of consent where consent is the basis."),
        ("13, 14", "Privacy notice that matches what the code actually collects."),
        ("28", "Data Processing Agreements with cloud, analytics and AI vendors."),
        ("30", "Record of Processing Activities (RoPA)."),
        ("35", "Data Protection Impact Assessment where processing is high risk."),
        ("33, 34", "Breach notification to the supervisory authority within 72 hours (AEPD in Spain) and to data subjects when required."),
        ("44+", "Valid transfer mechanism for any provider outside the EEA."),
    ],
    "ai-act": [
        ("6, Annex III", "Risk classification of the real deployment (prohibited, high-risk, limited or minimal)."),
        ("11, Annex IV", "Technical documentation for high-risk systems."),
        ("14", "Human oversight procedures: who can review, override or stop the system."),
        ("27", "Fundamental Rights Impact Assessment where it applies."),
        ("4", "AI literacy for the staff who build and operate the system."),
        ("50", "Transparency texts reviewed for every channel where users meet the AI."),
    ],
    "dora": [
        ("5, 6", "ICT risk management framework approved by the management body."),
        ("11, 12", "Backup, restore and business continuity plans with tested RTO/RPO."),
        ("17, 19", "Major ICT incident classification and reporting workflow (initial, intermediate and final reports)."),
        ("24-27", "Digital operational resilience testing programme, and TLPT where required."),
        ("28, 30", "Register of Information for ICT third-party providers, contract clauses and exit strategies."),
    ],
}
SCOPE_NOTE = ("Line-based rules read one line at a time, so calls split over several lines "
              "can be missed. Review authentication, authorization and data flows by hand.")


def disclaimer(fws: list[str]) -> str:
    names = ", ".join(FW_LABEL[f] for f in fws)
    return (f"This tool looks for technical signals and does not certify compliance with {names}. "
            "A clean report does not mean you comply: organizational, legal and governance "
            "measures are out of its reach. Consult a legal and cybersecurity professional.")


def finding(rid: str, sev: str, refs: dict, msg: str, fix: str, fws: list[str],
            file: str | None, line: int | None, detail: str = "") -> dict:
    sel = {k: v for k, v in refs.items() if k in fws}
    return {
        "rule": rid, "sev": sev, "art": refs.get("nis2", "") if "nis2" in fws else "",
        "refs": sel, "file": file, "line": line, "msg": msg, "fix": fix, "detail": detail,
    }


def active(refs: dict, fws: list[str]) -> bool:
    return any(k in fws for k in refs)


def collect(root: Path, excludes: list[str]) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            rel = (Path(dirpath) / name).relative_to(root)
            posix = rel.as_posix()
            if any(fnmatch.fnmatch(posix, e) for e in excludes):
                continue
            files.append(rel)
    return files


def read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:1024]:
        return None
    return data.decode("utf-8", errors="ignore")


def scannable(rel: Path) -> bool:
    low = rel.name.lower()
    if low in SKIP_FILES or ".min." in low:
        return False
    if any(m in low for m in (".example", ".sample", ".template")):
        return False
    return rel.suffix.lower() in SCAN_EXT or low.startswith(".env") or low.startswith("dockerfile")


def readable(rel: Path) -> bool:
    """Files that feed the project-wide checks (scannable files plus extra extensions)."""
    if scannable(rel):
        return True
    low = rel.name.lower()
    return rel.suffix.lower() in EXTRA_EXT and low not in SKIP_FILES and ".min." not in low


def scan_file(rel: Path, text: str, fws: list[str], is_ai_file: bool) -> list[dict]:
    suffix = rel.suffix.lower()
    base = scannable(rel)
    is_code = suffix in CODE_EXT
    is_env = rel.name.lower().startswith(".env")
    posix = rel.as_posix()
    rules = []
    for rule in RULES:
        if not active(rule["refs"], fws):
            continue
        if rule.get("fw_only") and rule["fw_only"] not in fws:
            continue
        if rule.get("ai_file") and not is_ai_file:
            continue
        if rule.get("path_glob") and not fnmatch.fnmatch(posix, rule["path_glob"]):
            continue
        exts = rule.get("exts")
        if exts:
            if not (suffix in exts or (rule.get("code_too") and is_code)):
                continue
        elif not base:
            continue
        elif rule.get("code_only") and not is_code:
            continue
        rules.append(rule)
    out: list[dict] = []
    if not rules and not is_env:
        return out
    for n, line in enumerate(text.splitlines(), 1):
        if "nis2-ignore" in line or len(line) > 2000:
            continue
        for rule in rules:
            for rx in rule["rx"]:
                m = rx.search(line)
                if not m:
                    continue
                if rule.get("placeholder_check") and PLACEHOLDER.search(m.group(0)):
                    continue
                if rule.get("post") and not rule["post"](m):
                    continue
                detail = rule["detail"](m) if rule.get("detail") else ""
                out.append(finding(rule["id"], rule["sev"], rule["refs"], rule["msg"],
                                   rule["fix"], fws, posix, n, detail))
                break
        if is_env and active(RULE_BY_ID["SECRET-HARDCODED"]["refs"], fws):
            m = ENV_SECRET.search(line)
            if m and not PLACEHOLDER.search(m.group(0)):
                r = RULE_BY_ID["SECRET-HARDCODED"]
                out.append(finding(r["id"], r["sev"], r["refs"], r["msg"], r["fix"], fws, posix, n))
    return out


def project_checks(root: Path, files: list[Path], texts: dict[str, str], ai_files: set[str],
                   uses_ai: bool, fws: list[str]) -> list[dict]:
    out: list[dict] = []
    posix = {f.as_posix().lower() for f in files}
    names = {f.name.lower() for f in files}
    corpus = "\n".join(texts.values())

    def add(rid, sev, msg, fix, file=None, detail=""):
        refs = PROJECT_RULES[rid]
        if active(refs, fws):
            out.append(finding(rid, sev, refs, msg, fix, fws, file, None, detail))

    # ---- NIS2 / shared ----
    if "security.md" not in names:
        add("PROJECT-NO-SECURITY-POLICY", "medium",
            "No vulnerability disclosure policy (SECURITY.md).",
            "Add a SECURITY.md with a contact and a response time. A template is in templates/.")

    if not any("incident" in p for p in posix):
        add("PROJECT-NO-INCIDENT-PLAN", "medium",
            "No incident response document found.",
            "Document who decides, how incidents are detected and how they are reported (NIS2 24 h / 72 h / 1 month, GDPR 72 h, DORA major-incident reports). A template is in templates/.")

    ci_files = [
        f for f in files
        if (f.as_posix().lower().startswith(".github/workflows/") and f.suffix.lower() in (".yml", ".yaml"))
        or f.name.lower() in (".gitlab-ci.yml", "jenkinsfile", "azure-pipelines.yml", "bitbucket-pipelines.yml")
    ]
    ci_text = " ".join((read_text(root / f) or "").lower() for f in ci_files)
    if not ci_files:
        add("PROJECT-NO-CI", "low",
            "No continuous integration, so there are no automatic checks.",
            "Add a pipeline that runs tests and this scanner on every change.")
    tools = ("codeql", "trivy", "pip-audit", "npm audit", "semgrep", "gitleaks",
             "snyk", "bandit", "grype", "osv-scanner", "dependency-review", "trufflehog")
    bots = {"renovate.json", ".renovaterc", ".renovaterc.json", "dependabot.yml", "dependabot.yaml"}
    if not (bots & names) and not any(t in ci_text for t in tools):
        add("PROJECT-NO-DEP-SCANNING", "medium",
            "No automatic dependency or secret scanning detected.",
            "Enable Dependabot or Renovate and add a scanner (CodeQL, Trivy, pip-audit, gitleaks...).")

    manifests = ("package.json", "requirements.txt", "go.mod", "pom.xml", "cargo.toml", "pyproject.toml")
    if names & set(manifests) and "sbom" not in " ".join(posix) and "cyclonedx" not in ci_text and "syft" not in ci_text:
        add("PROJECT-NO-SBOM", "low",
            "No software bill of materials (SBOM) is generated.",
            "Generate an SBOM (CycloneDX or SPDX) in the pipeline; it helps you respond quickly when a vulnerability is published.")

    lockfiles = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb")
    for f in files:
        low = f.name.lower()
        if low == "package.json" and not any((f.parent / lk).as_posix().lower() in posix for lk in lockfiles):
            add("PROJECT-NO-LOCKFILE", "medium",
                "package.json without a lockfile.",
                "Commit the lockfile and use npm ci in the pipeline.", f.as_posix())
        if re.fullmatch(r"requirements.*\.txt", low):
            lines = [l.strip() for l in (read_text(root / f) or "").splitlines()]
            loose = [l for l in lines if l and not l.startswith(("#", "-")) and "==" not in l and " @ " not in l and "git+" not in l]
            if loose:
                add("PROJECT-UNPINNED-DEPS", "low",
                    "Python dependencies without pinned versions.",
                    "Pin exact versions (ideally with hashes) or use a lockfile (uv, poetry, pip-tools).",
                    f.as_posix(), f"{len(loose)} unpinned")

    gitignore = (read_text(root / ".gitignore") or "").splitlines() if (root / ".gitignore").exists() else []
    ignored = any(l.strip() in (".env", ".env*", "*.env", "/.env") for l in gitignore)
    for f in files:
        if f.name == ".env" and not ignored:
            add("PROJECT-ENV-NOT-IGNORED", "high",
                "A .env file exists and is not listed in .gitignore: it can easily end up in the repository.",
                "Add .env to .gitignore, purge it from history if it was already committed and rotate any secrets it held.",
                f.as_posix())

    for f in files:
        if not (f.name.lower().startswith("dockerfile") or f.suffix.lower() == ".dockerfile"):
            continue
        text = read_text(root / f) or ""
        users = [m.group(1) for m in re.finditer(r"(?im)^\s*USER\s+(\S+)", text)]
        if not any(u.lower() not in ("root", "0") for u in users):
            add("DOCKER-ROOT", "medium",
                "The container runs as root.",
                "Create an unprivileged user and add USER before CMD.", f.as_posix())
        stages: set[str] = set()
        for m in re.finditer(r"(?im)^\s*FROM\s+(\S+)(?:\s+AS\s+(\S+))?", text):
            image, alias = m.group(1), m.group(2)
            floating = image.endswith(":latest") or (
                ":" not in image and "@" not in image and "$" not in image
                and image.lower() != "scratch" and image not in stages)
            if floating:
                add("DOCKER-UNPINNED-IMAGE", "low",
                    "Base image without a pinned version (latest or no tag).",
                    "Pin a specific tag or, better, a sha256 digest.", f.as_posix(), image)
            if alias:
                stages.add(alias)
        if re.search(r"(?i)(?:curl|wget)[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh", text):
            add("DOCKER-CURL-PIPE", "medium",
                "A remote script is downloaded and executed without verification.",
                "Download to a file, check its hash or signature, then run it.", f.as_posix())

    # ---- GDPR ----
    if "gdpr" in fws:
        table_rx = re.compile(
            r"(?im)create\s+table\s+(?:if\s+not\s+exists\s+)?[`\"\[]?(?:\w+\.)?[`\"]?"
            r"(users?|customers?|profiles?|clientes?|usuarios?)\b"
            r"|^\s*model\s+(User|Customer|Profile|Cliente|Usuario)\s*\{"
            r"|__tablename__\s*=\s*['\"](users?|customers?|profiles?|clientes?|usuarios?)['\"]"
            r"|^\s*class\s+(User|Customer|Profile|Cliente|Usuario)\s*\([^)]*(?:Model|Base)\b"
        )
        cascade_rx = re.compile(
            r"(?i)on\s+delete\s+(?:cascade|set\s+null)|on_delete\s*=\s*models\.(?:CASCADE|SET_NULL)"
            r"|ondelete\s*=\s*['\"](?:CASCADE|SET NULL)|onDelete\s*:\s*(?:Cascade|SetNull)"
            r"|cascade\s*=\s*['\"][^'\"]*delete"
        )
        erase_rx = re.compile(
            r"(?i)anonymi[sz]|\berase|purge|retention|delete_?user|delete_?account|"
            r"remove_?user|gdpr_?delete|right_to_be_forgotten|derecho_al_olvido|supresi[oó]n"
        )
        table_file = None
        for rel, text in texts.items():
            if Path(rel).suffix.lower() in (".sql", ".prisma", ".py", ".ts", ".js") and table_rx.search(text):
                table_file = rel
                break
        if table_file and not cascade_rx.search(corpus) and not erase_rx.search(corpus):
            add("GDPR-NO-ERASURE-PATH", "medium",
                "User/customer data is stored but there is no cascading delete and no deletion, anonymization or retention code.",
                "Implement account deletion (cascading deletes or explicit cleanup of every table that references the user) and a scheduled job that anonymizes or purges data past its retention period.",
                table_file)

    # ---- AI Act ----
    if "ai-act" in fws and uses_ai:
        disclosure_rx = re.compile(
            r"(?i)ai[-_ ]generated|generated (?:by|with) (?:an? )?ai\b|generad[oa] (?:por|con) (?:ia|inteligencia artificial)"
            r"|asistente (?:virtual )?(?:de|con) ia|chatting with an ai|talking to an ai|interacting with an ai"
            r"|hablando con una ia|ai[-_]disclosure|x-ai-generated|ai_disclosure|contenido sint[eé]tico"
        )
        if not disclosure_rx.search(corpus):
            add("AIACT-NO-DISCLOSURE", "medium",
                "The project uses an AI model but nothing tells users they are interacting with an AI or seeing AI-generated content.",
                "Show a clear notice in the UI (and a flag or header in the API, e.g. ai_generated: true) wherever users talk to the AI or receive generated content.")
        audit_rx = re.compile(r"(?i)model_version|prompt_hash|input_hash|output_hash|ai_audit|llm_audit|ai_event")
        if not audit_rx.search(corpus):
            add("AIACT-NO-AI-AUDIT-LOG", "medium",
                "No structured record of AI calls (model version, input hash, tool calls, output) was found.",
                "Log every AI call as a structured event: timestamp, model id/version, hash of the input, tools executed and final output or its hash, without raw personal data.")
        risk_rx = re.compile(
            r"(?i)\b(?:\w+_)?(?:candidate|hiring|recruit|cv_score|resume_score|credit_?score|creditworth|"
            r"loan_approv|triage|diagnos|exam_grade|grading|admission|insurance_premium)\w*\b")
        human_rx = re.compile(
            r"(?i)human_review|requires?_approval|manual_review|approve[ds]?_by|human_in_the_loop|"
            r"\bhitl\b|override|pending_review|revisi[oó]n_humana")
        if not human_rx.search(corpus):
            for rel in sorted(ai_files):
                m = risk_rx.search(texts.get(rel, ""))
                if m:
                    add("AIACT-HIGH-RISK-INDICATOR", "medium",
                        "AI is used around a domain the AI Act lists as potentially high-risk (employment, credit, health, education...) and no human approval or override hook was found.",
                        "Classify the system properly. If it is high-risk, add a human approval step before final decisions, an override mechanism and confidence thresholds.",
                        rel, m.group(0))

    # ---- DORA ----
    if "dora" in fws:
        manifest_text = "\n".join(t for r, t in texts.items() if Path(r).name.lower() in MANIFESTS
                                  or re.fullmatch(r"requirements.*\.txt", Path(r).name.lower()))
        for f in files:
            low = f.name.lower()
            if (low in MANIFESTS or re.fullmatch(r"requirements.*\.txt", low)) and f.as_posix() not in texts:
                manifest_text += "\n" + (read_text(root / f) or "")
        import_text = "\n".join(l for t in texts.values() for l in t.splitlines()
                                if re.match(r"\s*(?:import|from|require|const .*require)\b", l))
        deps = manifest_text + "\n" + import_text
        pay = re.search(r"(?i)\b(stripe|adyen|redsys|paypal|plaid|braintree|gocardless|mangopay)\b", deps)
        resilience = re.compile(
            r"(?i)\btenacity\b|\bbackoff\b|\bretrying\b|urllib3.*Retry|\bRetry\(|pybreaker|circuitbreaker|"
            r"circuit_breaker|resilience4j|\bpolly\b|opossum|cockatiel|p-retry|async-retry|axios-retry|"
            r"retry-axios|failsafe|max_network_retries|maxNetworkRetries")
        if pay and not resilience.search(corpus + manifest_text):
            add("DORA-NO-RESILIENCE-LIB", "low",
                "A payment or banking provider is integrated and no retry, backoff or circuit-breaker was found.",
                "Wrap provider calls with timeouts, retries with exponential backoff and idempotency keys, plus a circuit breaker and a degraded mode.",
                None, pay.group(1).lower())
        web = re.search(r"(?i)\b(flask|fastapi|django|express|@nestjs/core|spring-boot|gin-gonic|koa|hapi|starlette)\b", deps)
        health_rx = re.compile(r"(?i)['\"/](?:health|healthz|healthcheck|ready|readyz|readiness|livez|liveness)\b|actuator|^\s*HEALTHCHECK\b", re.M)
        docker_text = "\n".join(read_text(root / f) or "" for f in files if f.name.lower().startswith("dockerfile"))
        if web and not health_rx.search(corpus + "\n" + docker_text):
            add("DORA-NO-HEALTHCHECK", "low",
                "A web service was detected with no health or readiness endpoint.",
                "Expose /health (liveness) and /ready (readiness, checking database and critical providers) and use them in your orchestrator and monitoring.",
                None, web.group(1).lower())
    return out


def scan(root: Path, excludes: list[str] | None = None,
         frameworks: list[str] | None = None) -> tuple[list[dict], int]:
    fws = [f for f in FRAMEWORKS if f in (frameworks or ["nis2"])]
    root = root.resolve()
    files = collect(root, excludes or [])
    texts: dict[str, str] = {}
    for rel in files:
        if readable(rel):
            t = read_text(root / rel)
            if t is not None:
                texts[rel.as_posix()] = t
    ai_files = {r for r, t in texts.items() if Path(r).suffix.lower() in CODE_EXT and AI_IMPORT.search(t)}
    uses_ai = bool(ai_files) or any(
        AI_MANIFEST.search(t) for r, t in texts.items()
        if Path(r).name.lower() in MANIFESTS or re.fullmatch(r"requirements.*\.txt", Path(r).name.lower()))
    if not uses_ai:
        for f in files:
            low = f.name.lower()
            if re.fullmatch(r"requirements.*\.txt", low) or low in MANIFESTS:
                if AI_MANIFEST.search(read_text(root / f) or ""):
                    uses_ai = True
                    break
    findings: list[dict] = []
    scanned = 0
    for rel in files:
        key = rel.as_posix()
        if key not in texts:
            continue
        if scannable(rel):
            scanned += 1
        findings.extend(scan_file(rel, texts[key], fws, key in ai_files))
    findings.extend(project_checks(root, files, texts, ai_files, uses_ai, fws))
    consent_rx = re.compile(r"(?i)consent|cookiebot|onetrust|klaro|cookieconsent|\bcmp\b|tarteaucitron|iubenda|usercentrics")
    if any(consent_rx.search(t) for t in texts.values()):
        findings = [f for f in findings if f["rule"] != "GDPR-TRACKER-NO-CONSENT"]
    seen, unique = set(), []
    for f in findings:
        k = (f["rule"], f["file"], f["line"], f["detail"])
        if k not in seen:
            seen.add(k)
            unique.append(f)
    return unique, scanned


def summary(findings: list[dict]) -> dict:
    return {s: sum(1 for f in findings if f["sev"] == s) for s in ("high", "medium", "low")}


def refs_text(refs: dict) -> str:
    return " · ".join(f"{FW_LABEL[k]} Art. {refs[k]}" for k in FRAMEWORKS if k in refs)


def render_md(root: Path, findings: list[dict], scanned: int, frameworks: list[str] | None = None) -> str:
    fws = [f for f in FRAMEWORKS if f in (frameworks or ["nis2"])]
    s = summary(findings)
    lines = [
        "# nis2-guard report", "",
        f"Scanned path: `{root}`  ",
        f"Frameworks: {', '.join(FW_LABEL[f] for f in fws)}  ",
        f"Files reviewed: {scanned}  ",
        f"Findings: {s['high']} high, {s['medium']} medium, {s['low']} low", "",
        f"> {disclaimer(fws)}", "", "## Technical findings", "",
    ]
    if not findings:
        lines += ["The scanner found no technical signals. Still review the items in the next section.", ""]
    grouped: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        grouped[f["rule"]].append(f)
    for g in sorted(grouped.values(), key=lambda g: (-SEV_ORDER[g[0]["sev"]], g[0]["rule"])):
        h = g[0]
        lines += [f"### [{LABEL[h['sev']]}] {h['rule']} ({refs_text(h['refs'])})", "", h["msg"], "",
                  f"**What to change:** {h['fix']}", "", "Where:"]
        for f in g[:10]:
            loc = f["file"] or "(project)"
            if f["line"]:
                loc += f":{f['line']}"
            extra = f" ({f['detail']})" if f["detail"] else ""
            lines.append(f"- `{loc}`{extra}")
        if len(g) > 10:
            lines.append(f"- and {len(g) - 10} more")
        lines.append("")
    lines += ["## What a scanner cannot check", "", SCOPE_NOTE, ""]
    for fw in fws:
        lines += [f"### {FW_LABEL[fw]}", ""]
        lines += [f"- Art. {art}: {txt}" for art, txt in MANUAL[fw]]
        lines.append("")
    return "\n".join(lines)


def parse_frameworks(values: list[str]) -> list[str]:
    if not values:
        return ["nis2"]
    out: set[str] = set()
    for v in values:
        for part in v.split(","):
            part = part.strip().lower()
            if part == "all":
                out.update(FRAMEWORKS)
            elif part in FRAMEWORKS:
                out.add(part)
            elif part:
                raise SystemExit(f"Unknown framework: {part}. Use nis2, gdpr, ai-act, dora or all.")
    return [f for f in FRAMEWORKS if f in out]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Technical helper scanner for NIS2, GDPR, the AI Act and DORA.")
    ap.add_argument("path", help="Project folder")
    ap.add_argument("--framework", action="append", default=[],
                    help="nis2 (default), gdpr, ai-act, dora or all. Repeatable or comma-separated.")
    ap.add_argument("--format", choices=("md", "json"), default="md")
    ap.add_argument("--output", help="Output file (default: print to screen)")
    ap.add_argument("--fail-on", choices=("high", "medium", "low", "none"), default="none",
                    help="Exit with code 1 if there are findings of this severity or higher")
    ap.add_argument("--exclude", action="append", default=[], help="Glob pattern to ignore (repeatable)")
    args = ap.parse_args(argv)

    root = Path(args.path)
    if not root.is_dir():
        print(f"Folder not found: {root}", file=sys.stderr)
        return 2
    fws = parse_frameworks(args.framework)
    findings, scanned = scan(root, args.exclude, fws)
    if args.format == "json":
        body = json.dumps({
            "root": str(root.resolve()), "frameworks": fws, "files_scanned": scanned,
            "summary": summary(findings), "findings": findings,
            "manual_review": [{"framework": fw, "article": a, "item": t}
                              for fw in fws for a, t in MANUAL[fw]],
            "disclaimer": disclaimer(fws),
        }, ensure_ascii=False, indent=2)
    else:
        body = render_md(root.resolve(), findings, scanned, fws)
    if args.output:
        Path(args.output).write_text(body, encoding="utf-8")
    else:
        print(body)
    if args.fail_on != "none":
        limit = SEV_ORDER[args.fail_on]
        if any(SEV_ORDER[f["sev"]] >= limit for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
