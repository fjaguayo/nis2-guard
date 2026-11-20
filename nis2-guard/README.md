# nis2-guard

A Claude skill, plus a dependency-free scanner that also works on its own, that reviews
code and repositories against the technical side of four EU frameworks:

| Framework | Regulation | Focus in code |
|-----------|------------|---------------|
| **NIS2** | Directive (EU) 2022/2555, Art. 21 and 23 | Secrets, TLS, crypto, injection, supply chain, incident readiness |
| **GDPR** | Regulation (EU) 2016/679, Art. 5, 17, 25, 32, 44+ | PII in logs, password hashing, sensitive columns, erasure, trackers, PII sent to AI APIs |
| **AI Act** | Regulation (EU) 2024/1689, Art. 12, 14, 15, 50 | AI disclosure, AI audit logs, prompt injection, unvalidated LLM output, high-risk indicators |
| **DORA** | Regulation (EU) 2022/2554, Art. 9, 11, 24–28 | Timeouts and resilience on external calls, legacy TLS, health checks, pinned CI actions |

It catches the obvious problems, explains what fails and which article it relates to,
proposes what to change and helps you write new code that starts out more secure.

## What it does and what it does not

None of these regulations is a test that code passes. They are risk-management,
data-protection and governance frameworks with process, documentation and reporting
obligations. This skill covers the part that is visible in a repository and reminds you
in every report of what falls outside it: policies, records of processing, contracts
with suppliers, risk classification, training, continuity and management accountability.

A clean report does not mean you comply. It is not legal advice and it certifies nothing.

## What is included

```
nis2-guard/
├── SKILL.md                    instructions for Claude
├── scripts/nis2_scan.py        multi-framework scanner, Python standard library only
├── references/
│   ├── nis2-art21-mapping.md
│   ├── nis2-organizational-context.md
│   ├── gdpr-mapping.md
│   ├── ai-act-mapping.md
│   └── dora-mapping.md
├── templates/
│   ├── SECURITY.md             vulnerability disclosure policy
│   ├── incident-response-plan.md   NIS2 / GDPR / DORA deadlines
│   ├── nis2-scan.yml           GitHub Actions workflow (actions pinned to SHAs)
│   └── CLAUDE.md               proactive mode for Claude Code
├── tests/test_scanner.py
├── README.md
└── LICENSE
```

## Using it with Claude

1. Install the skill (from Agensi, or upload the `nis2-guard/` folder in the skills
   section of Claude's settings).
2. Ask something like "review this repo for NIS2 and GDPR", "audit our RAG pipeline for
   the AI Act" or "write this payment client with DORA in mind".
3. Claude picks the frameworks that apply from what the code does (personal data → GDPR,
   LLMs → AI Act, payments/banking → DORA, NIS2 always), runs the scanner when it has a
   repository, explains each finding and proposes the fixes.

**Proactive mode in Claude Code:** copy `templates/CLAUDE.md` to the root of your project
as `CLAUDE.md`. Claude Code will then apply the skill on every coding, review or
architecture request even if you never mention a regulation.

## Scanning

By default the scanner runs the NIS2 rules only. Use `--framework` to add the others
(repeatable or comma-separated), or `all` to run everything:

```bash
# NIS2 only (default)
python nis2-guard/scripts/nis2_scan.py . --format md

# Full scan: NIS2 + GDPR + AI Act + DORA
python nis2-guard/scripts/nis2_scan.py . --framework all --format md

# Only the frameworks that apply to you
python nis2-guard/scripts/nis2_scan.py . --framework gdpr,ai-act

# JSON for tooling, and fail the build on high findings
python nis2-guard/scripts/nis2_scan.py . --framework all --format json --output report.json
python nis2-guard/scripts/nis2_scan.py . --framework all --fail-on high --exclude "tests/*"
```

Accepted values for `--framework`: `nis2`, `gdpr`, `ai-act`, `dora`, `all`.

How the full scan behaves:

- **Shared rules count once.** A hardcoded secret is one finding, tagged with every
  selected framework it touches (for example `NIS2 Art. 21(2)(h) · GDPR Art. 32 · DORA Art. 9`).
- **Framework-specific rules** only run when their framework is selected. The AI Act
  rules also need the project to use an AI SDK.
- **The manual checklist** at the end of the report has one block per selected framework.
- **JSON output** includes `frameworks` at the root, `refs` per finding (for example
  `{"nis2": "21(2)(h)", "gdpr": "32", "dora": "9"}`), `art` with the NIS2 article (empty
  when NIS2 is not selected) and `manual_review` items tagged by framework.

To silence a single line (a justified false positive), add `nis2-ignore` in a comment on
that line; it works for every framework. The report never prints the value of the
secrets or personal data it detects.

The scanner's own source contains the patterns it looks for, so scanning the skill folder
itself flags it. Exclude it (`--exclude "nis2-guard/*"`) when the skill lives inside the
repository you scan.

## What it checks

### Shared rules (NIS2, with cross-mappings)

| Rule | What it detects | NIS2 | Also maps to |
|------|-----------------|------|--------------|
| SECRET-HARDCODED | Credentials in code or configuration | 21(2)(h), (i) | GDPR 32 · DORA 9 |
| TLS-VERIFY-OFF | Certificate verification disabled | 21(2)(h) | GDPR 32 · DORA 9 |
| CRYPTO-WEAK-CIPHER / WEAK-HASH | ECB, DES, RC4, MD5, SHA-1 | 21(2)(h) | GDPR 32 · DORA 9 |
| INJECTION-SQL | SQL built by concatenation | 21(2)(e) | GDPR 32 |
| EXEC-DANGEROUS | eval, shell=True, pickle, yaml.load | 21(2)(e) | AI Act 15 |
| DEBUG-ENABLED, CORS-WILDCARD | Insecure configuration | 21(2)(e), (i) | GDPR 32 |
| LOG-SENSITIVE | Logs containing passwords or tokens | 21(2)(i) | GDPR 32 · DORA 9 |
| AUTH-JWT-UNSAFE | JWT without signature verification | 21(2)(i), (j) | GDPR 32 · DORA 9 |
| HTTP-PLAINTEXT | Unencrypted HTTP URLs | 21(2)(h) | GDPR 32 |
| DORA-UNPINNED-ACTION | GitHub Actions referenced by tag or branch instead of a commit SHA | 21(2)(d) | DORA 28 |
| PROJECT-NO-INCIDENT-PLAN | No incident response document | 21(2)(b), 23 | GDPR 33 · DORA 17, 19 |
| PROJECT-NO-SBOM / NO-DEP-SCANNING / NO-LOCKFILE / UNPINNED-DEPS | Supply chain gaps | 21(2)(d) | DORA 28 |
| PROJECT-NO-CI | No automatic checks | 21(2)(e), (f) | DORA 24, 25 |
| PROJECT-NO-SECURITY-POLICY, PROJECT-ENV-NOT-IGNORED | Missing SECURITY.md, `.env` not ignored | 21(2)(e), (h), (i) | — |
| DOCKER-* | Container as root, unpinned images, curl piped to sh | 21(2)(d), (i) | DORA 28 |

### GDPR (`--framework gdpr`)

| Rule | Sev. | What it detects | GDPR |
|------|------|-----------------|------|
| GDPR-PASSWORD-FAST-HASH | high | Passwords hashed with a fast hash (MD5, SHA-1, SHA-256, SHA-512) instead of argon2id, scrypt or bcrypt | Art. 32 |
| GDPR-PII-IN-LOGS | medium | Log, print, console or error-tracker calls that include emails, IPs, phone numbers, national IDs (DNI/NIE/NIF/SSN), IBANs, dates of birth, names or addresses | Art. 5(1)(f), 32 |
| GDPR-SENSITIVE-PLAINTEXT-COLUMN | medium | SQL, Prisma, SQLAlchemy or Django columns for national IDs, IBAN/card numbers or health data stored as plain text | Art. 9, 32 |
| GDPR-NO-ERASURE-PATH | medium | A users / customers / profiles table with no cascading delete and no deletion, anonymization or retention code in the project | Art. 5(1)(e), 17 |
| GDPR-PII-TO-LLM | medium | Personal data fields interpolated into prompts sent to an external AI API | Art. 28, 44+ |
| GDPR-TRACKER-NO-CONSENT | low | Analytics or ad pixels (gtag, GTM, Meta pixel, Hotjar, Mixpanel, Segment, Clarity…) with no consent management detected in the project | Art. 6, 7 (+ ePrivacy) |

### AI Act (`--framework ai-act`)

These rules only fire when the project uses an AI SDK (OpenAI, Anthropic, LangChain,
LlamaIndex, Google GenAI, Mistral, Cohere, Ollama, transformers, LiteLLM, Vercel AI SDK),
detected from imports or dependency manifests.

| Rule | Sev. | What it detects | AI Act |
|------|------|-----------------|--------|
| AIACT-LLM-OUTPUT-EXEC | high | Model output passed to eval/exec, a shell or a SQL `execute` | Art. 15 |
| AIACT-PROMPT-INJECTION-RISK | medium | Dynamic data interpolated directly into the system prompt | Art. 15 |
| AIACT-NO-DISCLOSURE | medium | No sign anywhere in the UI, templates or API that users are told they are interacting with an AI or seeing AI-generated content | Art. 50 |
| AIACT-NO-AI-AUDIT-LOG | medium | No structured record of model version, input hash and output for AI calls | Art. 12 |
| AIACT-HIGH-RISK-INDICATOR | medium | AI used around hiring, credit, medical triage, education grading or similar Annex III domains with no human-approval or override hook | Art. 6, 14, Annex III |

The AI Act risk tier depends on how the system is deployed, not on the code.
`AIACT-HIGH-RISK-INDICATOR` is a signal to classify the system properly, not a verdict.

### DORA (`--framework dora`)

| Rule | Sev. | What it detects | DORA |
|------|------|-----------------|------|
| DORA-WEAK-TLS-VERSION | high | SSLv3, TLS 1.0 or TLS 1.1 explicitly allowed (Python, Node, Go, nginx) | Art. 9 |
| DORA-HTTP-NO-TIMEOUT | medium | Outbound HTTP calls with no timeout (Python `requests`, Go default client) | Art. 9, 11 |
| DORA-NO-RESILIENCE-LIB | low | Payment or banking SDK (Stripe, Adyen, Redsys, PayPal, Plaid…) with no retry, backoff or circuit breaker in the project | Art. 11 |
| DORA-NO-HEALTHCHECK | low | Web service with no health or readiness endpoint | Art. 11, 24 |

DORA applies to financial entities and their ICT third-party providers. If you are not
one of them, the DORA rules are still useful resilience hygiene, not a legal duty.

Full article-to-evidence detail lives in `references/`.

## What the scanner cannot check

Every report ends with this list, filtered by the selected frameworks:

- **NIS2:** management approval and training (Art. 20), risk policies, tested backups and
  continuity, supplier assessment, effectiveness testing, staff training, MFA in identity
  providers, and the 24 h / 72 h / 1 month incident reporting flow (Art. 23).
- **GDPR:** legal basis and consent records, Record of Processing Activities (Art. 30),
  DPAs with cloud and AI vendors (Art. 28), DPIA where required (Art. 35), privacy notice
  (Art. 13–14), cookie banner, and 72-hour breach notification to the supervisory
  authority (Art. 33; AEPD in Spain).
- **AI Act:** risk classification of the real deployment, technical documentation
  (Annex IV), human oversight procedures, Fundamental Rights Impact Assessment where
  applicable (Art. 27), AI literacy for staff (Art. 4).
- **DORA:** ICT risk management framework, Register of Information for ICT third-party
  providers, RTO/RPO and recovery testing, TLPT where required, and the major ICT
  incident classification and reporting workflow.

Line-based rules read one line at a time, so calls split over several lines can be missed.

## CI

Copy `templates/nis2-scan.yml` to `.github/workflows/` and adjust the path where you keep
the scanner. It runs a full scan (`--framework all --fail-on high`) on every push and pull
request and uploads the Markdown report as an artifact. The actions are pinned to commit
SHAs, which is exactly what `DORA-UNPINNED-ACTION` asks of you.

## Tests

```bash
cd nis2-guard
python -m unittest discover -s tests -v
```

Requires Python 3.9 or later. Every rule has positive and negative tests.

## Roadmap

- Reports in Spanish and other languages.
- Pre-commit hook.
- SARIF output so GitHub can show findings in the Security tab.
- Rules for Terraform and Kubernetes.
- Management summary generator (NIS2 Art. 20, DORA Art. 5).
- More AI Act checks for RAG ingestion (provenance, PII scrubbing).

## Contributing

Rules are simple patterns added to the `RULES` list in the scanner. Every new rule needs
a framework, the article it relates to, a positive test and a negative test. Open an
issue if you find a false positive.

## Disclaimer

This tool does not certify compliance with NIS2, GDPR, the AI Act or DORA, and does not
replace an audit or legal advice. Transposition status, application dates and guidance
change by country and over time: check the rules in force where you operate.

## License

MIT.
