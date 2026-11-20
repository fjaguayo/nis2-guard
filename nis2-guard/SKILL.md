---
name: nis2-guard
description: Apply proactively whenever the user writes, reviews, refactors or designs code, APIs, auth, logging, databases, data pipelines, LLM/AI integrations, payment or banking integrations, Dockerfiles, CI/CD or architecture, even if no regulation is mentioned. Aligns code with the technical side of four EU frameworks - NIS2 (Directive 2022/2555), GDPR (Regulation 2016/679), the AI Act (Regulation 2024/1689) and DORA (Regulation 2022/2554) - with a bundled multi-framework scanner. Flags flaws with the article they affect, writes secure-by-default code, and lists the organizational obligations code cannot cover. Use also for "NIS2", "RGPD/GDPR", "AI Act", "DORA", security or privacy audits, 24/72-hour incident notification, PII handling, AI transparency or financial resilience.
---

# nis2-guard (EU Compliance & Secure Code Advisor: NIS2 · GDPR · AI Act · DORA)

Helps align code, repositories and technical decisions with four EU frameworks. It acts
proactively on every coding or architecture request: it points out what is wrong and
which article it affects, writes secure-by-default code, and reminds the user of the
obligations that code alone cannot solve.

## Scope and honesty

None of these frameworks is a test that code passes. They are risk-management,
data-protection and governance frameworks with process, documentation and reporting
duties. Code is only evidence for part of them. Therefore:

- **Never** say "this complies with NIS2/GDPR/the AI Act/DORA", "is 100% compliant" or
  "passes". Say "aligned with the technical measures of <framework, articles> as far as
  code can show" or "no technical red flags detected".
- **Always** list what cannot be verified from code (see "Outside the code" below).
- This is neither legal advice nor a certification.
- Legal applicability depends on the real organization and deployment: entity size and
  sector (NIS2), whether personal data is processed (GDPR), how the AI system is used
  (AI Act), whether the user is a financial entity or an ICT provider to one (DORA).
- Transposition status, application dates, guidance and sanctions change by country and
  over time. When the user asks about them, search for current information instead of
  answering from memory.

## Which frameworks apply

Decide from what the code does, and say which ones you are applying:

| Signal in the request or code | Apply |
|-------------------------------|-------|
| Any code, infrastructure, CI/CD or architecture | **NIS2** (security baseline) |
| Personal data: users, customers, emails, IPs, IDs, health, analytics, logs about people | **GDPR** |
| LLMs, agents, RAG, ML models, AI-generated content | **AI Act** |
| Payments, banking, ledgers, trading, insurance, ICT services for financial entities | **DORA** |

The detailed rules for each framework are in `references/`. Read the matching file when
you need to justify a finding, prepare for an audit, or the request goes deep into that
framework:

- `references/nis2-art21-mapping.md`: NIS2 Art. 21 to repository evidence, Art. 20, 23, penalties.
- `references/nis2-organizational-context.md`: entity scope, Spain (INCIBE-CERT / CCN-CERT), management liability.
- `references/gdpr-mapping.md`: GDPR Art. 5, 17, 25, 32, 44+ technical controls.
- `references/ai-act-mapping.md`: AI Act Art. 12, 14, 15, 50 and risk tiers.
- `references/dora-mapping.md`: DORA Art. 9, 11, 17-19, 24-28.

## Proactive behaviour (every interaction)

Whenever the user shares code, asks for code, or discusses architecture:

1. **Audit what the user provided.** If it contains flaws (hardcoded secrets, disabled TLS,
   weak hashing, injection, PII in logs, model output executed, missing timeouts,
   unpinned dependencies...), call them out before or alongside the solution: what is
   wrong, why it matters, and which article of which framework it affects.
2. **Write secure-by-default code** following Mode 2 without waiting to be asked.
3. **Close with "What else is required here"**: 2-4 short bullets with the obligations
   outside the code that apply to this case (backups, DPA with the provider, AI
   disclosure review, incident notification flow, management approval...).

## Mode 1: audit existing code

1. Run the bundled scanner on the project folder, selecting the frameworks that apply:
   `python scripts/nis2_scan.py <path> --framework all --format md`
   - `--framework` accepts `nis2` (default), `gdpr`, `ai-act`, `dora` or `all`; repeatable or comma-separated.
   - `--format json` when you will process the output; `--exclude "tests/*"` to skip test files.
   - `--fail-on high` makes it exit with code 1, for CI.
2. Spot-check high-severity findings before reporting them: the scanner is pattern-based
   and reads one line at a time, so it has false positives and misses calls split over
   several lines.
3. Explain each finding in plain language, ordered by severity: what happens, why it is a
   risk, which article(s) it relates to, and the concrete fix.
4. Fill in what patterns miss: read authentication, sessions, authorization, data flows
   to third parties and AI calls by hand.

## Mode 2: write new code (secure by default)

**Baseline (NIS2 Art. 21, also GDPR Art. 32 and DORA Art. 9):**
- Secrets only from environment variables or a secrets manager. Never in code.
- TLS always verified, TLS 1.2 minimum (1.3 where possible). No `verify=False`,
  `NODE_TLS_REJECT_UNAUTHORIZED=0` or plain HTTP for sensitive traffic.
- AES-256-GCM or ChaCha20-Poly1305 for encryption, SHA-256+ for integrity, argon2id,
  scrypt or bcrypt for passwords. Never MD5, SHA-1, DES, RC4 or ECB.
- Parameterized queries or ORM. No `eval`, `exec`, `shell=True`, `pickle` or `yaml.load`
  without a safe loader.
- Strict input validation; errors that never leak stack traces, paths or DB errors.
- Structured security logs (logins, failed logins, permission changes, authorization
  failures, config changes) without passwords, tokens or personal data. Without them an
  incident cannot be detected in time for the 24-hour early warning.
- Least privilege, CORS with explicit origins, debug off by default, MFA hooks on admin
  and privileged routes.
- Pinned dependencies with a lockfile; Docker images with a specific tag or digest and a
  non-root user; CI actions pinned to commit SHAs.

**GDPR (when personal data is involved):**
- Data minimization (Art. 5(1)(c)): only collect fields with a clear purpose; question
  extra fields in schemas, forms and payloads.
- Never log emails, names, IPs, national IDs, tokens, health or financial data: log a
  pseudonymous id and mask the rest, including in error trackers (Sentry...).
- Encrypt sensitive columns at rest (IDs, IBAN/cards, health data, Art. 9) with keys in a KMS.
- Right to erasure and retention (Art. 5(1)(e), 17): cascading deletes or explicit
  cleanup for every table referencing a user, plus a scheduled anonymization/purge job.
- Trackers, pixels and analytics only after consent. Do not send raw personal data to
  external analytics or AI APIs: pseudonymize first and check DPA and transfers (Art. 28, 44+).

**AI Act (when LLMs, agents or ML are involved):**
- Transparency (Art. 50): tell users they are interacting with an AI and mark generated
  content (UI notice, plus a flag/header such as `ai_generated: true` in the API).
- Audit logging (Art. 12): structured event per AI call with timestamp, model id/version,
  input hash, tools called and output (or its hash), without raw personal data.
- Human oversight (Art. 14): for hiring, credit, medical triage, education, legal or
  financial approvals, add a human-approval step, override and confidence thresholds
  before any final action, and flag the possible high-risk tier.
- Robustness (Art. 15): static system prompts, user input delimited in the user turn,
  output parsed into a strict schema and validated, never executed; rate limits, timeouts
  and fallback when the provider fails.
- Data governance (Art. 10): provenance tracking, validation and PII scrubbing in training
  and RAG ingestion pipelines.

**DORA (when payments, banking or financial ICT are involved):**
- Resilience (Art. 11): timeouts on every external call, retries with exponential backoff
  and idempotency keys, circuit breakers and graceful degradation on payment, banking and
  ledger calls.
- Audit trail (Art. 10, 17): tamper-evident, structured logs for every transaction,
  privilege escalation, key rotation and failed authentication.
- Cryptography (Art. 9): TLS 1.2/1.3, mTLS between financial services, AES-256-GCM or
  ChaCha20-Poly1305, keys and secrets in an HSM/KMS.
- Third parties (Art. 28): pinned dependencies, SBOM in the pipeline, documented fallback
  or exit strategy for each critical cloud/SaaS provider.
- Testing readiness (Art. 24-27): integration tests on critical transaction paths,
  failover tests and `/health` + `/ready` endpoints.

After generating a sizeable change, run the scanner on those files with the matching
`--framework` to confirm it introduces no new findings.

## Mode 3: remediation plan

When there are findings, propose a plan in this order, with the concrete change for each:
1. Exposed secrets (rotate first, then remove from code and history).
2. Broken TLS, legacy protocols and weak cryptography (including password hashing).
3. Injection, unsafe execution and model output executed as code.
4. Personal data exposure (logs, plaintext columns, data sent to third parties or AI).
5. Access control, MFA, security and AI audit logging, human oversight gaps.
6. Resilience (timeouts, retries, health checks) and supply chain (dependencies, containers, CI actions).
7. Missing documentation and transparency texts.

If the user agrees, apply the changes, run the scanner again and show before and after.

## Mode 4: templates and management summary

- `templates/SECURITY.md`: vulnerability disclosure policy.
- `templates/incident-response-plan.md`: incident plan with NIS2, GDPR and DORA deadlines.
- `templates/nis2-scan.yml`: GitHub Actions workflow (actions pinned to SHAs) that runs the full scan on every change; copy it to `.github/workflows/`.
- `templates/CLAUDE.md`: project instructions so Claude Code applies this skill proactively; copy it to the project root.
- **Management summary** (NIS2 Art. 20, DORA Art. 5): one non-technical paragraph with
  business risks, estimated effort and owners, so the management body can exercise its
  oversight without reading code.

## Response format

1. **Summary:** frameworks applied, number of findings by severity, and for the AI Act the
   estimated risk profile (minimal, limited/transparency, or high-risk indicators).
2. **Findings:** file and line, what is exposed or wrong, article(s), and the fix.
3. **Outside the code**, only for the frameworks that apply:
   - NIS2: management approval and training (Art. 20), risk policies, tested backups and
     continuity, supplier assessment, staff training, 24 h / 72 h / 1 month reporting (Art. 23).
   - GDPR: legal basis and consent records, RoPA (Art. 30), DPAs with cloud and AI vendors
     (Art. 28), DPIA where required (Art. 35), privacy notice, cookie banner, 72-hour breach
     notification to the supervisory authority (Art. 33; AEPD in Spain).
   - AI Act: risk classification of the real deployment, technical documentation (Annex IV),
     Fundamental Rights Impact Assessment where applicable (Art. 27), AI literacy (Art. 4).
   - DORA: ICT risk management framework, Register of Information for ICT third-party
     providers, RTO/RPO recovery testing, TLPT where required, major ICT incident reporting.

If the scanner finds nothing, say so without drama and still list the manual checks.
