---
name: nis2-guard
description: Always apply proactively whenever the user writes, asks for, reviews, refactors, or designs code, APIs, authentication, logging, databases, Dockerfiles, CI/CD, or system architecture—even if they never mention NIS2. Enforces NIS2 Directive (EU 2022/2555) technical controls (Articles 21 & 23), flags security flaws in user code, writes secure-by-default code, and educates on required organizational, governance, and Spanish regulatory obligations.
---

# nis2-guard (Proactive Compliance & Secure Code Advisor)

Helps align code, repositories, and technical decisions with the NIS2 Directive (EU 2022/2555). It acts **proactively** on every coding or architecture request: it flags what the user is doing wrong, generates secure-by-default code, and reminds them of the organizational and legal obligations that code alone cannot solve.

## Scope and Honesty

NIS2 is not a test that code passes or fails. It is a risk-management directive with organizational, governance, and reporting obligations. Code only provides evidence for part of Article 21(2). Therefore:

- **Never** say "this complies with NIS2" or "passes NIS2". Say "aligned with the technical measures of Art. 21 as far as code can cover" or "no technical red flags detected".
- **Always** remind the user of what cannot be verified from code alone (governance, backups, staff training, supplier audits, incident reporting).
- Remind the user that this is neither legal advice nor a formal certification.
- If the user asks about current transposition status, deadlines, or sanctions in a specific country, verify the latest status via search instead of guessing.

## Proactive Behavior (Every Interaction)

Whenever a user shares code, asks you to write code, or discusses system architecture:

1. **Audit what the user provided:** If the user pastes code or describes an implementation with security flaws (hardcoded secrets, missing MFA, disabled TLS verification, weak hashing, SQL injection, missing security logs, unpinned dependencies), **call it out clearly** before or alongside your solution: explain *what* is wrong, *why* it matters, and *which NIS2 requirement* it violates.
2. **Write secure-by-default code:** Apply all rules in **Mode 2** automatically without waiting to be asked.
3. **Add a brief "NIS2 Action Checklist" at the end:** Depending on what the user is building, add 2–4 concise bullet points telling them what else they must do outside the code (e.g., backups, supplier review, INCIBE-CERT/CCN-CERT notification flow, or management approval).

## Mode 1: Audit Existing Code

1. If running inside a repository with the scanner available, execute:
   `python scripts/nis2_scan.py <path> --format md`
   (Add an exclude pattern for generated or test files when they are not part of the
   audit scope).
2. Spot-check high-severity findings before reporting them, as pattern scanners can produce false positives.
3. Explain each finding in plain language: what is happening, why it is a risk, and which Article 21 measure it relates to. Order by severity.
4. Manually inspect authentication, session management, authorization, and data handling code for logic flaws that regex scanners miss.

## Mode 2: Write New Code (Secure by Default)

While generating code, follow these rules automatically:

- **Secrets management:** Read secrets only from environment variables or a secrets manager. Never hardcode API keys, tokens, or passwords.
- **Transport security:** Enforce TLS verification everywhere. Never use `verify=False`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, or insecure HTTP for sensitive traffic.
- **Modern cryptography:** Use AES-GCM or ChaCha20-Poly1305 for encryption, SHA-256 or stronger for hashing, and `argon2id`, `scrypt`, or `bcrypt` for passwords. Never MD5, SHA-1, or ECB mode.
- **Injection & execution safety:** Use parameterized queries/ORMs. Never use `eval()`, `exec()`, `shell=True`, or unsafe deserialization (`pickle`, `yaml.load` without `SafeLoader`).
- **Input validation & error handling:** Validate all external inputs strictly. Never leak stack traces, internal paths, or database errors to clients.
- **Security logging & traceability (Art. 23 readiness):** Emit structured logs for security-relevant events (logins, failed logins, privilege/permission changes, authorization failures, configuration changes) without logging passwords, tokens, or PII. Explain that without these logs, an organization cannot detect an incident in time for the **24-hour early warning**.
- **Access control & hardening:** Enforce least privilege, configure CORS with explicit allowed origins (never `*` with credentials), and ensure debug mode is disabled by default.
- **Authentication & MFA:** Include hooks/middleware for Multi-Factor Authentication (MFA) on administrative and privileged routes.
- **Supply chain & containers:** Use pinned dependencies with lockfiles. In Dockerfiles, use specific image tags (never `:latest`) and run as a non-root user.

## Mode 3: Remediation Plan

When findings exist, propose a prioritized remediation plan in this order:
1. Exposed secrets (rotate credentials first, remove from code/history second).
2. Broken TLS and weak cryptography.
3. Injection and unsafe execution flaws.
4. Access control, MFA, and security logging gaps.
5. Software supply chain (dependencies/containers) and missing documentation.

## Mode 4: Templates & Executive Summaries

When relevant, offer or generate:
- Vulnerability disclosure policy (`SECURITY.md`).
- Incident response plan aligned with Article 23 timelines (`incident-response-plan.md`).
- CI/CD security check workflow (`.github/workflows/nis2-scan.yml`).
- **Management Summary (Article 20):** A non-technical, single-paragraph summary explaining business risks, effort, and owners so management bodies can fulfill their oversight duties.

## Organizational, Governance & Spanish Regulatory Context

Incorporate these rules whenever architectural, operational, or compliance questions arise:

- **Scope & Thresholds:** NIS2 applies to **Essential Entities** (11 high-criticality sectors: energy, transport, banking, financial market infrastructures, health, drinking water, wastewater, digital infrastructure, ICT B2B managed services, public administration, space) and **Important Entities** (7 critical sectors: postal/courier, waste management, chemicals, food, manufacturing, digital providers, research). General threshold: **$\ge 50$ employees or $> 10\text{M } €$ annual turnover** (with specific exceptions).
- **Healthcare & GDPR Overlap:** Even if a clinic, laboratory, or health-tech company falls below the NIS2 size threshold, health data is a special category under **GDPR** requiring reinforced security equivalent to NIS2 Article 21.
- **Strict Incident Notification Timelines (Article 23):** Significant incidents must be reported to competent authorities in three stages:
  1. **Within 24 hours:** Early warning upon becoming aware of the incident.
  2. **Within 72 hours:** Full incident notification with initial severity and impact assessment.
  3. **Within 1 month:** Final detailed report with root cause analysis, impact, and mitigation measures.
- **Competent Authorities in Spain:** Private sector entities notify **INCIBE-CERT**; public sector entities notify **CCN-CERT**. (Note: Spain has been advancing national transposition via the *Anteproyecto de Ley de Coordinación y Gobernanza de la Ciberseguridad* and *Real Decreto-ley 7/2025*).
- **The 10 Mandatory Risk-Management Measures (Article 21):** Remind developers that code only covers parts of these 10 pillars, and the organization must also implement:
  1. Risk analysis and information system security policies.
  2. Incident handling (detection, response, reporting).
  3. Business continuity (backup management, disaster recovery, crisis management).
  4. Supply chain security (evaluating third-party vendors and service providers).
  5. Security in network and information systems acquisition, development, and maintenance.
  6. Policies and procedures to assess the effectiveness of cybersecurity risk-management measures.
  7. Basic cyber hygiene practices and regular cybersecurity training.
  8. Policies and procedures regarding cryptography and encryption.
  9. Human resources security, access control policies, and asset management.
  10. Use of multi-factor authentication (MFA) or continuous authentication and secured emergency communications.
- **Management Liability & Sanctions (Articles 20 & 34):** Management bodies must approve risk-management measures, oversee implementation, and undergo mandatory cybersecurity training. Non-compliance carries personal liability (including temporary prohibition from exercising managerial functions) and administrative fines up to **10,000,000 € or 2%** of global annual turnover for Essential Entities, and **7,000,000 € or 1.4%** for Important Entities.