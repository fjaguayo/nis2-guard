---
name: nis2-guard
description: Reviews code and repositories against the technical cybersecurity measures of the NIS2 Directive (EU 2022/2555, Articles 21 and 23), finds what fails, proposes what to change, and helps write new code that is secure by default. Use this whenever the user mentions NIS2, the EU cybersecurity directive or a national cybersecurity law, security compliance, "passing NIS2", auditing or reviewing the security of a repository, essential or important entities, 24/72-hour incident notification, or software supply chain security, even if they do not ask for a skill explicitly.
---

# nis2-guard

Helps align code and repositories with the technical side of NIS2. It covers reviewing
existing code, the rules to follow for code written from now on, and the supporting
documents that tend to be missing.

## Scope and honesty

NIS2 is not a test that code passes or fails. It is a risk-management directive with
organizational, governance and reporting obligations. Code only provides evidence for
part of Article 21(2) (mostly points e, h, i and d). Therefore:

- Never say "complies with NIS2" or "passes NIS2". Say "no technical signals detected"
  or "aligned with Art. 21(2)(h) as far as it can be checked from the repo".
- Always show the list of what cannot be verified from a repository.
- Remind the user that this is neither legal advice nor a certification.
- The transposition status differs by country and changes often. If the user asks about
  deadlines, penalties or whether it is already mandatory, search for current
  information instead of answering from memory.

## Mode 1: audit existing code

1. Run the scanner on the project folder:
   `python scripts/nis2_scan.py <path> --format md`
   Use `--format json` if you will process the output, and `--exclude "tests/*"` to
   leave test files out.
2. Read the report and spot-check the high-severity findings before accepting them:
   the scanner is pattern-based and can be wrong.
3. Explain each finding in plain language: what is happening, why it matters and which
   article it relates to. Order by severity.
4. Fill in what the scanner cannot see: read the authentication, session management and
   data handling code, and note problems that patterns miss.

## Mode 2: write new code

While generating code for a project subject to NIS2, follow these rules without the
user having to ask:

- Secrets only from environment variables or a secrets manager. Never in code.
- TLS always verified. No `verify=False` or equivalents.
- Modern cryptography: AES-GCM or ChaCha20-Poly1305, SHA-256 or stronger, argon2id,
  scrypt or bcrypt for passwords.
- Parameterized queries. No `eval`, no `shell=True`, no unsafe deserialization.
- Input validation, and errors that do not leak stack traces to the client.
- Structured logs with security events (login, permission changes, authorization
  failures) and without sensitive data. Without those events an incident cannot be
  detected in time for the 24-hour early warning.
- Least privilege, CORS with explicit origins, debug mode off by default.
- Hooks for MFA on administration routes.
- Pinned dependencies with a lockfile. Docker images with a specific tag and an
  unprivileged user.

After generating a sizeable change, run the scanner again on those files to confirm
that it introduces no new findings.

## Mode 3: remediation plan

When there are findings, propose a plan in this order: exposed secrets (rotate first,
fix after), TLS and cryptography, injection and unsafe execution, supply chain, and
finally documentation. For each item deliver the concrete change. If the user agrees,
apply it, run the scanner again and share the before and after.

## Mode 4: extras

- Vulnerability disclosure policy template: `templates/SECURITY.md`.
- Incident response plan template with the Article 23 deadlines:
  `templates/incident-response-plan.md`.
- GitHub Actions workflow that runs the scanner on every change: `.github/workflows/nis2-scan.yml`
  in the project's repository.
- Summary for management: one paragraph with risks, estimated effort and owners.
  Article 20 places oversight with management bodies, so they need to be able to
  understand it without reading code.
- Detailed mapping from articles to repository evidence: `references/nis2-art21-mapping.md`.
  Read it when the user asks to justify a finding or prepare for an audit.

## Response format

Start with the summary (how many findings and of what severity), continue with the most
important ones and close with what falls outside the tool's scope. If the scanner finds
nothing, say so without drama and remind the user of the manual checks.
