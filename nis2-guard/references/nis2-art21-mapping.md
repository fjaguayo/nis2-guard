# Mapping Article 21(2) of NIS2 to repository evidence

Quick reference: what code or a repository can show for each measure, and which scanner
rules touch it. Directive (EU) 2022/2555.

| Art. | Measure | Possible evidence in the repo | Scanner rules |
|------|---------|-------------------------------|---------------|
| 21(2)(a) | Risk analysis and security policies | Policy and risk documents | None (manual) |
| 21(2)(b) | Incident handling | Response plan, security logs, alerts | PROJECT-NO-INCIDENT-PLAN |
| 21(2)(c) | Business continuity, backups, crisis management | Backup and restore scripts and documentation | None (manual) |
| 21(2)(d) | Supply chain security | Lockfiles, pinned versions, SBOM, dependency scanning | PROJECT-NO-LOCKFILE, PROJECT-UNPINNED-DEPS, PROJECT-NO-DEP-SCANNING, PROJECT-NO-SBOM, DOCKER-UNPINNED-IMAGE, DOCKER-CURL-PIPE |
| 21(2)(e) | Security in acquisition, development and maintenance; vulnerability handling and disclosure | SECURITY.md, CI with scanning, code review | INJECTION-SQL, EXEC-DANGEROUS, DEBUG-ENABLED, CORS-WILDCARD, PROJECT-NO-SECURITY-POLICY, PROJECT-NO-CI |
| 21(2)(f) | Assessing the effectiveness of measures | Periodic tests, audit reports | PROJECT-NO-CI (partial) |
| 21(2)(g) | Cyber hygiene and training | Training records | None (manual) |
| 21(2)(h) | Cryptography and encryption | Use of TLS, algorithms and key management | TLS-VERIFY-OFF, CRYPTO-WEAK-CIPHER, CRYPTO-WEAK-HASH, HTTP-PLAINTEXT, SECRET-HARDCODED |
| 21(2)(i) | HR security, access control, asset management | Roles, least privilege, non-root containers, logs without sensitive data | DOCKER-ROOT, LOG-SENSITIVE, AUTH-JWT-UNSAFE, PROJECT-ENV-NOT-IGNORED |
| 21(2)(j) | MFA and secure communications | MFA configuration in identity providers | AUTH-JWT-UNSAFE (partial) |

## Article 23: reporting significant incidents

- Early warning: without undue delay and in any event within 24 hours of becoming aware.
- Incident notification: within 72 hours, with an initial assessment.
- Final report: no later than one month after the notification.

Meeting those deadlines requires fast detection, so security event logs and a named
responsible person with a phone number are part of the technical work.

## Article 20: management accountability

Management bodies approve the risk-management measures, oversee their implementation and
can be held liable for infringements. A technical report that never reaches that table
does not cover this part.

## Penalties (directive framework)

For essential entities the maximum is at least 10 million euros or 2% of worldwide annual
turnover. For important entities, at least 7 million euros or 1.4%. Each Member State
sets the details in its transposition law.

## What this tool does not cover

Classification of the entity (essential, important or out of scope), registration with
the competent authority, supplier contracts, training, real continuity capability and any
additional sector obligations (DORA, CRA, ENS in Spain).
