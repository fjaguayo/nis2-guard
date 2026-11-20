# GDPR: technical controls and repository evidence

Regulation (EU) 2016/679. Focus: Art. 25 (data protection by design and by default) and
Art. 32 (security of processing). Code alone does not certify GDPR compliance: legal
bases, consent records, DPAs and privacy notices need organizational action. Phrase
results as "aligned with GDPR Art. 25/32 technical safeguards as far as code can verify".

| Art. | Principle / duty | What to look for in code | Scanner rules |
|------|------------------|--------------------------|---------------|
| 5(1)(c) | Data minimization | Schemas, forms and payloads collecting fields with no clear purpose | None (manual) |
| 5(1)(e), 17 | Storage limitation, right to erasure | Cascading deletes or explicit cleanup for tables referencing users; retention/anonymization jobs | GDPR-NO-ERASURE-PATH |
| 5(1)(f), 32 | Integrity and confidentiality | No PII in logs or error trackers; masking by default | GDPR-PII-IN-LOGS, LOG-SENSITIVE |
| 6, 7 | Lawfulness, consent | Trackers and analytics loaded only after consent | GDPR-TRACKER-NO-CONSENT |
| 9, 32 | Special categories, encryption | Encryption at rest for IDs, IBAN/cards, health data | GDPR-SENSITIVE-PLAINTEXT-COLUMN |
| 25 | By design and by default | Privacy-friendly defaults, pseudonymous identifiers, opt-in | None (manual) |
| 28, 44+ | Processors, international transfers | No raw PII sent to external analytics, pixels or AI APIs without pseudonymization, DPA and transfer mechanism | GDPR-PII-TO-LLM |
| 32 | Security of processing | TLS, strong password hashing (argon2id/bcrypt), secrets out of code, no injection | GDPR-PASSWORD-FAST-HASH, SECRET-HARDCODED, TLS-VERIFY-OFF, CRYPTO-*, INJECTION-SQL, AUTH-JWT-UNSAFE |
| 33, 34 | Breach notification | Incident plan with the 72-hour notification to the supervisory authority | PROJECT-NO-INCIDENT-PLAN |

## Secure patterns to propose

- **Logs:** log `user_id` (internal, pseudonymous) instead of email or name; a logging
  filter that masks emails, IPs and ID numbers; scrub PII in Sentry `before_send`.
- **Passwords:** argon2id (argon2-cffi) or bcrypt; never a plain SHA-256 or MD5.
- **Sensitive columns:** application-level AES-GCM with keys in a KMS, or the database's
  encryption features; restrict access by role.
- **Erasure:** `ON DELETE CASCADE` / `SET NULL` on foreign keys to users, an account
  deletion endpoint, and a scheduled job that anonymizes or purges data past retention.
- **Third parties:** consent-gated loading of trackers; pseudonymize before sending data
  to analytics or AI providers; keep the list of processors up to date.

## Outside the code

- Legal basis per processing and consent records.
- Record of Processing Activities (Art. 30).
- Data Processing Agreements with cloud, analytics and AI vendors (Art. 28).
- DPIA when processing is likely to be high risk (Art. 35).
- Privacy notice (Art. 13, 14) and cookie/consent banner (ePrivacy).
- Breach notification within 72 hours to the supervisory authority (Art. 33; AEPD in Spain) and to data subjects when required (Art. 34).
