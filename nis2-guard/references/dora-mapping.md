# DORA: digital operational resilience and repository evidence

Regulation (EU) 2022/2554, applicable since 17 January 2025. It applies to financial
entities (banks, payment and e-money institutions, investment firms, crypto-asset
service providers, insurers and others) and brings critical ICT third-party providers
under EU oversight. For the financial sector, DORA prevails over NIS2 on ICT risk.
Code checks cover technical resilience and observability; full compliance needs an ICT
risk management framework, testing programmes and contractual registers.

| Art. | Requirement | What to look for in code | Scanner rules |
|------|-------------|--------------------------|---------------|
| 9 | Protection and prevention, cryptography | TLS 1.2/1.3, mTLS between financial services, AES-256-GCM / ChaCha20-Poly1305, keys in HSM/KMS, no secrets in code | DORA-WEAK-TLS-VERSION, TLS-VERIFY-OFF, SECRET-HARDCODED, CRYPTO-*, LOG-SENSITIVE |
| 10, 17 | Detection, incident management | Tamper-evident, structured logs for transactions, privilege escalation, key rotation, failed auth | None (manual) |
| 11 | Response and recovery | Timeouts, retries with exponential backoff, idempotency keys, circuit breakers, graceful degradation | DORA-HTTP-NO-TIMEOUT, DORA-NO-RESILIENCE-LIB, DORA-NO-HEALTHCHECK |
| 17, 19 | Incident classification and reporting | Incident plan with the major ICT incident reporting workflow | PROJECT-NO-INCIDENT-PLAN |
| 24-27 | Resilience testing | Integration tests on critical paths, failover/chaos tests, health checks; TLPT for designated entities | PROJECT-NO-CI, DORA-NO-HEALTHCHECK |
| 28 | ICT third-party risk | Pinned dependencies, SBOM, pinned CI actions, documented exit/fallback per provider | DORA-UNPINNED-ACTION, PROJECT-NO-SBOM, PROJECT-NO-LOCKFILE, PROJECT-UNPINNED-DEPS, PROJECT-NO-DEP-SCANNING, DOCKER-* |

## Secure patterns to propose

- **External calls:** explicit connect/read timeouts; retries only for idempotent
  operations or with idempotency keys; exponential backoff with jitter; a circuit
  breaker that opens on repeated failures and a degraded mode (queue the payment, show
  status) instead of failing hard.
- **Audit trail:** append-only, hash-chained or WORM-stored log entries with actor,
  action, amount, before/after state and correlation id.
- **Health:** `/health` (liveness) and `/ready` (readiness checking DB and critical
  providers), wired to monitoring and the orchestrator.
- **Supply chain:** lockfiles, SBOM (CycloneDX/SPDX) in CI, actions and images pinned by
  SHA/digest, a documented exit strategy for each critical SaaS/cloud provider.

## Major ICT incident reporting

Under the implementing technical standards, the initial notification is due within
4 hours of classifying the incident as major and no later than 24 hours after becoming
aware of it; the intermediate report within 72 hours of the initial notification; and
the final report within one month of the latest intermediate report. Confirm the
current standards and your competent authority (in Spain, Banco de España, CNMV or DGSFP
depending on the entity).

## Outside the code

- ICT risk management framework approved by the management body (Art. 5, 6).
- Register of Information for all ICT third-party arrangements (Art. 28(3)).
- Business continuity and recovery plans with tested RTO/RPO (Art. 11, 12).
- Digital operational resilience testing programme, TLPT where required (Art. 24-27).
- Major incident classification and reporting workflow (Art. 17-19).
