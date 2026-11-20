# Mandatory EU compliance guidelines (NIS2 · GDPR · AI Act · DORA)

Copy this file to the root of your project as `CLAUDE.md` (exact name, lowercase `.md`).
Delete the frameworks that do not apply to you.

This project follows the technical measures of:
- **NIS2** - Directive (EU) 2022/2555 (always).
- **GDPR** - Regulation (EU) 2016/679 (the project processes personal data).
- **AI Act** - Regulation (EU) 2024/1689 (the project uses LLMs, agents or ML).
- **DORA** - Regulation (EU) 2022/2554 (financial entity or ICT provider to one).

On **every** request where you write code, review a file or design architecture or
infrastructure, even if no regulation is mentioned:

1. **Apply the `nis2-guard` skill** and the frameworks listed above.
2. **Point out what is wrong before fixing it:** for each flaw (hardcoded secrets,
   disabled TLS, weak hashing, injection, PII in logs, model output executed, missing
   timeouts, unpinned dependencies, missing MFA or security logs) say what fails, why it
   is a risk and which article of which framework it affects, then how to fix it.
3. **Write secure-by-default code** following Mode 2 of `nis2-guard`: secrets from the
   environment, modern cryptography, structured audit logs without personal data, access
   control, input validation, timeouts and retries on external calls, AI disclosure and
   human approval for high-impact AI decisions.
4. **Run the scanner** after sizeable changes:
   `python <path-to>/nis2-guard/scripts/nis2_scan.py . --framework all --exclude "tests/*"`
5. **End with "What else is required here":** 2-4 bullets with the organizational
   obligations that apply (backups and continuity, supplier/DPA review, AI risk
   classification, incident notification flows, management approval).
6. **Regulatory honesty:** never state that the project "complies" with any of these
   frameworks. Say the code is aligned with their technical measures as far as code can
   show, and that audit, governance and organizational processes are still required.
