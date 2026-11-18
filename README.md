# nis2-guard

A skill for Claude (and a scanner that also works on its own) that reviews code and
repositories against the technical measures of the NIS2 Directive (EU 2022/2555).

It catches the obvious problems, explains what fails, proposes what to change and helps
you write new code that starts out more secure.

## What it does and what it does not

NIS2 is not a test that code passes. It is a risk-management directive with governance,
process and reporting obligations. This project covers the part that is visible in a
repository (mainly supply chain, cryptography, secure development and access control) and
reminds you in every report of what falls outside it: policies, training, continuity,
suppliers, management accountability.

A clean report does not mean you comply. It is also not legal advice.

## What is included

- `nis2-guard/`: the skill (SKILL.md, scanner, references and templates).
- `nis2-guard/scripts/nis2_scan.py`: static scanner in Python, no dependencies.
- `nis2-guard/templates/`: SECURITY.md and an incident response plan with the Article 23 deadlines.
- `.github/workflows/nis2-scan.yml`: runs the tests and the scanner on every push and pull request.
- `tests/`: scanner tests.

## Using the scanner

```bash
python nis2-guard/scripts/nis2_scan.py . --format md
python nis2-guard/scripts/nis2_scan.py . --format json --output report.json
python nis2-guard/scripts/nis2_scan.py . --fail-on high --exclude "tests/*"
```

To silence a single line (a justified false positive), add `nis2-ignore` in a comment on
that line. The report never prints the value of the secrets it detects.

The scanner's own source contains the patterns it looks for, so scanning this repository
flags itself. The CI workflow excludes `nis2-guard/scripts/*` for that reason.

## Installing as a Claude skill

1. Package the `nis2-guard/` folder as a `.skill` file (or download it from the releases page).
2. Upload it in the skills section of Claude's settings.
3. Ask something like "review this repo for NIS2" or "write this endpoint with NIS2 in mind".

## What it checks today

| Rule | What it detects | NIS2 Art. |
|------|-----------------|-----------|
| SECRET-HARDCODED | Credentials in code or configuration | 21(2)(h), (i) |
| TLS-VERIFY-OFF | Certificate verification disabled | 21(2)(h) |
| CRYPTO-WEAK-CIPHER / WEAK-HASH | ECB, DES, RC4, MD5, SHA-1 | 21(2)(h) |
| INJECTION-SQL | SQL built by concatenation | 21(2)(e) |
| EXEC-DANGEROUS | eval, shell=True, pickle, yaml.load | 21(2)(e) |
| DEBUG-ENABLED, CORS-WILDCARD | Insecure configuration | 21(2)(e), (i) |
| LOG-SENSITIVE | Logs containing passwords or tokens | 21(2)(i) |
| AUTH-JWT-UNSAFE | JWT without signature verification | 21(2)(i), (j) |
| PROJECT-* | Missing SECURITY.md, incident plan, lockfile, SBOM, dependency scanning | 21(2)(b), (d), (e) |
| DOCKER-* | Container as root, unpinned images, curl piped to sh | 21(2)(d), (i) |

Full detail in `nis2-guard/references/nis2-art21-mapping.md`.

## Tests

```bash
python -m unittest discover -s tests -v
```

Requires Python 3.9 or later.

## Roadmap

- Reports in Spanish and other languages.
- Pre-commit hook.
- SARIF output so GitHub can show findings in the Security tab.
- Rules for Terraform and Kubernetes.
- Management summary generator.

## Contributing

Rules are simple patterns and are added to the `RULES` list in the scanner. Every new
rule needs a test and the NIS2 article it relates to. Open an issue if you find a false
positive.

## Disclaimer

This tool does not certify NIS2 compliance and does not replace an audit or legal advice.
Transposition status changes by country: check the regulation in force in yours.

## License

MIT.
