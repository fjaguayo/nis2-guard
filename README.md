# NIS2 Guard for Claude

Proactive security guidance for **Claude Code** and **Claude.ai** that reviews code,
APIs, infrastructure, and technical architecture against the technical measures of the
**NIS2 Directive (EU) 2022/2555**, especially Articles 20, 21, and 23.

This package combines the `nis2-guard` skill with project-level instructions so Claude
can review coding requests by default, identify security weaknesses, explain the related
NIS2 measure, and remind you about obligations that cannot be solved in code alone.

## What it does

- Detects hardcoded secrets, missing MFA, insecure logging, disabled TLS verification,
  weak cryptography, injection risks, and unpinned dependencies.
- Generates secure-by-default code using environment-based secrets, modern cryptography,
  strict input validation, structured security logs, and least-privilege controls.
- Reminds teams about continuity, backups, supplier security, incident reporting
  deadlines (24 hours, 72 hours, and one month), and management accountability.

## Installation

### Claude.ai (web or desktop)

1. Download `nis2-guard-skill.zip` from the repository Releases page.
2. Open **Customize > Skills** in Claude and upload the ZIP file.
3. Create a Claude Project and paste the contents of
   [`PROJECT_INSTRUCTIONS.md`](./PROJECT_INSTRUCTIONS.md) into **Project Instructions**.

### Claude Code

1. Copy [`CLAUDE.md`](./CLAUDE.md) to the root of your project.
2. Copy [`nis2-guard/`](./nis2-guard) into `.claude/skills/nis2-guard/`:

   ```bash
   mkdir -p .claude/skills
   cp -r nis2-guard .claude/skills/
   ```

3. Optionally copy [`.github/workflows/nis2-scan.yml`](./.github/workflows/nis2-scan.yml)
   into your repository to run the scanner on pushes and pull requests.

## Running the scanner

```bash
python nis2-guard/scripts/nis2_scan.py . --format md --exclude "nis2-guard/scripts/*"
python nis2-guard/scripts/nis2_scan.py . --format json --output report.json
```

The Markdown report is written to the path passed to `--output`. Open it with any
Markdown viewer, a text editor, or from PowerShell with:

```powershell
notepad "$env:TEMP\nis2-report.md"
```

The scanner is pattern-based and can produce false positives. Review each finding
against the surrounding code before treating it as a vulnerability. A justified
single-line finding can be suppressed by adding `nis2-ignore` in a comment on that
line; document the reason in your review.

Reports include the scanned path, relative file paths, line numbers, rule names, and
remediation advice. The scanner does not intentionally print matched secret values,
but reports can still reveal private project names, file names, directory paths, and
security weaknesses. Do not commit reports from confidential projects or publish them
without redaction. The default report names are ignored by `.gitignore`.

## Legal notice

This tool helps align software development with technical measures in Article 21. It
does not certify NIS2 compliance and is not legal advice. Full compliance also requires
governance, training, supplier management, continuity capabilities, and documented
incident-response processes.

## Credits and license

Based on [fjaguayo/nis2-guard](https://github.com/fjaguayo/nis2-guard). Distributed
under the original license in [`LICENSE`](./LICENSE).
