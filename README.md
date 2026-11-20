# nis2-guard

A free, open-source Claude skill (plus a dependency-free scanner that also works on its
own) that reviews code and repositories against the technical side of four EU
frameworks: **NIS2**, **GDPR**, the **AI Act** and **DORA**.

It catches the obvious problems, explains what fails and which article it relates to,
proposes what to change, and helps Claude write new code that starts out more secure.

| Framework | Regulation | Focus in code |
|-----------|------------|---------------|
| **NIS2** | Directive (EU) 2022/2555, Art. 20, 21, 23 | Secrets, TLS, crypto, injection, supply chain, incident readiness |
| **GDPR** | Regulation (EU) 2016/679 | PII in logs, password hashing, sensitive columns, erasure, trackers, PII sent to AI APIs |
| **AI Act** | Regulation (EU) 2024/1689 | AI disclosure, audit logs, prompt injection, unvalidated LLM output, high-risk indicators |
| **DORA** | Regulation (EU) 2022/2554 | Timeouts and resilience on external calls, legacy TLS, health checks, pinned CI actions |

## Contents

- [What it does and what it does not](#what-it-does-and-what-it-does-not)
- [What is in this repository](#what-is-in-this-repository)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage guide](#usage-guide)
- [What it checks](#what-it-checks)
- [Troubleshooting](#troubleshooting)
- [Tests](#tests)
- [Contributing](#contributing)
- [Security](#security)
- [Disclaimer](#disclaimer)
- [License](#license)

## What it does and what it does not

None of these regulations is a test that code passes. They are risk-management,
data-protection and governance frameworks with process, documentation and reporting
obligations. This project covers the part that is visible in a repository and reminds
you in every report of what falls outside it: policies, records of processing, supplier
contracts, risk classification, training, continuity and management accountability.

A clean report does not mean you comply. The skill never says that your project
"complies"; it says that it is aligned with the technical measures it can check.

## What is in this repository

| Path | What it is |
|------|------------|
| `nis2-guard/` | The skill: `SKILL.md`, scanner, references, templates and tests. |
| `nis2-guard-skill.zip` | The same folder, packaged and ready to upload to Claude. |
| `nis2-guard/scripts/nis2_scan.py` | Multi-framework scanner, Python standard library only. |
| `nis2-guard/templates/` | `CLAUDE.md` (proactive mode), `SECURITY.md`, incident response plan, CI workflow. |
| `PROJECT_INSTRUCTIONS.md` | Text to paste into a Claude Project for proactive mode in the chat app. |
| `CLAUDE.md` | Instructions Claude Code follows when working on this repository itself. |
| `.github/workflows/nis2-scan.yml` | Runs the tests and a full scan on every push and pull request. |

The full list of rules and what each one maps to is in
[`nis2-guard/README.md`](nis2-guard/README.md).

## Requirements

- **Python 3.9 or later** for the scanner. There is nothing to `pip install`.
- **To use it as a Claude skill:** a Claude plan where skills are available, with code
  execution and file creation turned on, because the skill runs the scanner script.
- **Git**, only if you want to clone the repository.

## Installation

There are three ways to use nis2-guard. They are independent: pick the one that fits.

### Option A: Claude (web or desktop app)

1. Download `nis2-guard-skill.zip` from the root of this repository (or from the
   [Releases](../../releases) page).
2. In Claude, open **Customize > Skills** and upload the ZIP file. The exact menu name
   can vary with your plan and app version.
3. Check that code execution and file creation are enabled in Claude's settings.
4. Optional, for proactive mode: create a Claude Project and paste the contents of
   [`PROJECT_INSTRUCTIONS.md`](PROJECT_INSTRUCTIONS.md) into its **Project Instructions**.
   Claude will then apply the skill to every coding request in that Project, even if
   you never mention a regulation.

### Option B: Claude Code

```bash
git clone https://github.com/fjaguayo/nis2-guard.git

# Available in all your projects
mkdir -p ~/.claude/skills
cp -r nis2-guard/nis2-guard ~/.claude/skills/

# Or only in one project
mkdir -p .claude/skills
cp -r nis2-guard/nis2-guard .claude/skills/
```

Restart Claude Code so it picks the skill up.

For proactive mode, copy [`nis2-guard/templates/CLAUDE.md`](nis2-guard/templates/CLAUDE.md)
to the root of your project as `CLAUDE.md` and delete the frameworks that do not apply
to you. Do not copy the `CLAUDE.md` from the root of this repository: that one is for
working on nis2-guard itself.

### Option C: only the scanner, without Claude

```bash
git clone https://github.com/fjaguayo/nis2-guard.git
cd nis2-guard
python nis2-guard/scripts/nis2_scan.py /path/to/your/project
```

On Windows, use `py` if `python` is not found. The scanner is a single file, so you can
also copy `nis2-guard/scripts/nis2_scan.py` into your own repository (for example into
`tools/`).

## Usage guide

### With Claude

Describe what you want in plain language. Claude chooses the frameworks that apply from
what the code does: personal data brings in GDPR, LLMs bring in the AI Act,
payments or banking bring in DORA, and NIS2 is always included.

| Goal | Example prompt |
|------|----------------|
| Audit a repository | "Review this repo for NIS2 and tell me what fails." |
| Pick frameworks | "Audit our RAG pipeline for the AI Act and GDPR." |
| Get a fix plan | "Scan this project and give me a prioritized fix plan." |
| Write new code | "Write this payment client with DORA in mind." |
| Fix and verify | "Fix the high-severity findings and scan again to confirm." |
| Documents | "Create an incident response plan using the NIS2, GDPR and DORA deadlines." |

In a chat, attach or paste the code (a zip of the project works well). In Claude Code,
run it from the project folder.

### With the command line

By default the scanner runs the NIS2 rules only. Add frameworks with `--framework`.

```bash
# NIS2 only (default)
python nis2-guard/scripts/nis2_scan.py .

# Everything: NIS2 + GDPR + AI Act + DORA
python nis2-guard/scripts/nis2_scan.py . --framework all

# Only the frameworks that apply to you
python nis2-guard/scripts/nis2_scan.py . --framework gdpr,ai-act

# Save the report, or get JSON for other tools
python nis2-guard/scripts/nis2_scan.py . --framework all --output nis2-report.md
python nis2-guard/scripts/nis2_scan.py . --framework all --format json --output report.json

# Leave paths out and fail the build on high-severity findings
python nis2-guard/scripts/nis2_scan.py . --framework all --exclude "tests/*" --fail-on high
```

| Option | Meaning |
|--------|---------|
| `path` | Project folder to scan (required). |
| `--framework` | `nis2` (default), `gdpr`, `ai-act`, `dora` or `all`. Repeatable or comma-separated. |
| `--format md\|json` | Report format. Default: `md`. |
| `--output FILE` | Write the report to a file instead of the screen. |
| `--fail-on high\|medium\|low\|none` | Exit with code 1 if there are findings of this severity or higher. Default: `none`. |
| `--exclude GLOB` | Ignore paths matching the pattern. Repeatable. |

Exit codes: `0` means the scan ran and the `--fail-on` threshold was not reached, `1`
means it was reached, and `2` means the folder was not found.

### Reading the report

The report starts with a summary (how many high, medium and low findings) and groups the
findings by rule, most severe first. Each group says what was found, which articles it
relates to, what to change and where (file and line, or "(project)" for repository-level
checks such as a missing `SECURITY.md`). The last section lists what a scanner cannot
check, with one block per selected framework, and it appears even when nothing was found.

A rule shared by several frameworks counts once. For example, a hardcoded secret is a
single finding tagged with every selected framework it touches.

### Silencing a false positive

The scanner is pattern-based and can be wrong. Review each finding against the code around
it. For a justified false positive, add `nis2-ignore` in a comment on that line (it works
for every framework) and write the reason next to it:

```python
requests.get(internal_url, verify=False)  # nis2-ignore: internal test server
```

Lockfiles, minified files, files over 1 MB, `*.example` / `*.sample` / `*.template` files
and folders such as `.git`, `node_modules`, `venv` and `dist` are skipped automatically.

### Privacy of the reports

The scanner never prints the value of the secrets or personal data it detects. Reports can
still reveal file names, directory paths and security weaknesses, so do not commit or
publish reports from confidential projects without redacting them. The default report
names are listed in `.gitignore`.

### In continuous integration

This repository runs the tests and a full scan on every push and pull request
(`.github/workflows/nis2-scan.yml`). To use it in another project, copy
`nis2-guard/templates/nis2-scan.yml` to `.github/workflows/`, adjust the path where you keep
the scanner, and let Dependabot keep the pinned action hashes up to date.

The scanner's own source contains the patterns it looks for, so scanning the skill folder
flags itself. Exclude it (`--exclude "nis2-guard/*"`) when the skill lives inside the
repository you scan.

## What it checks

- **Shared rules (NIS2, cross-mapped to the others):** hardcoded secrets, disabled TLS
  verification, weak ciphers and hashes, SQL injection, dangerous execution, debug mode,
  open CORS, sensitive data in logs, unsafe JWT handling, plaintext HTTP, unpinned
  dependencies and CI actions, missing lockfile, SBOM, dependency scanning, security
  policy and incident plan, Docker running as root.
- **GDPR (`--framework gdpr`):** fast password hashes, personal data in logs, sensitive
  data in plaintext columns, no erasure path, personal data sent to LLM prompts, trackers
  without consent management.
- **AI Act (`--framework ai-act`):** model output passed to `eval` or a shell, prompt
  injection risk, no AI disclosure, no AI audit log, high-risk use indicators. These rules
  only run when the project uses an AI SDK.
- **DORA (`--framework dora`):** legacy TLS versions, outbound HTTP without timeout, payment
  SDKs without retry or circuit breaker, no health endpoint.

Rule IDs, severities and article mappings are in [`nis2-guard/README.md`](nis2-guard/README.md)
and in `nis2-guard/references/`.

## Troubleshooting

- **`python: command not found`**: try `python3`, or `py` on Windows.
- **The skill does not trigger in Claude**: mention the regulation explicitly in your
  request, and check that the skill is enabled and that code execution is on.
- **Claude says it cannot run the script**: code execution and file creation must be
  enabled in Claude's settings.
- **"Folder not found"**: the path must be a directory, not a single file.
- **Too many false positives**: exclude test and fixture folders with `--exclude`, silence
  single lines with `nis2-ignore`, and open an issue with the pattern that misfired.
- **A file is not scanned**: it may be over 1 MB, binary, in an ignored folder or of a
  format the scanner does not read. Rules read one line at a time, so calls split over
  several lines can be missed.
- **The report is clean but I am worried**: a clean report only means no technical signals
  were found. Go through the manual checks at the end of the report.

## Tests

```bash
python -m unittest discover -s nis2-guard/tests -v
```

Requires Python 3.9 or later. Every rule has positive and negative tests.

## Contributing

Rules are simple patterns added to the `RULES` list in the scanner. A new rule needs a
framework, the article it relates to, a positive test and a negative test. Open an issue
if you find a false positive. The roadmap is in [`nis2-guard/README.md`](nis2-guard/README.md#roadmap).

## Security

To report a vulnerability in nis2-guard itself, see [`SECURITY.md`](SECURITY.md).

## Disclaimer

This tool does not certify compliance with NIS2, GDPR, the AI Act or DORA, and does not
replace an audit or legal advice. Transposition status, application dates and guidance
change by country and over time: check the rules in force where you operate.

## License

MIT. See [`LICENSE`](LICENSE).
