#!/usr/bin/env python3
"""nis2-guard: static scanner that helps align a codebase with NIS2's technical measures.

Standard library only. It looks for technical signals in code and repository
layout that relate to the risk-management measures of Article 21(2) of
Directive (EU) 2022/2555. It certifies nothing: it is a helper for catching the
obvious problems.

Usage:
    python nis2_scan.py PATH [--format md|json] [--output FILE]
                             [--fail-on high|medium|low|none] [--exclude GLOB ...]

To silence a single line, add "nis2-ignore" in a comment on that line.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist",
    "build", ".next", "target", "vendor", ".tox", ".mypy_cache", ".idea",
}
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock",
    "cargo.lock", "go.sum", "pipfile.lock", "composer.lock",
}
CODE_EXT = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".cs",
    ".rs", ".kt", ".swift", ".sh",
}
CONFIG_EXT = {
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".tf",
    ".properties", ".xml", ".env",
}
SCAN_EXT = CODE_EXT | CONFIG_EXT
MAX_BYTES = 1_000_000
SEV_ORDER = {"high": 3, "medium": 2, "low": 1}
LABEL = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}

PLACEHOLDER = re.compile(
    r"(?i)example|changeme|change_me|your[_-]|xxx|<[^>]+>|\$\{|%\(|environ|"
    r"getenv|process\.env|\*{3,}|dummy|sample|placeholder|todo|fake"
)
ENV_SECRET = re.compile(
    r"(?i)^\s*(?:export\s+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)"
    r"[A-Z0-9_]*\s*=\s*[^\s'\"#$][^\s#]{7,}"
)

RULES = [
    {
        "id": "SECRET-HARDCODED", "sev": "high", "art": "21(2)(h), 21(2)(i)",
        "placeholder_check": True,
        "pats": [
            r"AKIA[0-9A-Z]{16}",
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            r"gh[pousr]_[A-Za-z0-9]{36,}",
            r"sk-ant-[A-Za-z0-9_\-]{20,}",
            r"xox[baprs]-[A-Za-z0-9-]{10,}",
            r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b"
            r"\s*[:=]\s*['\"][^'\"\s]{8,}['\"]",
        ],
        "msg": "Possible credential written in code or in a configuration file.",
        "fix": "Remove it from the repository, rotate the credential (treat it as exposed) and read it from an environment variable or a secrets manager.",
    },
    {
        "id": "TLS-VERIFY-OFF", "sev": "high", "art": "21(2)(h)",
        "pats": [
            r"verify\s*=\s*False",
            r"rejectUnauthorized\s*:\s*false",
            r"InsecureSkipVerify\s*:\s*true",
            r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0",
            r"CURLOPT_SSL_VERIFYPEER\W+(?:false|0)",
            r"ssl\._create_unverified_context",
        ],
        "msg": "TLS certificate verification is disabled.",
        "fix": "Remove the override. If the problem is an internal CA, add that CA to the trust store instead of skipping verification.",
    },
    {
        "id": "AUTH-JWT-UNSAFE", "sev": "high", "art": "21(2)(i), 21(2)(j)",
        "code_only": True,
        "pats": [
            r"algorithms\s*=\s*\[\s*['\"]none['\"]",
            r"verify_signature['\"]?\s*:\s*False",
        ],
        "msg": "JWT tokens are accepted without verifying the signature.",
        "fix": "Always verify the signature and pin the list of allowed algorithms (for example RS256 or ES256).",
    },
    {
        "id": "INJECTION-SQL", "sev": "high", "art": "21(2)(e)", "code_only": True,
        "pats": [
            r"\.(?:execute|executemany|query|raw)\(\s*(?:f['\"]|['\"][^'\"]*['\"]\s*(?:%|\+|\.format\())",
            r"\.query\(\s*`[^`]*\$\{",
        ],
        "msg": "SQL query built by concatenating or interpolating strings: injection risk.",
        "fix": "Use parameterized queries (placeholders with parameters passed separately) or the ORM.",
    },
    {
        "id": "CRYPTO-WEAK-CIPHER", "sev": "high", "art": "21(2)(h)", "code_only": True,
        "pats": [r"MODE_ECB|AES/ECB|\bRC4\b|\b3DES\b|DES/|DESede|createCipher\("],
        "msg": "Obsolete cipher or insecure mode (ECB, DES, RC4).",
        "fix": "Switch to AES-256-GCM or ChaCha20-Poly1305, with keys and nonces handled by a high-level library.",
    },
    {
        "id": "CRYPTO-WEAK-HASH", "sev": "medium", "art": "21(2)(h)", "code_only": True,
        "pats": [
            r"hashlib\.(?:md5|sha1)\(",
            r"getInstance\(\s*['\"](?:MD5|SHA-?1)['\"]",
            r"createHash\(\s*['\"](?:md5|sha1)['\"]",
            r"\b(?:MD5|SHA1)\.Create\(",
        ],
        "msg": "MD5 or SHA-1 in use; neither is suitable for security purposes.",
        "fix": "Use SHA-256 or stronger for integrity, and argon2id, scrypt or bcrypt for passwords.",
    },
    {
        "id": "EXEC-DANGEROUS", "sev": "medium", "art": "21(2)(e)", "code_only": True,
        "pats": [
            r"\beval\(", r"\bos\.system\(", r"shell\s*=\s*True",
            r"child_process\.exec\(", r"\bpickle\.loads?\(", r"yaml\.load\((?![^)]*Loader)",
        ],
        "msg": "Dynamic code execution or unsafe deserialization.",
        "fix": "Avoid eval and shell=True, pass arguments as a list, use yaml.safe_load and data formats that cannot execute code.",
    },
    {
        "id": "DEBUG-ENABLED", "sev": "medium", "art": "21(2)(e)", "code_only": True,
        "pats": [r"\bDEBUG\s*=\s*True\b", r"\bdebug\s*=\s*True\b"],
        "msg": "Debug mode enabled in code: it can leak stack traces and internal data.",
        "fix": "Read it from configuration and keep it off by default in production.",
    },
    {
        "id": "CORS-WILDCARD", "sev": "medium", "art": "21(2)(e), 21(2)(i)",
        "pats": [
            r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]?\*",
            r"allow_origins\s*=\s*\[\s*['\"]\*['\"]",
            r"origin\s*:\s*['\"]\*['\"]",
            r"CORS_ALLOW_ALL_ORIGINS\s*=\s*True",
        ],
        "msg": "CORS is open to any origin.",
        "fix": "List the allowed origins explicitly.",
    },
    {
        "id": "LOG-SENSITIVE", "sev": "medium", "art": "21(2)(i)", "code_only": True,
        "pats": [
            r"(?i)(?:log(?:ger)?\.\w+|print|console\.\w+|logging\.\w+)\(.*"
            r"\b(?:password|passwd|token|secret|api[_-]?key|authorization)\b"
        ],
        "msg": "A log statement may be writing sensitive data (check whether it logs the value or only the name).",
        "fix": "Never log passwords, tokens or authorization headers; mask or drop the value.",
    },
    {
        "id": "HTTP-PLAINTEXT", "sev": "low", "art": "21(2)(h)", "code_only": True,
        "pats": [r"['\"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|www\.w3\.org|schemas\.|example\.)"],
        "msg": "URL using unencrypted HTTP.",
        "fix": "Use HTTPS unless the traffic is strictly local.",
    },
]
RULE_BY_ID = {r["id"]: r for r in RULES}
for _r in RULES:
    _r["rx"] = [re.compile(p) for p in _r["pats"]]

MANUAL = [
    ("20", "Management bodies approve and oversee the cybersecurity measures and receive training."),
    ("21(2)(a)", "Documented and approved policies on risk analysis and information system security."),
    ("21(2)(b), 23", "Incident handling able to deliver an early warning within 24 h, a notification within 72 h and a final report within one month."),
    ("21(2)(c)", "Tested backups, business continuity and crisis management."),
    ("21(2)(d)", "Assessment of critical suppliers and security clauses in contracts."),
    ("21(2)(f)", "Periodic testing or audits that measure whether the measures work."),
    ("21(2)(g)", "Cyber hygiene practices and staff training."),
    ("21(2)(i)", "Access control, joiner/leaver processes and asset inventory."),
    ("21(2)(j)", "MFA enabled for administration, email and remote access; secured emergency communications."),
]
DISCLAIMER = (
    "This tool looks for technical signals and does not certify NIS2 compliance. "
    "A clean report does not mean you comply: organizational, legal and governance "
    "measures are out of its reach. Consult a legal and cybersecurity professional."
)


def finding(rule: dict, file: str | None, line: int | None, detail: str = "") -> dict:
    return {
        "rule": rule["id"], "sev": rule["sev"], "art": rule["art"],
        "file": file, "line": line, "msg": rule["msg"], "fix": rule["fix"],
        "detail": detail,
    }


def collect(root: Path, excludes: list[str]) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            rel = (Path(dirpath) / name).relative_to(root)
            posix = rel.as_posix()
            if any(fnmatch.fnmatch(posix, e) for e in excludes):
                continue
            files.append(rel)
    return files


def read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:1024]:
        return None
    return data.decode("utf-8", errors="ignore")


def scannable(rel: Path) -> bool:
    low = rel.name.lower()
    if low in SKIP_FILES or ".min." in low:
        return False
    if any(m in low for m in (".example", ".sample", ".template")):
        return False
    return rel.suffix.lower() in SCAN_EXT or low.startswith(".env") or low.startswith("dockerfile")


def scan_file(root: Path, rel: Path) -> list[dict]:
    if not scannable(rel):
        return []
    text = read_text(root / rel)
    if text is None:
        return []
    is_code = rel.suffix.lower() in CODE_EXT
    is_env = rel.name.lower().startswith(".env")
    out: list[dict] = []
    for n, line in enumerate(text.splitlines(), 1):
        if "nis2-ignore" in line or len(line) > 2000:
            continue
        for rule in RULES:
            if rule.get("code_only") and not is_code:
                continue
            for rx in rule["rx"]:
                m = rx.search(line)
                if not m:
                    continue
                if rule.get("placeholder_check") and PLACEHOLDER.search(m.group(0)):
                    continue
                out.append(finding(rule, rel.as_posix(), n))
                break
        if is_env:
            m = ENV_SECRET.search(line)
            if m and not PLACEHOLDER.search(m.group(0)):
                out.append(finding(RULE_BY_ID["SECRET-HARDCODED"], rel.as_posix(), n))
    return out


def project_checks(root: Path, files: list[Path]) -> list[dict]:
    out: list[dict] = []
    posix = {f.as_posix().lower() for f in files}
    names = {f.name.lower() for f in files}

    def add(rid, sev, art, msg, fix, file=None, detail=""):
        out.append(finding({"id": rid, "sev": sev, "art": art, "msg": msg, "fix": fix}, file, None, detail))

    if "security.md" not in names:
        add("PROJECT-NO-SECURITY-POLICY", "medium", "21(2)(e)",
            "No vulnerability disclosure policy (SECURITY.md).",
            "Add a SECURITY.md with a contact and a response time. A template is in templates/.")

    if not any("incident" in p for p in posix):
        add("PROJECT-NO-INCIDENT-PLAN", "medium", "21(2)(b), 23",
            "No incident response document found.",
            "Document who decides, how incidents are detected and how they are reported (24 h / 72 h / 1 month). A template is in templates/.")

    ci_files = [
        f for f in files
        if (f.as_posix().lower().startswith(".github/workflows/") and f.suffix.lower() in (".yml", ".yaml"))
        or f.name.lower() in (".gitlab-ci.yml", "jenkinsfile", "azure-pipelines.yml", "bitbucket-pipelines.yml")
    ]
    ci_text = " ".join((read_text(root / f) or "").lower() for f in ci_files)
    if not ci_files:
        add("PROJECT-NO-CI", "low", "21(2)(e), 21(2)(f)",
            "No continuous integration, so there are no automatic checks.",
            "Add a pipeline that runs tests and this scanner on every change.")
    tools = ("codeql", "trivy", "pip-audit", "npm audit", "semgrep", "gitleaks",
             "snyk", "bandit", "grype", "osv-scanner", "dependency-review", "trufflehog")
    bots = {"renovate.json", ".renovaterc", ".renovaterc.json", "dependabot.yml", "dependabot.yaml"}
    if not (bots & names) and not any(t in ci_text for t in tools):
        add("PROJECT-NO-DEP-SCANNING", "medium", "21(2)(d), 21(2)(e)",
            "No automatic dependency or secret scanning detected.",
            "Enable Dependabot or Renovate and add a scanner (CodeQL, Trivy, pip-audit, gitleaks...).")

    manifests = ("package.json", "requirements.txt", "go.mod", "pom.xml", "cargo.toml", "pyproject.toml")
    if names & set(manifests) and "sbom" not in " ".join(posix) and "cyclonedx" not in ci_text and "syft" not in ci_text:
        add("PROJECT-NO-SBOM", "low", "21(2)(d)",
            "No software bill of materials (SBOM) is generated.",
            "Generate an SBOM (CycloneDX or SPDX) in the pipeline; it helps you respond quickly when a vulnerability is published.")

    lockfiles = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb")
    for f in files:
        low = f.name.lower()
        if low == "package.json" and not any((f.parent / lk).as_posix().lower() in posix for lk in lockfiles):
            add("PROJECT-NO-LOCKFILE", "medium", "21(2)(d)",
                "package.json without a lockfile.",
                "Commit the lockfile and use npm ci in the pipeline.", f.as_posix())
        if re.fullmatch(r"requirements.*\.txt", low):
            lines = [l.strip() for l in (read_text(root / f) or "").splitlines()]
            loose = [l for l in lines if l and not l.startswith(("#", "-")) and "==" not in l and " @ " not in l and "git+" not in l]
            if loose:
                add("PROJECT-UNPINNED-DEPS", "low", "21(2)(d)",
                    "Python dependencies without pinned versions.",
                    "Pin exact versions (ideally with hashes) or use a lockfile (uv, poetry, pip-tools).",
                    f.as_posix(), f"{len(loose)} unpinned")

    gitignore = (read_text(root / ".gitignore") or "").splitlines() if (root / ".gitignore").exists() else []
    ignored = any(l.strip() in (".env", ".env*", "*.env", "/.env") for l in gitignore)
    for f in files:
        if f.name == ".env" and not ignored:
            add("PROJECT-ENV-NOT-IGNORED", "high", "21(2)(h), 21(2)(i)",
                "A .env file exists and is not listed in .gitignore: it can easily end up in the repository.",
                "Add .env to .gitignore, purge it from history if it was already committed and rotate any secrets it held.",
                f.as_posix())

    for f in files:
        if not (f.name.lower().startswith("dockerfile") or f.suffix.lower() == ".dockerfile"):
            continue
        text = read_text(root / f) or ""
        users = [m.group(1) for m in re.finditer(r"(?im)^\s*USER\s+(\S+)", text)]
        if not any(u.lower() not in ("root", "0") for u in users):
            add("DOCKER-ROOT", "medium", "21(2)(i)",
                "The container runs as root.",
                "Create an unprivileged user and add USER before CMD.", f.as_posix())
        stages: set[str] = set()
        for m in re.finditer(r"(?im)^\s*FROM\s+(\S+)(?:\s+AS\s+(\S+))?", text):
            image, alias = m.group(1), m.group(2)
            floating = image.endswith(":latest") or (
                ":" not in image and "@" not in image and "$" not in image
                and image.lower() != "scratch" and image not in stages)
            if floating:
                add("DOCKER-UNPINNED-IMAGE", "low", "21(2)(d)",
                    "Base image without a pinned version (latest or no tag).",
                    "Pin a specific tag or, better, a sha256 digest.", f.as_posix(), image)
            if alias:
                stages.add(alias)
        if re.search(r"(?i)(?:curl|wget)[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh", text):
            add("DOCKER-CURL-PIPE", "medium", "21(2)(d)",
                "A remote script is downloaded and executed without verification.",
                "Download to a file, check its hash or signature, then run it.", f.as_posix())
    return out


def scan(root: Path, excludes: list[str] | None = None) -> tuple[list[dict], int]:
    root = root.resolve()
    files = collect(root, excludes or [])
    findings: list[dict] = []
    scanned = 0
    for rel in files:
        if scannable(rel):
            scanned += 1
        findings.extend(scan_file(root, rel))
    findings.extend(project_checks(root, files))
    seen, unique = set(), []
    for f in findings:
        key = (f["rule"], f["file"], f["line"], f["detail"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique, scanned


def summary(findings: list[dict]) -> dict:
    return {s: sum(1 for f in findings if f["sev"] == s) for s in ("high", "medium", "low")}


def render_md(root: Path, findings: list[dict], scanned: int) -> str:
    s = summary(findings)
    lines = [
        "# nis2-guard report", "",
        f"Scanned path: `{root}`  ",
        f"Files reviewed: {scanned}  ",
        f"Findings: {s['high']} high, {s['medium']} medium, {s['low']} low", "",
        f"> {DISCLAIMER}", "", "## Technical findings", "",
    ]
    if not findings:
        lines += ["The scanner found no technical signals. Still review the items in the next section.", ""]
    grouped: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        grouped[f["rule"]].append(f)
    for g in sorted(grouped.values(), key=lambda g: (-SEV_ORDER[g[0]["sev"]], g[0]["rule"])):
        h = g[0]
        lines += [f"### [{LABEL[h['sev']]}] {h['rule']} (NIS2 Art. {h['art']})", "", h["msg"], "",
                  f"**What to change:** {h['fix']}", "", "Where:"]
        for f in g[:10]:
            loc = f["file"] or "(project)"
            if f["line"]:
                loc += f":{f['line']}"
            extra = f" ({f['detail']})" if f["detail"] else ""
            lines.append(f"- `{loc}`{extra}")
        if len(g) > 10:
            lines.append(f"- and {len(g) - 10} more")
        lines.append("")
    lines += ["## What a scanner cannot check", ""]
    lines += [f"- Art. {art}: {txt}" for art, txt in MANUAL]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Technical helper scanner for NIS2.")
    ap.add_argument("path", help="Project folder")
    ap.add_argument("--format", choices=("md", "json"), default="md")
    ap.add_argument("--output", help="Output file (default: print to screen)")
    ap.add_argument("--fail-on", choices=("high", "medium", "low", "none"), default="none",
                    help="Exit with code 1 if there are findings of this severity or higher")
    ap.add_argument("--exclude", action="append", default=[], help="Glob pattern to ignore (repeatable)")
    args = ap.parse_args(argv)

    root = Path(args.path)
    if not root.is_dir():
        print(f"Folder not found: {root}", file=sys.stderr)
        return 2
    findings, scanned = scan(root, args.exclude)
    if args.format == "json":
        body = json.dumps({
            "root": str(root.resolve()), "files_scanned": scanned,
            "summary": summary(findings), "findings": findings,
            "manual_review": [{"article": a, "item": t} for a, t in MANUAL],
            "disclaimer": DISCLAIMER,
        }, ensure_ascii=False, indent=2)
    else:
        body = render_md(root.resolve(), findings, scanned)
    if args.output:
        Path(args.output).write_text(body, encoding="utf-8")
    else:
        print(body)
    if args.fail_on != "none":
        limit = SEV_ORDER[args.fail_on]
        if any(SEV_ORDER[f["sev"]] >= limit for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
