#!/usr/bin/env python3
"""
happy-grok: local repository exposure checker for AI coding-agent incidents.

This tool never uploads data. Findings are redacted by default.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable


VERSION = "0.1.0"


@dataclass(frozen=True)
class SecretRule:
    rule_id: str
    severity: str
    description: str
    pattern: re.Pattern[str]
    rotate_hint: str


@dataclass
class Finding:
    kind: str
    severity: str
    rule_id: str
    location: str
    line: int | None
    match: str
    recommendation: str


@dataclass
class Evidence:
    kind: str
    severity: str
    location: str
    detail: str
    recommendation: str


SECRET_RULES: list[SecretRule] = [
    SecretRule(
        "aws-access-key",
        "critical",
        "AWS access key id",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "Rotate the IAM access key and review CloudTrail for usage.",
    ),
    SecretRule(
        "github-token",
        "critical",
        "GitHub personal or fine-grained access token",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,255}\b|\bgithub_pat_[A-Za-z0-9_]{80,255}\b"),
        "Revoke the GitHub token and review audit logs, repo access, and workflow runs.",
    ),
    SecretRule(
        "openai-api-key",
        "high",
        "OpenAI API key",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,200}\b"),
        "Revoke the API key, create a replacement, and review usage/billing.",
    ),
    SecretRule(
        "xai-api-key",
        "high",
        "xAI API key",
        re.compile(r"\bxai-[A-Za-z0-9_-]{20,200}\b"),
        "Revoke the xAI key, create a replacement, and review API usage.",
    ),
    SecretRule(
        "anthropic-api-key",
        "high",
        "Anthropic API key",
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,200}\b"),
        "Revoke the Anthropic key, create a replacement, and review usage.",
    ),
    SecretRule(
        "google-api-key",
        "high",
        "Google API key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "Restrict or rotate the Google key and review Cloud audit/API usage logs.",
    ),
    SecretRule(
        "stripe-secret-key",
        "critical",
        "Stripe secret key",
        re.compile(r"\b(?:sk_live|rk_live)_[0-9A-Za-z]{20,200}\b"),
        "Roll the Stripe key and inspect payment/account activity.",
    ),
    SecretRule(
        "slack-token",
        "high",
        "Slack token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,200}\b"),
        "Revoke the Slack token and review workspace app audit logs.",
    ),
    SecretRule(
        "npm-token",
        "high",
        "npm access token",
        re.compile(r"\bnpm_[A-Za-z0-9]{36,}\b"),
        "Revoke the npm token and inspect package publishing activity.",
    ),
    SecretRule(
        "pypi-token",
        "high",
        "PyPI API token",
        re.compile(r"\bpypi-[A-Za-z0-9_-]{40,200}\b"),
        "Revoke the PyPI token and inspect release history.",
    ),
    SecretRule(
        "huggingface-token",
        "high",
        "Hugging Face token",
        re.compile(r"\bhf_[A-Za-z0-9]{30,200}\b"),
        "Revoke the Hugging Face token and review model/dataset access.",
    ),
    SecretRule(
        "private-key-block",
        "critical",
        "Private key block",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
        "Replace the keypair or certificate and remove the private key from repository history.",
    ),
    SecretRule(
        "database-url",
        "critical",
        "Database URL with embedded credentials",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^:\s/@]+:[^@\s]+@[^ \t\r\n]+", re.IGNORECASE),
        "Rotate the database password/user and review database access logs.",
    ),
    SecretRule(
        "jwt",
        "medium",
        "JWT-like token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "If this is a live token, revoke the session or rotate the signing secret.",
    ),
    SecretRule(
        "generic-assignment",
        "medium",
        "Generic secret-looking assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd|client[_-]?secret|private[_-]?key|access[_-]?key|auth[_-]?token|bearer)\b"
            r"\s*[:=]\s*[\"']?([A-Za-z0-9_./+=:@$%!-]{12,})"
        ),
        "Inspect manually. If real, rotate it and move it into a secret manager.",
    ),
]


SENSITIVE_NAME_PATTERNS = [
    re.compile(r"(^|/)\.env(\..*)?$", re.IGNORECASE),
    re.compile(r"(^|/)\.npmrc$", re.IGNORECASE),
    re.compile(r"(^|/)\.pypirc$", re.IGNORECASE),
    re.compile(r"(^|/)\.netrc$", re.IGNORECASE),
    re.compile(r"(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519)$", re.IGNORECASE),
    re.compile(r"\.(pem|key|p12|pfx|jks|keystore)$", re.IGNORECASE),
    re.compile(r"(^|/)(credentials|service-account|firebase|google-credentials).*\.json$", re.IGNORECASE),
    re.compile(r"(^|/)(kubeconfig|config\.json|dockerconfigjson)$", re.IGNORECASE),
]


EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    ".next",
    ".nuxt",
    "dist",
    "build",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
}


PLACEHOLDER_WORDS = {
    "example",
    "sample",
    "dummy",
    "placeholder",
    "changeme",
    "change_me",
    "your_key",
    "your-token",
    "your_token",
    "not-a-secret",
    "notasecret",
    "test",
}


def run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, text=True, capture_output=True)


def is_git_repo(path: Path) -> bool:
    result = run(["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"])
    return result.returncode == 0 and result.stdout.strip() == "true"


def git_root(path: Path) -> Path | None:
    result = run(["git", "-C", str(path), "rev-parse", "--show-toplevel"])
    if result.returncode != 0:
        return None
    return Path(result.stdout.strip()).resolve()


def redact(value: str, show: bool = False) -> str:
    value = value.strip()
    if show:
        return value
    if len(value) <= 10:
        return "<redacted>"
    return f"{value[:4]}...{value[-4:]}"


def looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    if any(word in lowered for word in PLACEHOLDER_WORDS):
        return True
    unique = set(value)
    if len(value) >= 16 and len(unique) <= 4:
        return True
    return False


def normalize_path(path: Path) -> str:
    return path.as_posix()


def scan_text(text: str, location: str, line_no: int | None, show: bool) -> list[Finding]:
    findings: list[Finding] = []
    if len(text) > 20000:
        text = text[:20000]
    for rule in SECRET_RULES:
        for match in rule.pattern.finditer(text):
            raw = match.group(1) if rule.rule_id == "generic-assignment" and match.groups() else match.group(0)
            if looks_like_placeholder(raw):
                continue
            findings.append(
                Finding(
                    kind="secret",
                    severity=rule.severity,
                    rule_id=rule.rule_id,
                    location=location,
                    line=line_no,
                    match=redact(raw, show),
                    recommendation=rule.rotate_hint,
                )
            )
    return findings


def is_binary(path: Path) -> bool:
    try:
        chunk = path.read_bytes()[:4096]
    except OSError:
        return True
    return b"\0" in chunk


def iter_files(root: Path, max_file_mb: float) -> Iterable[Path]:
    max_bytes = int(max_file_mb * 1024 * 1024)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        base = Path(dirpath)
        for filename in filenames:
            path = base / filename
            try:
                if path.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
            if not is_binary(path):
                yield path


def scan_files(root: Path, max_file_mb: float, show: bool) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_files(root, max_file_mb):
        try:
            rel = normalize_path(path.relative_to(root))
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for idx, line in enumerate(handle, start=1):
                    findings.extend(scan_text(line, rel, idx, show))
        except OSError:
            continue
    return findings


def sensitive_path_evidence(root: Path) -> list[Evidence]:
    evidence: list[Evidence] = []
    for path in iter_files(root, max_file_mb=5):
        rel = normalize_path(path.relative_to(root))
        if any(rule.search(rel) for rule in SENSITIVE_NAME_PATTERNS):
            evidence.append(
                Evidence(
                    kind="sensitive-file-present",
                    severity="medium",
                    location=rel,
                    detail="Sensitive-looking file exists in the working tree.",
                    recommendation="Confirm it is ignored, untracked, and never read by coding agents unless intentional.",
                )
            )
    return evidence


def git_tracked_sensitive_files(root: Path) -> list[Evidence]:
    evidence: list[Evidence] = []
    result = run(["git", "-C", str(root), "ls-files"], cwd=root)
    if result.returncode != 0:
        return evidence
    for rel in result.stdout.splitlines():
        rel_norm = rel.replace("\\", "/")
        if any(rule.search(rel_norm) for rule in SENSITIVE_NAME_PATTERNS):
            evidence.append(
                Evidence(
                    kind="sensitive-file-tracked",
                    severity="high",
                    location=rel_norm,
                    detail="Sensitive-looking file is tracked by Git.",
                    recommendation="Rotate any contained secret, remove from Git, and consider cleaning history.",
                )
            )
    return evidence


def git_history_sensitive_paths(root: Path) -> list[Evidence]:
    evidence: list[Evidence] = []
    result = run(["git", "-C", str(root), "log", "--all", "--name-only", "--format="], cwd=root)
    if result.returncode != 0:
        return evidence
    seen: set[str] = set()
    for rel in result.stdout.splitlines():
        rel_norm = rel.strip().replace("\\", "/")
        if not rel_norm or rel_norm in seen:
            continue
        if any(rule.search(rel_norm) for rule in SENSITIVE_NAME_PATTERNS):
            seen.add(rel_norm)
            evidence.append(
                Evidence(
                    kind="sensitive-file-in-history",
                    severity="high",
                    location=rel_norm,
                    detail="Sensitive-looking path appears somewhere in Git history.",
                    recommendation="Scan the full history, rotate contained secrets, and clean history if needed.",
                )
            )
    return evidence


def scan_git_history(root: Path, show: bool, max_findings: int) -> list[Finding]:
    findings: list[Finding] = []
    cmd = ["git", "-C", str(root), "log", "--all", "--full-history", "-p", "--no-ext-diff", "--no-renames", "--"]
    try:
        proc = subprocess.Popen(cmd, cwd=str(root), text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        return findings
    commit = ""
    current_file = ""
    if not proc.stdout:
        return findings
    for raw_line in proc.stdout:
        line = raw_line.rstrip("\n")
        if line.startswith("commit "):
            commit = line.split(" ", 1)[1][:12]
            continue
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue
        if line.startswith("--- a/") or line.startswith("+++") or line.startswith("---"):
            continue
        if not line.startswith(("+", "-")):
            continue
        payload = line[1:]
        location = f"{commit}:{current_file or '<patch>'}"
        new_findings = scan_text(payload, location, None, show)
        findings.extend(new_findings)
        if len(findings) >= max_findings:
            proc.kill()
            return findings[:max_findings]
    proc.wait()
    return findings


def grok_evidence(repo: Path) -> list[Evidence]:
    evidence: list[Evidence] = []
    grok_path = shutil.which("grok")
    if grok_path:
        evidence.append(
            Evidence(
                kind="grok-installed",
                severity="info",
                location=grok_path,
                detail="Grok Build CLI appears to be available on PATH.",
                recommendation="Avoid sensitive repositories unless you have independently verified current upload behavior.",
            )
        )
    for rel in [".grok", "AGENTS.md"]:
        path = repo / rel
        if path.exists():
            evidence.append(
                Evidence(
                    kind="agent-config-present",
                    severity="low",
                    location=rel,
                    detail="Repository contains agent configuration or instructions.",
                    recommendation="Review for tokens, hooks, MCP endpoints, and commands before using any coding agent.",
                )
            )
    home = Path.home()
    for rel in [".grok", ".config/grok"]:
        path = home / rel
        if path.exists():
            evidence.append(
                Evidence(
                    kind="grok-home-state",
                    severity="info",
                    location=str(path),
                    detail="Grok-related user-level state/config directory exists.",
                    recommendation="Review local config and session state. Do not paste any secrets from it into chats.",
                )
            )
    return evidence


def severity_score(value: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(value, 0)


def summarize(findings: list[Finding], evidence: list[Evidence]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in findings + evidence:  # type: ignore[operator]
        counts[item.severity] = counts.get(item.severity, 0) + 1
    return counts


def print_report(root: Path, findings: list[Finding], evidence: list[Evidence], git_enabled: bool) -> None:
    counts = summarize(findings, evidence)
    print(f"happy-grok v{VERSION}")
    print(f"Target: {root}")
    print(f"Git history scanned: {'yes' if git_enabled else 'no'}")
    print("")
    print("Summary:")
    for sev in ["critical", "high", "medium", "low", "info"]:
        print(f"  {sev:8} {counts.get(sev, 0)}")
    print("")

    ordered_findings = sorted(findings, key=lambda f: severity_score(f.severity), reverse=True)
    ordered_evidence = sorted(evidence, key=lambda e: severity_score(e.severity), reverse=True)

    if ordered_findings:
        print("Secret findings:")
        for f in ordered_findings:
            line = f":{f.line}" if f.line else ""
            print(f"- [{f.severity}] {f.rule_id} at {f.location}{line}: {f.match}")
            print(f"  action: {f.recommendation}")
        print("")
    else:
        print("Secret findings: none detected by built-in rules.")
        print("")

    if ordered_evidence:
        print("Exposure evidence:")
        for e in ordered_evidence:
            print(f"- [{e.severity}] {e.kind} at {e.location}")
            print(f"  detail: {e.detail}")
            print(f"  action: {e.recommendation}")
        print("")

    print("Recommended next steps:")
    if counts["critical"] or counts["high"]:
        print("- Rotate/revoke critical and high secrets first. Do not wait for history cleanup.")
        print("- Review provider usage logs for the dates when AI coding agents were used.")
    else:
        print("- Treat this as a screening result, not a guarantee. Consider a second scanner such as Gitleaks or TruffleHog.")
    print("- Enable secret scanning and push protection on the remote repository where available.")
    print("- If Grok Build was used, ask xAI for repository/session trace deletion confirmation for affected dates.")


def write_json(path: Path, root: Path, findings: list[Finding], evidence: list[Evidence], git_enabled: bool) -> None:
    payload = {
        "tool": "happy-grok",
        "version": VERSION,
        "target": str(root),
        "git_history_scanned": git_enabled,
        "summary": summarize(findings, evidence),
        "findings": [asdict(item) for item in findings],
        "evidence": [asdict(item) for item in evidence],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local secret and AI coding-agent exposure checker.")
    parser.add_argument("path", nargs="?", default=".", help="Repository or directory to scan.")
    parser.add_argument("--no-history", action="store_true", help="Skip Git history scanning.")
    parser.add_argument("--max-file-mb", type=float, default=5.0, help="Maximum single file size for working-tree scan.")
    parser.add_argument("--max-history-findings", type=int, default=500, help="Stop Git history scan after this many findings.")
    parser.add_argument("--json", dest="json_path", help="Write a JSON report to this path.")
    parser.add_argument("--show-secrets", action="store_true", help="Print full matched secrets. Dangerous; redacted by default.")
    parser.add_argument("--version", action="version", version=f"happy-grok {VERSION}")
    args = parser.parse_args(argv)

    target = Path(args.path).resolve()
    if not target.exists():
        print(f"error: path does not exist: {target}", file=sys.stderr)
        return 2
    if target.is_file():
        root = target.parent
    else:
        root = target

    findings: list[Finding] = []
    evidence: list[Evidence] = []

    findings.extend(scan_files(root, args.max_file_mb, args.show_secrets))
    evidence.extend(sensitive_path_evidence(root))
    evidence.extend(grok_evidence(root))

    git_enabled = False
    if not args.no_history and is_git_repo(root):
        actual_root = git_root(root) or root
        git_enabled = True
        evidence.extend(git_tracked_sensitive_files(actual_root))
        evidence.extend(git_history_sensitive_paths(actual_root))
        findings.extend(scan_git_history(actual_root, args.show_secrets, args.max_history_findings))
    elif not args.no_history:
        evidence.append(
            Evidence(
                kind="not-a-git-repo",
                severity="info",
                location=str(root),
                detail="Target is not inside a Git repository; Git history was not scanned.",
                recommendation="Run happy-grok from the repository root for full history checks.",
            )
        )

    print_report(root, findings, evidence, git_enabled)

    if args.json_path:
        report_path = Path(args.json_path).resolve()
        write_json(report_path, root, findings, evidence, git_enabled)
        print(f"JSON report written: {report_path}")

    return 1 if any(severity_score(f.severity) >= 3 for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
