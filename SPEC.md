# happy-grok Specification

## Purpose

`happy-grok` is a local triage tool for developers who want to check whether an
AI coding-agent incident may have exposed sensitive repository content.

The tool is intentionally conservative: it should be useful for first-pass
screening, but it must not claim to prove that a repository is safe.

## Threat Model

`happy-grok` focuses on incidents where a coding agent, CLI, extension, or
trace system may have collected more repository context than the user expected.

In scope:

- Secrets currently present in the working tree.
- Secrets present in Git patch history.
- Sensitive file paths such as `.env`, private keys, package tokens, and cloud
  service-account files.
- Local indicators that Grok Build or repository-level agent instructions may
  have been used.

Out of scope:

- Proving that a vendor retained, trained on, or deleted uploaded data.
- Verifying whether a credential is live.
- Exhaustively detecting every possible custom credential format.
- Replacing mature scanners, provider audit logs, or professional incident
  response.

## Privacy Requirements

- The tool must run locally.
- The tool must not make network requests.
- Findings must be redacted by default.
- Full secret output may only be shown when the user explicitly passes
  `--show-secrets`.

## Platform Requirements

Supported platforms:

- macOS
- Linux
- Windows

Runtime requirements:

- Python 3.10 or newer.
- Git on `PATH` when Git history scanning is enabled.

Launchers:

- `./happy-grok` for macOS/Linux.
- `happy-grok.ps1` for Windows PowerShell.
- `happy-grok.cmd` for Windows Command Prompt.
- `python happy_grok.py` on any supported platform.

## Scanning Behavior

Working tree scan:

- Recursively scan text files below the target directory.
- Skip common build, dependency, cache, virtualenv, and `.git` directories.
- Skip files larger than `--max-file-mb`.
- Ignore obvious placeholders such as `example`, `sample`, and `changeme`.

Git scan:

- When the target is inside a Git repository and `--no-history` is not passed,
  scan Git patch history with `git log --all --full-history -p`.
- Stop history scanning after `--max-history-findings` findings.
- Detect sensitive-looking paths in tracked files and historical file names.

Grok Build indicators:

- Report a `grok` executable found on `PATH`.
- Report repository-level `.grok` and `AGENTS.md` files.
- Report user-level `.grok` and `.config/grok` directories when present.

## Output Requirements

Text output:

- Include the tool version.
- Include the target path.
- Include whether Git history was scanned.
- Include severity counts for `critical`, `high`, `medium`, `low`, and `info`.
- Include secret findings and exposure evidence.
- Include recommended next steps.

JSON output:

- When `--json PATH` is passed, write a JSON report to `PATH`.
- The report must include:
  - `tool`
  - `version`
  - `target`
  - `git_history_scanned`
  - `summary`
  - `findings`
  - `evidence`

## Exit Codes

- `0`: completed without high or critical secret findings.
- `1`: completed and found at least one high or critical secret finding.
- `2`: usage or runtime error, such as a missing target path.

## Safety Notes

`happy-grok` is an early-stage tool. It is allowed to miss secrets and produce
false positives. The README and release notes should avoid guarantees and should
recommend pairing results with mature scanners and provider logs.
