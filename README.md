# happy-grok

Meet Grok, my adorable Chinese village dog. Curious by nature, always sniffing
around. `happy-grok` is a small local tool for checking whether anything
sensitive may have been exposed.

It is designed for AI coding-agent incidents such as broad repository upload,
trace upload, or accidental secret exposure. It does not upload anything, and
findings are redacted by default.

## Disclaimer

`happy-grok` is an early-stage tool and has not been thoroughly tested across
all repositories, platforms, file formats, or secret patterns. It is provided
as-is, without warranties. Use it at your own risk, and verify important
security decisions with mature scanners, provider logs, and professional
incident-response practices where appropriate.

## Platform support

`happy-grok` is written in Python standard library code and is intended to run
on macOS, Linux, and Windows.

Requirements:

- Python 3.10 or newer.
- Git installed and available on `PATH` for Git history checks.

Launchers:

- macOS/Linux: `./happy-grok`
- Windows PowerShell: `.\happy-grok.ps1`
- Windows Command Prompt: `happy-grok.cmd`
- Any platform: `python happy_grok.py`

## What it checks

- Secret-looking values in the current working tree.
- Secret-looking values in Git patch history.
- Sensitive file names in the working tree, tracked files, and Git history.
- Grok Build usage signals such as a `grok` binary on `PATH`, `.grok`
  directories, and repository-level agent instructions.

## What it cannot prove

- It cannot prove whether a vendor retained, trained on, or deleted uploaded
  data.
- It cannot prove that a repository is clean. Secret scanners miss custom
  formats and heavily obfuscated values.
- It cannot determine whether a credential is still valid unless you check the
  provider or use a scanner with verification support.

## Quick start

macOS/Linux:

```bash
chmod +x ./happy-grok
./happy-grok /path/to/your/repo
```

Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\happy-grok.ps1 C:\path\to\your\repo
```

Windows Command Prompt:

```bat
happy-grok.cmd C:\path\to\your\repo
```

Any platform:

```bash
python happy_grok.py /path/to/your/repo
```

Write a JSON report:

```bash
./happy-grok /path/to/your/repo --json ./happy-grok-report.json
```

Skip Git history if the repository is very large:

```bash
./happy-grok /path/to/your/repo --no-history
```

By default, matched secrets are redacted. Only use `--show-secrets` in a private
terminal when you really need the full value:

```bash
./happy-grok /path/to/your/repo --show-secrets
```

## Recommended response workflow

1. Rotate or revoke critical/high findings first.
2. Review provider usage logs for the date range when AI coding agents were
   used.
3. If Grok Build was used on the repository, ask xAI for deletion confirmation
   for repository, session-state, and trace objects.
4. Remove secrets from current files.
5. Clean Git history only after rotation. History cleanup reduces future
   exposure, but it does not make an already exposed key safe again.
6. Enable secret scanning and push protection on the remote repository.

## Pair with stronger scanners

For more coverage, run at least one mature scanner too:

```bash
gitleaks git --redact --report-format json --report-path gitleaks-history.json /path/to/your/repo
gitleaks dir --redact --report-format json --report-path gitleaks-files.json /path/to/your/repo
trufflehog git file:///path/to/your/repo --only-verified --json
trufflehog filesystem /path/to/your/repo --only-verified --json
```

`happy-grok` is intended as a fast local triage tool, not a replacement for
dedicated secret management and incident response.

## License

MIT. See [LICENSE](LICENSE).
