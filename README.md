# repo-guardian

repo-guardian is an offline Go CLI that audits the health of a local project.
It reports missing repository essentials, risky filenames and artifacts, and
a transparent health score in human-readable or JSON form.

The scanner does not upload repository data, make network requests, or read
file contents. It works from paths, file metadata, and the local Git index.

## Install

Go 1.26 or later is required.

```console
go install github.com/ramiabukhader/repo-guardian/cmd/repo-guardian@latest
```

You can also build a local binary:

```console
git clone https://github.com/ramiabukhader/repo-guardian.git
cd repo-guardian
go build -o bin/repo-guardian ./cmd/repo-guardian
```

## Usage

Audit the current directory:

```console
repo-guardian
```

Audit another local directory:

```console
repo-guardian /path/to/project
```

Flags must precede the optional path:

```text
--format human|json          Output format (default: human)
--large-file-threshold N     Large-file threshold in bytes (default: 10485760)
--min-score N                Required score from 0 through 100 (default: 0)
--fail-on-risk               Exit 1 when any risk is found
```

For example, emit JSON and require a score of at least 80:

```console
repo-guardian --format json --min-score 80 /path/to/project
```

### Human output

```text
Repository: "/home/alex/project"
Files scanned: 42
Total size: 183420 bytes
  ci: 1
  configuration: 5
  documentation: 5
  source: 21
  test: 10
Health checks: 8/8
  [PASS] README: "README.md"
  [PASS] License: "LICENSE"
  [PASS] .gitignore: ".gitignore"
  [PASS] CI workflow: ".github/workflows/ci.yml"
  [PASS] Test files: "internal/audit/audit_test.go"
  [PASS] Security policy: "SECURITY.md"
  [PASS] Contribution guide: "CONTRIBUTING.md"
  [PASS] Pull-request template: ".github/pull_request_template.md"
Risks: 0
Health score: 100/100 (health 70, risk hygiene 30)
```

### JSON output

JSON is versioned so automation can reject schemas it does not understand.
This is a complete, shortened-file-count example:

```json
{
  "version": "1",
  "repository": {
    "root": "/home/alex/project",
    "files_scanned": 8,
    "total_size_bytes": 24000,
    "categories": {
      "ci": 1,
      "configuration": 1,
      "documentation": 5,
      "test": 1
    },
    "git_tracking_available": true
  },
  "health": {
    "checks": [
      {"id": "readme", "label": "README", "passed": true, "evidence": ["README.md"]},
      {"id": "license", "label": "License", "passed": true, "evidence": ["LICENSE"]},
      {"id": "gitignore", "label": ".gitignore", "passed": true, "evidence": [".gitignore"]},
      {"id": "ci", "label": "CI workflow", "passed": true, "evidence": [".github/workflows/ci.yml"]},
      {"id": "tests", "label": "Test files", "passed": true, "evidence": ["audit_test.go"]},
      {"id": "security_policy", "label": "Security policy", "passed": true, "evidence": ["SECURITY.md"]},
      {"id": "contributing_guide", "label": "Contribution guide", "passed": true, "evidence": ["CONTRIBUTING.md"]},
      {"id": "pull_request_template", "label": "Pull-request template", "passed": true, "evidence": [".github/pull_request_template.md"]}
    ],
    "passed": 8,
    "total": 8
  },
  "risks": [],
  "score": {
    "total": 100,
    "maximum": 100,
    "health_points": 70,
    "risk_hygiene_points": 30
  }
}
```

## Checks and risks

Health checks look for a root README, root license, root `.gitignore`, GitHub
Actions workflow, recognizable test file, security policy, contribution guide,
and pull-request template.

Risk detection reports:

- `.env` variants, excluding `.example`, `.sample`, and `.template` files;
- common credential, private-key, package-token, and secret filenames;
- files at or above the configured byte threshold;
- files inside common build-output directories when those files are tracked.

Findings contain paths and metadata only. Secret values are never printed.

## Scoring model

The score is deterministic and capped at 100.

| Component | Points |
| --- | ---: |
| README | 15 |
| License | 10 |
| `.gitignore` | 5 |
| CI workflow | 10 |
| Tests | 15 |
| Security policy | 5 |
| Contribution guide | 5 |
| Pull-request template | 5 |
| No environment-file findings | 10 |
| No secret-file findings | 10 |
| No large-file findings | 5 |
| No tracked build-output findings | 5 |

Multiple findings of the same kind deduct that kind's hygiene points once.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Audit completed and configured gates passed. |
| 1 | Audit completed, but `--min-score` or `--fail-on-risk` failed. |
| 2 | Invalid usage, scan failure, Git-index failure, or output failure. |

## Architecture

```text
cmd/repo-guardian
        |
  internal/app        CLI flags, rendering, and exit policy
        |
  internal/scanner    metadata-only traversal and classification
        |
  +-- internal/audit  repository-health checks
  +-- internal/risk   filename, size, and Git-index findings
        |
  internal/score      fixed 100-point scoring model
        |
  internal/report     versioned structured document
```

Every layer receives metadata rather than file contents. The only subprocess is
local `git`, invoked with separate arguments to read the index safely.

## Limitations

- Filename heuristics can produce false positives and cannot prove a file is
  safe.
- File contents are deliberately not scanned, so secrets under ordinary names
  are not detected.
- Symlinks are skipped; their targets are not audited.
- `.git`, `node_modules`, and `vendor` trees are ignored.
- Tracked build-output detection is unavailable outside a Git worktree or when
  Git is not installed.
- Reports contain the absolute scan root and repository-relative filenames;
  review them before sharing.
- The CLI audits one local directory at a time and does not inspect remote
  repository settings, branch protection, dependencies, or hosted secrets.

See [SECURITY.md](SECURITY.md) for the security boundary and reporting process,
and [CONTRIBUTING.md](CONTRIBUTING.md) for development guidance.

## License

MIT
