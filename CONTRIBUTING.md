# Contributing

Thank you for improving repo-guardian. Contributions should solve a documented
repository-auditing problem and preserve the offline, metadata-only security
boundary.

## Before coding

1. Search existing issues for the behavior you want to change.
2. Open an issue for a bug or feature with reproducible examples and acceptance
   criteria.
3. Keep changes focused. Avoid adding network access or reading audited file
   contents.

## Development

repo-guardian requires Go 1.26 or later.

```console
git clone https://github.com/ramiabukhader/repo-guardian.git
cd repo-guardian
go test ./...
```

Before opening a pull request, run:

```console
gofmt -w ./cmd ./internal
go test ./...
go vet ./...
```

Add meaningful tests for new behavior, including Windows and POSIX path cases
when path handling changes. Commit messages should explain the behavior being
added or corrected.

## Pull requests

Link the issue the pull request closes and explain correctness, edge cases,
security implications, and test coverage. Never put real secrets or private
repository paths in fixtures, screenshots, logs, issues, or reviews. A change
is ready to merge when required CI checks pass and review findings are
resolved.
